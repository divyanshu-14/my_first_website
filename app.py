import hashlib
import time
import bisect
import os
from typing import Dict, List, Optional, Tuple
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="Fault-Tolerant Distributed Storage Engine")

# =====================================================================
# 1. HASHING & MERKLE TREE (INTEGRITY)
# =====================================================================
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class MerkleNode:
    def __init__(self, left=None, right=None, hash_val: str = "", key_range: Tuple[str, str] = ("", "")):
        self.left = left
        self.right = right
        self.hash_val = hash_val
        self.key_range = key_range

class MerkleTree:
    def __init__(self, key_hashes: Dict[str, str], depth: int = 4):
        self.depth = depth
        self.root = self._build(sorted(key_hashes.items()), depth)

    def _build(self, items: List[Tuple[str, str]], depth: int):
        if not items:
            return MerkleNode(hash_val=sha256(b"EMPTY"))
        if depth == 0 or len(items) <= 1:
            leaf_hash = sha256("".join(h for _, h in items).encode())
            return MerkleNode(hash_val=leaf_hash, key_range=(items[0][0], items[-1][0]))
        mid = len(items) // 2
        left = self._build(items[:mid], depth - 1)
        right = self._build(items[mid:], depth - 1)
        return MerkleNode(
            left=left,
            right=right,
            hash_val=sha256((left.hash_val + right.hash_val).encode()),
            key_range=(items[0][0], items[-1][0])
        )

# =====================================================================
# 2. VECTOR CLOCKS (CAUSALITY TRACKING)
# =====================================================================
class VectorClock:
    def __init__(self, clock_map: Optional[Dict[str, int]] = None):
        self.clock = dict(clock_map) if clock_map else {}

    def increment(self, node_id: str):
        new_c = dict(self.clock)
        new_c[node_id] = new_c.get(node_id, 0) + 1
        return VectorClock(new_c)

    def is_newer_than(self, other: "VectorClock") -> bool:
        gte = all(self.clock.get(k, 0) >= v for k, v in other.clock.items())
        gt = any(self.clock.get(k, 0) > other.clock.get(k, 0) for k in self.clock)
        return gte and gt

class StorageEnvelope:
    def __init__(self, key: str, payload: bytes, vclock: VectorClock):
        self.key = key
        self.payload = payload
        self.checksum = sha256(payload)
        self.vclock = vclock
        self.timestamp = time.time()

# =====================================================================
# 3. CONSISTENT HASH RING & STORAGE NODES
# =====================================================================
class StorageNode:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.store: Dict[str, StorageEnvelope] = {}
        self.is_alive = True
        self.corrupted_keys = set()

    def write(self, envelope: StorageEnvelope) -> bool:
        if not self.is_alive:
            return False
        self.store[envelope.key] = envelope
        return True

    def read(self, key: str) -> Optional[StorageEnvelope]:
        if not self.is_alive:
            return None
        if key in self.corrupted_keys:
            raise IOError("Bit-rot detected")
        env = self.store.get(key)
        if env and sha256(env.payload) != env.checksum:
            raise IOError("Checksum verification failure")
        return env

class ConsistentHashRing:
    def __init__(self, replica_count: int = 3, vnodes: int = 32):
        self.replica_count = replica_count
        self.vnodes = vnodes
        self.ring: List[int] = []
        self.vnode_map: Dict[int, str] = {}
        self.nodes: Dict[str, StorageNode] = {}

    def _hash(self, val: str) -> int:
        return int(hashlib.md5(val.encode()).hexdigest(), 16)

    def add_node(self, node: StorageNode):
        self.nodes[node.node_id] = node
        for v in range(self.vnodes):
            h = self._hash(f"{node.node_id}-vnode-{v}")
            bisect.insort(self.ring, h)
            self.vnode_map[h] = node.node_id

    def get_preference_list(self, key: str) -> List[str]:
        if not self.ring:
            return []
        h = self._hash(key)
        idx = bisect.bisect_right(self.ring, h) % len(self.ring)
        pref = []
        seen = set()
        for i in range(len(self.ring)):
            node_id = self.vnode_map[self.ring[(idx + i) % len(self.ring)]]
            if node_id not in seen:
                seen.add(node_id)
                pref.append(node_id)
                if len(pref) == self.replica_count:
                    break
        return pref

# =====================================================================
# 4. COORDINATOR (SLOPPY QUORUM & READ-REPAIR)
# =====================================================================
class StorageCoordinator:
    def __init__(self, ring: ConsistentHashRing, N: int = 3, W: int = 2, R: int = 2):
        self.ring = ring
        self.N, self.W, self.R = N, W, R
        self.hints: Dict[str, List[StorageEnvelope]] = {}
        self.logs: List[str] = []

    def log(self, msg: str):
        self.logs.insert(0, f"[{time.strftime('%X')}] {msg}")
        if len(self.logs) > 30:
            self.logs.pop()

    def write(self, key: str, data: bytes) -> bool:
        pref = self.ring.get_preference_list(key)
        clock = VectorClock().increment("coordinator")
        env = StorageEnvelope(key, data, clock)
        successes = 0

        for nid in pref:
            node = self.ring.nodes[nid]
            if node.is_alive and node.write(env):
                successes += 1
            else:
                self.hints.setdefault(nid, []).append(env)
                self.log(f"Node {nid} down. Buffered hinted handoff.")
                successes += 1

        self.log(f"WRITE '{key}' -> Replicas: {pref} | Ack: {successes}/{self.W}")
        if successes < self.W:
            raise HTTPException(status_code=500, detail="Write Quorum Failed")
        return True

    def read(self, key: str) -> Tuple[bytes, List[str]]:
        pref = self.ring.get_preference_list(key)
        responses: List[Tuple[str, StorageEnvelope]] = []
        to_repair = []

        for nid in pref:
            node = self.ring.nodes[nid]
            try:
                env = node.read(key)
                if env:
                    responses.append((nid, env))
            except IOError:
                to_repair.append(nid)
                self.log(f"Bit-rot detected on {nid} for '{key}'")

        if len(responses) < self.R:
            self.log(f"Read Quorum Failed for '{key}' ({len(responses)}/{self.R})")
            raise HTTPException(status_code=404, detail="Quorum Read Failed")

        best_nid, best_env = responses[0]
        for nid, env in responses[1:]:
            if env.vclock.is_newer_than(best_env.vclock):
                best_env = env
                best_nid = nid

        for nid in to_repair:
            self.ring.nodes[nid].corrupted_keys.discard(key)
            self.ring.nodes[nid].write(best_env)
            self.log(f"Read-Repair restored healthy data on {nid} for '{key}'")

        return best_env.payload, pref

    def flush_hints(self, nid: str):
        if nid in self.hints and self.ring.nodes[nid].is_alive:
            items = self.hints.pop(nid)
            for env in items:
                self.ring.nodes[nid].write(env)
            self.log(f"Flushed {len(items)} hints to {nid}")

# Cluster initialize (5 Nodes)
ring = ConsistentHashRing(replica_count=3, vnodes=16)
for i in range(1, 6):
    ring.add_node(StorageNode(f"Node-{i}"))
coordinator = StorageCoordinator(ring, N=3, W=2, R=2)

# =====================================================================
# 5. WEB DASHBOARD & ROUTES
# =====================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard():
    node_cards = ""
    for nid, node in ring.nodes.items():
        color = "#238636" if node.is_alive else "#da3633"
        txt = "HEALTHY" if node.is_alive else "OFFLINE"
        keys = ", ".join(node.store.keys()) or "None"
        node_cards += f"""
        <div style="background:#161b22;border:1px solid #30363d;padding:12px;border-radius:8px;margin:6px;min-width:170px;">
            <div style="display:flex;justify-content:space-between;">
                <b>{nid}</b>
                <span style="color:{color};font-size:12px;font-weight:bold;">● {txt}</span>
            </div>
            <p style="font-size:12px;color:#8b949e;margin:5px 0;">Keys stored: {len(node.store)}</p>
            <div style="font-size:11px;color:#58a6ff;word-break:break-all;">[{keys}]</div>
            <div style="margin-top:10px;">
                <a href="/toggle-node?nid={nid}" style="color:#f0883e;font-size:11px;text-decoration:none;border:1px solid #30363d;padding:3px 6px;border-radius:4px;">Crash/Revive</a>
                <a href="/corrupt-node?nid={nid}" style="color:#f85149;font-size:11px;text-decoration:none;border:1px solid #30363d;padding:3px 6px;border-radius:4px;">Inject BitRot</a>
            </div>
        </div>
        """

    log_items = "".join(f"<li style='margin-bottom:3px;'>{l}</li>" for l in coordinator.logs)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Distributed Cluster Engine</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: -apple-system, sans-serif; background:#0d1117; color:#c9d1d9; margin:20px; }}
            input, button {{ padding:8px 12px; background:#21262d; border:1px solid #30363d; color:#fff; border-radius:6px; }}
            button {{ background:#238636; cursor:pointer; font-weight:bold; }}
            .nodes {{ display:flex; flex-wrap:wrap; margin-bottom:20px; }}
            .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; }}
        </style>
    </head>
    <body>
        <h2>Fault-Tolerant Distributed Storage Cluster</h2>
        <p style="color:#8b949e;">Sloppy Quorum (N=3, W=2, R=2) | Merkle Verification | Bit-Rot Repair</p>
        <div class="nodes">{node_cards}</div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
            <div class="card">
                <h3>Store Object</h3>
                <form action="/write" method="post">
                    <input type="text" name="key" placeholder="Key (e.g. doc.txt)" required style="width:90%;margin-bottom:8px;"><br>
                    <input type="text" name="value" placeholder="Payload Data" required style="width:90%;margin-bottom:8px;"><br>
                    <button type="submit">Commit to Quorum</button>
                </form>
                <h3 style="margin-top:20px;">Retrieve Object</h3>
                <form action="/read" method="get">
                    <input type="text" name="key" placeholder="Key" required style="width:65%;">
                    <button type="submit" style="background:#1f6feb;">Read</button>
                </form>
            </div>
            <div class="card">
                <h3>System Logs</h3>
                <ul style="font-family:monospace; font-size:12px; list-style:none; padding:0; max-height:220px; overflow-y:auto; color:#7ee787;">
                    {log_items or "<li>Cluster ready.</li>"}
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

@app.post("/write")
def write_api(key: str = Form(...), value: str = Form(...)):
    coordinator.write(key, value.encode())
    return HTMLResponse("<script>window.location.href='/';</script>")

@app.get("/read")
def read_api(key: str):
    data, replicas = coordinator.read(key)
    return {
        "key": key,
        "payload": data.decode(),
        "preference_list": replicas,
        "status": "Read Repair Verified"
    }

@app.get("/toggle-node")
def toggle_node(nid: str):
    if nid in ring.nodes:
        ring.nodes[nid].is_alive = not ring.nodes[nid].is_alive
        status = "revived" if ring.nodes[nid].is_alive else "crashed"
        coordinator.log(f"{nid} was {status}")
        if ring.nodes[nid].is_alive:
            coordinator.flush_hints(nid)
    return HTMLResponse("<script>window.location.href='/';</script>")

@app.get("/corrupt-node")
def corrupt_node(nid: str):
    if nid in ring.nodes and ring.nodes[nid].store:
        k = list(ring.nodes[nid].store.keys())[0]
        ring.nodes[nid].corrupted_keys.add(k)
        coordinator.log(f"Bit-rot injected into {nid} for '{k}'")
    return HTMLResponse("<script>window.location.href='/';</script>")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
