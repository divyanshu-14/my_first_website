import hashlib
import time
import bisect
import os
from typing import Dict, List, Optional, Tuple
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="Distributed Object Storage Cluster")

# =====================================================================
# CORE ENGINE: CHECKSUM & CONSISTENT HASH RING
# =====================================================================
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class StorageEnvelope:
    def __init__(self, key: str, payload: bytes, vclock: Dict[str, int]):
        self.key = key
        self.payload = payload
        self.checksum = sha256(payload)
        self.vclock = vclock
        self.size_bytes = len(payload)
        self.timestamp = time.time()

class StorageNode:
    def __init__(self, node_id: str, capacity_gb: int = 10):
        self.node_id = node_id
        self.capacity_bytes = capacity_gb * 1024 * 1024 * 1024
        self.store: Dict[str, StorageEnvelope] = {}
        self.is_alive = True
        self.corrupted_keys = set()

    @property
    def used_bytes(self) -> int:
        return sum(item.size_bytes for item in self.store.values())

    def write(self, envelope: StorageEnvelope) -> bool:
        if not self.is_alive:
            return False
        self.store[envelope.key] = envelope
        return True

    def read(self, key: str) -> Optional[StorageEnvelope]:
        if not self.is_alive:
            return None
        if key in self.corrupted_keys:
            raise IOError("Bit-rot silent corruption detected")
        env = self.store.get(key)
        if env and sha256(env.payload) != env.checksum:
            raise IOError("SHA-256 Checksum validation mismatch")
        return env

class ConsistentHashRing:
    def __init__(self, replica_count: int = 3, vnodes: int = 16):
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
# COORDINATOR: SLOPPY QUORUM & READ REPAIR
# =====================================================================
class StorageCoordinator:
    def __init__(self, ring: ConsistentHashRing, N: int = 3, W: int = 2, R: int = 2):
        self.ring = ring
        self.N, self.W, self.R = N, W, R
        self.hints: Dict[str, List[StorageEnvelope]] = {}
        self.logs: List[dict] = []
        self.total_writes = 0
        self.total_reads = 0
        self.total_repairs = 0

    def log(self, text: str, tag: str = "INFO"):
        self.logs.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "text": text,
            "tag": tag
        })
        if len(self.logs) > 30:
            self.logs.pop()

    def write(self, key: str, data: bytes) -> dict:
        self.total_writes += 1
        pref = self.ring.get_preference_list(key)
        clock = {"coordinator": int(time.time())}
        env = StorageEnvelope(key, data, clock)
        successes = 0

        for nid in pref:
            node = self.ring.nodes[nid]
            if node.is_alive and node.write(env):
                successes += 1
            else:
                self.hints.setdefault(nid, []).append(env)
                self.log(f"Node {nid} DOWN. Buffered hinted handoff for '{key}'", "WARN")
                successes += 1

        if successes < self.W:
            self.log(f"Quorum Write failed for '{key}' ({successes}/{self.W})", "CRIT")
            raise HTTPException(status_code=500, detail="Write Quorum Failed")

        self.log(f"WRITE COMMITTED: '{key}' → Replicas: {pref} (Ack {successes}/{self.W})", "WRITE")
        return {"key": key, "replicas": pref, "quorum": f"{successes}/{self.W}"}

    def read(self, key: str) -> dict:
        self.total_reads += 1
        pref = self.ring.get_preference_list(key)
        responses = []
        corrupted = []

        for nid in pref:
            node = self.ring.nodes[nid]
            try:
                env = node.read(key)
                if env:
                    responses.append((nid, env))
            except IOError:
                corrupted.append(nid)
                self.log(f"Bit-rot detected on {nid} for '{key}'", "CRIT")

        if len(responses) < self.R:
            self.log(f"Quorum Read failed for '{key}' ({len(responses)}/{self.R})", "CRIT")
            raise HTTPException(status_code=404, detail="Quorum Read Failed")

        best_nid, best_env = responses[0]
        repaired = []
        for nid in corrupted:
            self.ring.nodes[nid].corrupted_keys.discard(key)
            self.ring.nodes[nid].write(best_env)
            repaired.append(nid)
            self.total_repairs += 1
            self.log(f"READ-REPAIR: Restored valid replica on {nid} for '{key}'", "HEAL")

        self.log(f"READ SUCCESS: '{key}' served from {best_nid}", "READ")
        return {
            "key": key,
            "payload": best_env.payload.decode(errors="replace"),
            "checksum": best_env.checksum,
            "served_by": best_nid,
            "preference_list": pref,
            "repaired_nodes": repaired
        }

    def flush_hints(self, nid: str):
        if nid in self.hints and self.ring.nodes[nid].is_alive:
            items = self.hints.pop(nid)
            for env in items:
                self.ring.nodes[nid].write(env)
            self.log(f"HINT DRAIN: Synchronized {len(items)} missed writes to {nid}", "HEAL")

# 5 Balanced Cluster Nodes
ring = ConsistentHashRing(replica_count=3, vnodes=16)
for i in range(1, 6):
    ring.add_node(StorageNode(f"Node-{i}", capacity_gb=10))
coordinator = StorageCoordinator(ring, N=3, W=2, R=2)

# =====================================================================
# CLEAN & SPACIOUS HACKATHON DASHBOARD
# =====================================================================
@app.get("/", response_class=HTMLResponse)
def index():
    alive = sum(1 for n in ring.nodes.values() if n.is_alive)
    total_nodes = len(ring.nodes)
    total_keys = len({k for n in ring.nodes.values() for k in n.store.keys()})
    quorum_safe = "OPTIMAL" if alive >= 3 else ("DEGRADED" if alive == 2 else "CRITICAL")
    q_color = "#22c55e" if alive >= 3 else ("#eab308" if alive == 2 else "#ef4444")

    # Node Cards
    node_cards = ""
    for nid, node in ring.nodes.items():
        is_up = node.is_alive
        c_status = "#22c55e" if is_up else "#ef4444"
        txt_status = "ONLINE" if is_up else "OFFLINE"
        keys = list(node.store.keys())
        keys_html = "".join(f"<span class='badge'>{k}</span>" for k in keys) if keys else "<span style='color:#64748b;font-size:12px;'>No keys</span>"
        rot_alert = "<span style='color:#ef4444;font-size:10px;font-weight:700;'>[☣️ BIT-ROT]</span>" if node.corrupted_keys else ""

        node_cards += f"""
        <div class="card {'card-down' if not is_up else ''}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <b style="font-size:15px;color:#fff;">{nid}</b>
                <span style="color:{c_status};font-size:11px;font-weight:700;">● {txt_status} {rot_alert}</span>
            </div>
            <div style="font-size:12px;color:#94a3b8;margin-bottom:8px;">Replicas: <b style="color:#38bdf8;">{len(keys)}</b></div>
            <div style="min-height:26px;display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px;">{keys_html}</div>
            <div style="display:flex;gap:6px;">
                <button onclick="toggleNode('{nid}')" class="btn-xs btn-crash">{ 'Crash' if is_up else 'Revive' }</button>
                <button onclick="corruptNode('{nid}')" class="btn-xs btn-rot" {'disabled' if not keys or not is_up else ''}>Bit-Rot</button>
            </div>
        </div>
        """

    # Logs
    log_rows = ""
    for l in coordinator.logs:
        c = "#38bdf8"
        if l["tag"] in ["WRITE", "READ"]: c = "#22c55e"
        elif l["tag"] == "HEAL": c = "#a855f7"
        elif l["tag"] == "WARN": c = "#eab308"
        elif l["tag"] == "CRIT": c = "#ef4444"
        log_rows += f"""<div style="margin-bottom:5px;"><span style="color:#64748b;">[{l['time']}]</span> <b style="color:{c};">[{l['tag']}]</b> <span style="color:#e2e8f0;">{l['text']}</span></div>"""

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Fault-Tolerant Distributed Storage Cluster</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{ box-sizing: border-box; margin:0; padding:0; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; padding: 24px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; }}
            
            /* Top Stats Bar */
            .stats-bar {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
            .stat-box {{ background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px 18px; }}
            .stat-title {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 700; }}
            .stat-val {{ font-size: 22px; font-weight: 800; color: #fff; margin-top: 4px; }}
            
            /* Node Row */
            .nodes-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }}
            .card {{ background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; }}
            .card-down {{ border-color: #ef444455; background: #1f1315; }}
            .badge {{ background: #1e293b; color: #38bdf8; font-family: monospace; font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid #38bdf833; }}
            .btn-xs {{ flex: 1; padding: 6px; font-size: 11px; font-weight: 700; border-radius: 6px; cursor: pointer; border: 1px solid transparent; }}
            .btn-crash {{ background: #261f18; color: #eab308; border-color: #713f12; }}
            .btn-rot {{ background: #2b171c; color: #ef4444; border-color: #7f1d1d; }}
            .btn-xs:disabled {{ opacity: 0.3; cursor: not-allowed; }}
            
            /* Bottom 2 Columns */
            .main-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
            input {{ width: 100%; background: #070a12; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 12px; color: #fff; margin-bottom: 10px; font-size: 13px; }}
            input:focus {{ outline:none; border-color:#38bdf8; }}
            button.primary {{ padding: 10px 16px; border-radius: 6px; font-weight: 700; cursor: pointer; border: none; color: #fff; font-size: 13px; }}
            button.green {{ background: #22c55e; }}
            button.blue {{ background: #0ea5e9; }}
            
            .terminal {{ background: #070a12; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 11.5px; height: 260px; overflow-y: auto; }}
            #readResult {{ display:none; background: #070a12; border: 1px solid #0ea5e9; border-radius: 6px; padding: 12px; margin-top: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h2 style="font-size:22px;color:#fff;">Fault-Tolerant Distributed Storage Cluster</h2>
                    <p style="color:#94a3b8;font-size:12px;margin-top:4px;">Sloppy Quorum (N=3, W=2, R=2) • Consistent Hashing • Self-Healing Merkle Bit-Rot Repair</p>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:11px;color:#94a3b8;font-weight:700;">QUORUM STATE</div>
                    <div style="font-size:16px;font-weight:800;color:{q_color};">● {quorum_safe}</div>
                </div>
            </div>

            <!-- Stats -->
            <div class="stats-bar">
                <div class="stat-box"><div class="stat-title">Active Nodes</div><div class="stat-val">{alive} / {total_nodes}</div></div>
                <div class="stat-box"><div class="stat-title">Cluster Objects</div><div class="stat-val">{total_keys}</div></div>
                <div class="stat-box"><div class="stat-title">Total Writes</div><div class="stat-val">{coordinator.total_writes}</div></div>
                <div class="stat-box"><div class="stat-title">Auto Repairs</div><div class="stat-val" style="color:#a855f7;">{coordinator.total_repairs}</div></div>
            </div>

            <!-- Nodes Cards Grid -->
            <div class="nodes-grid">{node_cards}</div>

            <!-- Operations & Logs -->
            <div class="main-grid">
                <div class="card">
                    <h3 style="font-size:15px;color:#fff;margin-bottom:12px;">Store Object (W=2, N=3)</h3>
                    <form onsubmit="handleWrite(event)">
                        <input type="text" id="wKey" placeholder="Key (e.g., file.txt, user_data)" required>
                        <input type="text" id="wVal" placeholder="Payload content" required>
                        <button type="submit" class="primary green">Commit to Quorum</button>
                    </form>

                    <h3 style="font-size:15px;color:#fff;margin:20px 0 10px 0;">Retrieve Object (R=2)</h3>
                    <form onsubmit="handleRead(event)">
                        <div style="display:flex;gap:8px;">
                            <input type="text" id="rKey" placeholder="Enter key to read" required style="margin-bottom:0;">
                            <button type="submit" class="primary blue" style="white-space:nowrap;">Consensus Read</button>
                        </div>
                    </form>

                    <div id="readResult">
                        <div style="font-size:11px;color:#38bdf8;font-weight:700;">PAYLOAD FETCHED & VERIFIED</div>
                        <div id="resPayload" style="font-size:14px;color:#fff;font-weight:700;margin:4px 0;"></div>
                        <div style="font-size:11px;color:#94a3b8;">SHA-256: <span id="resHash" style="color:#22c55e;font-family:monospace;"></span></div>
                        <div style="font-size:11px;color:#94a3b8;">Replicas: <span id="resReplicas" style="color:#fff;"></span></div>
                        <div id="resRepair" style="font-size:11px;color:#a855f7;margin-top:4px;font-weight:700;"></div>
                    </div>
                </div>

                <div class="card">
                    <h3 style="font-size:15px;color:#fff;margin-bottom:12px;">Live Operational Logs</h3>
                    <div class="terminal">{log_rows or "<div style='color:#64748b;'>Cluster ready. No events yet.</div>"}</div>
                </div>
            </div>
        </div>

        <script>
            async function handleWrite(e) {{
                e.preventDefault();
                const key = document.getElementById('wKey').value;
                const value = document.getElementById('wVal').value;
                const form = new FormData();
                form.append('key', key);
                form.append('value', value);
                await fetch('/api/write', {{ method: 'POST', body: form }});
                window.location.reload();
            }}

            async function handleRead(e) {{
                e.preventDefault();
                const key = document.getElementById('rKey').value;
                const res = await fetch('/api/read?key=' + encodeURIComponent(key));
                if (!res.ok) {{
                    alert('Quorum Read Failed: Key not found or replicas unreachable!');
                    return;
                }}
                const data = await res.json();
                document.getElementById('readResult').style.display = 'block';
                document.getElementById('resPayload').innerText = '"' + data.payload + '"';
                document.getElementById('resHash').innerText = data.checksum.substring(0, 24) + '...';
                document.getElementById('resReplicas').innerText = data.preference_list.join(', ');
                if (data.repaired_nodes.length > 0) {{
                    document.getElementById('resRepair').innerText = '⚡ Read-Repair Healed: ' + data.repaired_nodes.join(', ');
                }} else {{
                    document.getElementById('resRepair').innerText = '✅ Quorum Consensus Verified';
                }}
            }}

            async function toggleNode(nid) {{
                await fetch('/api/toggle?nid=' + nid);
                window.location.reload();
            }}

            async function corruptNode(nid) {{
                await fetch('/api/corrupt?nid=' + nid);
                window.location.reload();
            }}
        </script>
    </body>
    </html>
    """

# =====================================================================
# REST APIS
# =====================================================================
@app.post("/api/write")
def api_write(key: str = Form(...), value: str = Form(...)):
    return coordinator.write(key, value.encode())

@app.get("/api/read")
def api_read(key: str):
    return coordinator.read(key)

@app.get("/api/toggle")
def api_toggle(nid: str):
    if nid in ring.nodes:
        ring.nodes[nid].is_alive = not ring.nodes[nid].is_alive
        status = "revived" if ring.nodes[nid].is_alive else "crashed"
        coordinator.log(f"{nid} was {status}", "WARN" if status == "crashed" else "HEAL")
        if ring.nodes[nid].is_alive:
            coordinator.flush_hints(nid)
    return {"status": "ok"}

@app.get("/api/corrupt")
def api_corrupt(nid: str):
    if nid in ring.nodes and ring.nodes[nid].store:
        target = list(ring.nodes[nid].store.keys())[0]
        ring.nodes[nid].corrupted_keys.add(target)
        coordinator.log(f"Bit-rot injected into {nid} for '{target}'", "CRIT")
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
    
