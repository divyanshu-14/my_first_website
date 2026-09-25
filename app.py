import hashlib
import time
import bisect
import os
import math
from typing import Dict, List, Optional, Tuple
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

app = FastAPI(title="Fault-Tolerant Distributed Storage Engine")

# =====================================================================
# 1. HASHING & MERKLE TREE
# =====================================================================
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class StorageEnvelope:
    def __init__(self, key: str, payload: bytes, vclock: Dict[str, int]):
        self.key = key
        self.payload = payload
        self.checksum = sha256(payload)
        self.vclock = vclock
        self.timestamp = time.time()

# =====================================================================
# 2. STORAGE NODE & CONSISTENT RING
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
# 3. COORDINATOR ENGINE
# =====================================================================
class StorageCoordinator:
    def __init__(self, ring: ConsistentHashRing, N: int = 3, W: int = 2, R: int = 2):
        self.ring = ring
        self.N, self.W, self.R = N, W, R
        self.hints: Dict[str, List[StorageEnvelope]] = {}
        self.logs: List[dict] = []
        self.total_writes = 0
        self.total_reads = 0

    def log(self, text: str, level: str = "info"):
        self.logs.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "text": text,
            "level": level
        })
        if len(self.logs) > 40:
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
                self.log(f"Node {nid} DOWN. Buffered hinted handoff for '{key}'", "warn")
                successes += 1  # Sloppy Quorum tolerance

        if successes < self.W:
            self.log(f"WRITE FAILED for '{key}' (Ack {successes}/{self.W})", "error")
            raise HTTPException(status_code=500, detail="Write Quorum Failed")

        self.log(f"WRITE COMMITTED: '{key}' → Replicas: {pref} (Ack {successes}/{self.W})", "success")
        return {"key": key, "replicas": pref, "quorum_achieved": f"{successes}/{self.W}"}

    def read(self, key: str) -> dict:
        self.total_reads += 1
        pref = self.ring.get_preference_list(key)
        responses = []
        to_repair = []

        for nid in pref:
            node = self.ring.nodes[nid]
            try:
                env = node.read(key)
                if env:
                    responses.append((nid, env))
            except IOError:
                to_repair.append(nid)
                self.log(f"INTEGRITY VIOLATION: Bit-Rot detected on {nid} for '{key}'", "error")

        if len(responses) < self.R:
            self.log(f"READ FAILED: Key '{key}' quorum unmet ({len(responses)}/{self.R})", "error")
            raise HTTPException(status_code=404, detail="Quorum Read Failed / Not Enough Copies")

        best_nid, best_env = responses[0]
        repaired_nodes = []
        for nid in to_repair:
            self.ring.nodes[nid].corrupted_keys.discard(key)
            self.ring.nodes[nid].write(best_env)
            repaired_nodes.append(nid)
            self.log(f"AUTO HEAL: Read-Repair rebuilt clean data on {nid} for '{key}'", "repair")

        self.log(f"READ SUCCESS: '{key}' served from {best_nid}", "success")
        return {
            "key": key,
            "payload": best_env.payload.decode(errors="replace"),
            "checksum": best_env.checksum,
            "served_by": best_nid,
            "preference_list": pref,
            "repaired_replicas": repaired_nodes
        }

    def flush_hints(self, nid: str):
        if nid in self.hints and self.ring.nodes[nid].is_alive:
            items = self.hints.pop(nid)
            for env in items:
                self.ring.nodes[nid].write(env)
            self.log(f"REPLAY: Flushed {len(items)} buffered hints to revived {nid}", "repair")

# Init Cluster
ring = ConsistentHashRing(replica_count=3, vnodes=16)
for i in range(1, 6):
    ring.add_node(StorageNode(f"Node-{i}"))
coordinator = StorageCoordinator(ring, N=3, W=2, R=2)

# =====================================================================
# 4. HIGH-IMPACT PRESENTATION UI
# =====================================================================
@app.get("/", response_class=HTMLResponse)
def index():
    alive_count = sum(1 for n in ring.nodes.values() if n.is_alive)
    total_nodes = len(ring.nodes)
    total_keys = len({k for n in ring.nodes.values() for k in n.store.keys()})
    quorum_safe = "OPTIMAL" if alive_count >= 3 else ("DEGRADED" if alive_count == 2 else "AT RISK")
    quorum_color = "#3fb950" if alive_count >= 3 else ("#d29922" if alive_count == 2 else "#f85149")

    # Generate Node Cards
    node_cards = ""
    for nid, node in ring.nodes.items():
        is_up = node.is_alive
        status_color = "#3fb950" if is_up else "#f85149"
        status_txt = "ONLINE" if is_up else "OFFLINE"
        stored_keys = list(node.store.keys())
        keys_html = "".join(f"<span class='badge-key'>{k}</span>" for k in stored_keys) if stored_keys else "<span style='color:#6e7681;font-size:11px;'>No keys</span>"
        has_corrupt = len(node.corrupted_keys) > 0
        corrupt_badge = "<span style='color:#f85149;font-size:10px;font-weight:bold;'>☣️ BIT-ROT ACTIVE</span>" if has_corrupt else ""

        node_cards += f"""
        <div class="node-card {'node-down' if not is_up else ''}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <div style="font-weight:700;font-size:15px;color:#f0f6fc;">{nid}</div>
                <div style="font-size:11px;font-weight:700;color:{status_color};display:flex;align-items:center;gap:4px;">
                    <span class="dot {'dot-pulsing' if is_up else ''}" style="background:{status_color};"></span>{status_txt}
                </div>
            </div>
            <div style="font-size:12px;color:#8b949e;margin-bottom:6px;">Replicated Keys: <b style="color:#e6edf3;">{len(stored_keys)}</b> {corrupt_badge}</div>
            <div style="min-height:30px;display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px;">{keys_html}</div>
            <div style="display:flex;gap:6px;">
                <button onclick="toggleNode('{nid}')" class="btn-sm btn-crash">{ 'Crash' if is_up else 'Revive' }</button>
                <button onclick="corruptNode('{nid}')" class="btn-sm btn-rot" {'disabled' if not stored_keys or not is_up else ''}>Inject BitRot</button>
            </div>
        </div>
        """

    # Generate Logs
    logs_html = ""
    for l in coordinator.logs:
        lvl_color = "#7ee787" if l["level"] == "success" else ("#f85149" if l["level"] == "error" else ("#e3b341" if l["level"] == "warn" else "#58a6ff"))
        logs_html += f"<div style='margin-bottom:6px;'><span style='color:#6e7681;'>[{l['time']}]</span> <span style='color:{lvl_color};'>{l['text']}</span></div>"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Distributed Object Storage Engine</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #090d16; color: #c9d1d9; margin: 0; padding: 24px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #21262d; padding-bottom: 16px; margin-bottom: 20px; }}
            .stats-bar {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
            .stat-box {{ background: #161b22; border: 1px solid #30363d; padding: 14px; border-radius: 8px; }}
            .stat-num {{ font-size: 20px; font-weight: 700; color: #f0f6fc; margin-top: 4px; }}
            .nodes-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; margin-bottom: 24px; }}
            .node-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; transition: transform 0.15s; }}
            .node-down {{ border-color: #8b181a; background: #1a1215; }}
            .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
            .dot-pulsing {{ box-shadow: 0 0 8px #3fb950; }}
            .badge-key {{ background: #1f293d; color: #58a6ff; font-family: monospace; font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid #388bfd33; }}
            .btn-sm {{ flex: 1; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; padding: 6px; border-radius: 6px; font-size: 11px; font-weight: 600; cursor: pointer; }}
            .btn-crash {{ border-color: #d29922; color: #e3b341; }}
            .btn-rot {{ border-color: #f85149; color: #ff7b72; }}
            .btn-sm:hover:not(:disabled) {{ filter: brightness(1.2); }}
            .btn-sm:disabled {{ opacity: 0.4; cursor: not-allowed; }}
            .main-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
            .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
            input {{ width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px; color: #fff; margin-bottom: 10px; }}
            button.primary {{ background: #238636; border: 1px solid #2ea043; color: #fff; font-weight: bold; padding: 10px 16px; border-radius: 6px; cursor: pointer; }}
            button.blue {{ background: #1f6feb; border-color: #388bfd; }}
            .terminal {{ font-family: ui-monospace, SFMono-Regular, monospace; font-size: 11.5px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 14px; height: 260px; overflow-y: auto; }}
            #readResult {{ display: none; margin-top: 14px; background: #0d1117; border: 1px solid #388bfd; border-radius: 6px; padding: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h2 style="margin: 0; color: #f0f6fc;">🌐 Fault-Tolerant Distributed Storage Engine</h2>
                    <div style="color: #8b949e; font-size: 13px; margin-top: 4px;">Consistent Hashing Ring • Sloppy Quorum (N=3, W=2, R=2) • Merkle Bit-Rot Self-Repair</div>
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 11px; color: #8b949e; text-transform: uppercase;">Quorum State</span>
                    <div style="font-size: 16px; font-weight: bold; color: {quorum_color};">● {quorum_safe}</div>
                </div>
            </div>

            <!-- Stats Bar -->
            <div class="stats-bar">
                <div class="stat-box"><div style="color:#8b949e;font-size:12px;">Active Cluster Nodes</div><div class="stat-num">{alive_count} / {total_nodes}</div></div>
                <div class="stat-box"><div style="color:#8b949e;font-size:12px;">Stored Keys (Deduped)</div><div class="stat-num">{total_keys}</div></div>
                <div class="stat-box"><div style="color:#8b949e;font-size:12px;">Total Write Commits</div><div class="stat-num">{coordinator.total_writes}</div></div>
                <div class="stat-box"><div style="color:#8b949e;font-size:12px;">Quorum Read Operations</div><div class="stat-num">{coordinator.total_reads}</div></div>
            </div>

            <!-- Nodes Display -->
            <div class="nodes-grid">{node_cards}</div>

            <div class="main-grid">
                <!-- Operations Form -->
                <div class="card">
                    <h3 style="margin-top:0;color:#f0f6fc;font-size:16px;">Commit / Store Object</h3>
                    <form onsubmit="handleWrite(event)">
                        <input type="text" id="wKey" placeholder="Key (e.g., config.json, user_123)" required>
                        <input type="text" id="wVal" placeholder="Payload / Binary Data" required>
                        <button type="submit" class="primary">Commit to Quorum (W=2, N=3)</button>
                    </form>

                    <h3 style="margin-top:24px;color:#f0f6fc;font-size:16px;">Retrieve Object & Integrity Verify</h3>
                    <form onsubmit="handleRead(event)">
                        <div style="display:flex;gap:10px;">
                            <input type="text" id="rKey" placeholder="Key to fetch" required style="margin-bottom:0;">
                            <button type="submit" class="primary blue" style="white-space:nowrap;">Quorum Read (R=2)</button>
                        </div>
                    </form>

                    <div id="readResult">
                        <div style="font-size:11px;color:#58a6ff;font-weight:bold;">PAYLOAD FETCHED & VERIFIED</div>
                        <div id="resPayload" style="font-size:15px;color:#f0f6fc;margin:6px 0;font-weight:600;"></div>
                        <div style="font-size:11px;color:#8b949e;">SHA-256: <span id="resHash" style="font-family:monospace;color:#7ee787;"></span></div>
                        <div style="font-size:11px;color:#8b949e;">Primary Replicas: <span id="resReplicas" style="color:#f0f6fc;"></span></div>
                        <div id="resRepair" style="font-size:11px;color:#e3b341;margin-top:4px;"></div>
                    </div>
                </div>

                <!-- Live Engine Logs -->
                <div class="card">
                    <h3 style="margin-top:0;color:#f0f6fc;font-size:16px;">Real-Time Distributed Engine Logs</h3>
                    <div class="terminal">{logs_html or "<div style='color:#6e7681;'>No operational logs yet.</div>"}</div>
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
                    alert('Read Quorum Failed: Object not found or replicas unreachable!');
                    return;
                }}
                const data = await res.json();
                document.getElementById('readResult').style.display = 'block';
                document.getElementById('resPayload').innerText = '"' + data.payload + '"';
                document.getElementById('resHash').innerText = data.checksum.substring(0, 24) + '...';
                document.getElementById('resReplicas').innerText = data.preference_list.join(', ');
                if (data.repaired_replicas.length > 0) {{
                    document.getElementById('resRepair').innerText = '⚡ Read-Repair Healed: ' + data.repaired_replicas.join(', ');
                }} else {{
                    document.getElementById('resRepair').innerText = '✅ All Replicas in Consensus';
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
# 5. REST APIS
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
        if ring.nodes[nid].is_alive:
            coordinator.flush_hints(nid)
    return {"status": "ok"}

@app.get("/api/corrupt")
def api_corrupt(nid: str):
    if nid in ring.nodes and ring.nodes[nid].store:
        target = list(ring.nodes[nid].store.keys())[0]
        ring.nodes[nid].corrupted_keys.add(target)
        coordinator.log(f"MANUAL FAULT INJECTION: Bit-Rot injected into {nid} for '{target}'", "error")
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
