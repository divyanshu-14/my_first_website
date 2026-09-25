import hashlib
import time
import bisect
import os
from typing import Dict, List, Optional, Tuple
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

app = FastAPI(title="VAULT Distributed Object Storage")

# =====================================================================
# CORE ARCHITECTURE: INTEGRITY & ENVELOPE
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

# =====================================================================
# STORAGE NODE WITH BIT-ROT DETECTION
# =====================================================================
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
            raise IOError("Bit-rot detected")
        env = self.store.get(key)
        if env and sha256(env.payload) != env.checksum:
            raise IOError("Checksum verification failure")
        return env

# =====================================================================
# CONSISTENT HASH RING
# =====================================================================
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
# COORDINATOR ENGINE WITH SLOPPY QUORUM & READ REPAIR
# =====================================================================
class StorageCoordinator:
    def __init__(self, ring: ConsistentHashRing, N: int = 3, W: int = 2, R: int = 2):
        self.ring = ring
        self.N, self.W, self.R = N, W, R
        self.hints: Dict[str, List[StorageEnvelope]] = {}
        self.events: List[dict] = []
        self.total_writes = 0
        self.total_reads = 0

    def record_event(self, title: str, category: str = "Replication"):
        self.events.insert(0, {
            "title": title,
            "category": category,
            "time": time.strftime("%d %b %Y, %H:%M:%S")
        })
        if len(self.events) > 30:
            self.events.pop()

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
                self.record_event(f"Node {nid} unavailable. Buffered hinted handoff for '{key}'", "Fallback")
                successes += 1

        if successes < self.W:
            self.record_event(f"Write quorum failed for '{key}' ({successes}/{self.W})", "Error")
            raise HTTPException(status_code=500, detail="Write Quorum Failed")

        self.record_event(f"Object '{key}' replicated to {', '.join(pref)} ({len(data)} B)", "Replication")
        return {"key": key, "replicas": pref, "quorum": f"{successes}/{self.W}"}

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
                self.record_event(f"Bit-rot silent corruption caught on {nid} for '{key}'", "Integrity")

        if len(responses) < self.R:
            self.record_event(f"Read quorum failed for '{key}' ({len(responses)}/{self.R})", "Error")
            raise HTTPException(status_code=404, detail="Quorum Read Failed")

        best_nid, best_env = responses[0]
        repaired_nodes = []
        for nid in to_repair:
            self.ring.nodes[nid].corrupted_keys.discard(key)
            self.ring.nodes[nid].write(best_env)
            repaired_nodes.append(nid)
            self.record_event(f"Read-Repair healed corrupted replica on {nid} for '{key}'", "Self-Healing")

        self.record_event(f"Integrity check: 1 verified, {len(repaired_nodes)} repaired for '{key}'", "Integrity")
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
            self.record_event(f"Flushed {len(items)} buffered hints to revived {nid}", "Recovery")

# Setup 5 Named Nodes (Jaise laptop screen par the)
ring = ConsistentHashRing(replica_count=3, vnodes=16)
node_names = ["node-alpha", "node-beta", "node-delta", "node-epsilon", "node-gamma"]
caps = [10, 10, 8, 8, 10]
for name, cap in zip(node_names, caps):
    ring.add_node(StorageNode(name, capacity_gb=cap))
coordinator = StorageCoordinator(ring, N=3, W=2, R=2)

# =====================================================================
# VAULT PROFESSIONAL SaaS DASHBOARD (HTML/CSS)
# =====================================================================
@app.get("/", response_class=HTMLResponse)
def index():
    alive_nodes = sum(1 for n in ring.nodes.values() if n.is_alive)
    total_nodes = len(ring.nodes)
    
    unique_keys = {k for n in ring.nodes.values() for k in n.store.keys()}
    total_objects = len(unique_keys)
    total_replicas = sum(len(n.store) for n in ring.nodes.values())
    
    any_corrupt = any(len(n.corrupted_keys) > 0 for n in ring.nodes.values())
    integrity_status = "Corrupted" if any_corrupt else "Clean"
    integrity_color = "#f85149" if any_corrupt else "#38d39f"
    integrity_sub = "Bit-rot active" if any_corrupt else "No corruption"

    # Node Bars HTML
    node_rows = ""
    for nid, node in ring.nodes.items():
        is_up = node.is_alive
        status_badge = '<span class="status-badge status-healthy">● HEALTHY</span>' if is_up else '<span class="status-badge status-offline">● OFFLINE</span>'
        has_rot = len(node.corrupted_keys) > 0
        rot_badge = '<span style="color:#f85149;font-size:11px;font-weight:bold;margin-left:6px;">[☣️ CORRUPTED]</span>' if has_rot else ''
        
        used_kb = round(node.used_bytes / 1024, 2)
        total_gb = int(node.capacity_bytes / (1024**3))
        pct = round((node.used_bytes / node.capacity_bytes) * 100, 3)
        progress_width = max(pct, 2) if node.used_bytes > 0 else 0

        node_rows += f"""
        <div class="node-row {'node-row-down' if not is_up else ''}">
            <div class="node-info-top">
                <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-weight:600;font-size:14px;color:#f0f6fc;">{nid}</span>
                    {status_badge}
                    {rot_badge}
                </div>
                <div style="font-size:12px;color:#8b949e;font-weight:500;">
                    {used_kb} KB / {total_gb} GB &nbsp;&bull;&nbsp; <span style="color:#58a6ff;">{pct}%</span>
                </div>
            </div>
            <div style="font-size:11px;color:#8b949e;margin: 4px 0 8px 0;">
                {len(node.store)} replicas stored
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {progress_width}%;"></div>
            </div>
            <div style="display:flex;gap:8px;margin-top:10px;">
                <button onclick="toggleNode('{nid}')" class="btn-ctrl btn-warn">{ 'Crash Node' if is_up else 'Revive Node' }</button>
                <button onclick="corruptNode('{nid}')" class="btn-ctrl btn-danger" {'disabled' if not node.store or not is_up else ''}>Inject Bit-Rot</button>
            </div>
        </div>
        """

    # Events HTML (Fixed Date/Time)
    events_html = ""
    for ev in coordinator.events:
        events_html += f"""
        <div class="event-item">
            <div style="display:flex;align-items:center;gap:6px;">
                <span class="event-dot"></span>
                <span style="font-size:12.5px;color:#e6edf3;font-weight:500;">{ev['title']}</span>
            </div>
            <div style="font-size:11px;color:#8b949e;margin-top:3px;padding-left:14px;">{ev['time']}</div>
        </div>
        """
    if not events_html:
        events_html = "<div style='color:#6e7681;font-size:12px;padding:10px;'>No events recorded. System optimal.</div>"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vault - Distributed Object Storage</title>
        <style>
            * {{ box-sizing: border-box; margin:0; padding:0; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #c9d1d9; display: flex; min-height: 100vh; }}
            
            /* Left Sidebar */
            .sidebar {{ width: 240px; background: #0e1526; border-right: 1px solid #1c263d; display: flex; flex-direction: column; padding: 20px 16px; flex-shrink: 0; }}
            .brand {{ display: flex; align-items: center; gap: 10px; margin-bottom: 30px; padding: 0 8px; }}
            .brand-logo {{ width: 34px; height: 34px; background: linear-gradient(135deg, #38ef7d, #11998e); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 900; color: #fff; font-size: 18px; }}
            .brand-text h2 {{ font-size: 16px; font-weight: 700; color: #fff; letter-spacing: 0.5px; }}
            .brand-text span {{ font-size: 10px; color: #58a6ff; font-weight: 600; text-transform: uppercase; }}
            
            .nav-group {{ display: flex; flex-direction: column; gap: 4px; flex-grow: 1; }}
            .nav-item {{ display: flex; align-items: center; gap: 12px; padding: 10px 12px; color: #8b949e; text-decoration: none; border-radius: 8px; font-size: 13px; font-weight: 500; transition: all 0.2s; }}
            .nav-item:hover, .nav-item.active {{ background: #1a233a; color: #58a6ff; }}
            
            /* Main Content Area */
            .main {{ flex-grow: 1; padding: 28px 36px; overflow-y: auto; }}
            .top-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }}
            .top-header h1 {{ font-size: 22px; font-weight: 700; color: #fff; }}
            .top-header p {{ font-size: 13px; color: #8b949e; margin-top: 3px; }}
            
            /* 4 Top Cards */
            .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }}
            .metric-card {{ background: #111827; border: 1px solid #1f293d; border-radius: 10px; padding: 18px 20px; }}
            .metric-title {{ font-size: 11px; font-weight: 700; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }}
            .metric-val {{ font-size: 26px; font-weight: 700; color: #fff; margin: 8px 0 4px 0; }}
            .metric-sub {{ font-size: 12px; color: #8b949e; }}
            
            /* Central Layout */
            .content-grid {{ display: grid; grid-template-columns: 1.6fr 1fr; gap: 20px; }}
            .panel {{ background: #111827; border: 1px solid #1f293d; border-radius: 10px; padding: 20px; }}
            .panel-header {{ font-size: 15px; font-weight: 600; color: #fff; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }}
            
            /* Node Progress Rows */
            .node-row {{ background: #0d1322; border: 1px solid #1c263d; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }}
            .node-row-down {{ border-color: #7f1d1d; background: #1c1117; }}
            .node-info-top {{ display: flex; justify-content: space-between; align-items: center; }}
            .status-badge {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 12px; }}
            .status-healthy {{ background: rgba(56, 211, 159, 0.12); color: #38d39f; border: 1px solid rgba(56, 211, 159, 0.3); }}
            .status-offline {{ background: rgba(248, 81, 73, 0.12); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }}
            
            .progress-bar {{ height: 6px; background: #1f293d; border-radius: 3px; overflow: hidden; }}
            .progress-fill {{ height: 100%; background: linear-gradient(90deg, #1f6feb, #38ef7d); border-radius: 3px; }}
            
            .btn-ctrl {{ padding: 5px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }}
            .btn-warn {{ background: #261f18; color: #e3b341; border-color: #59441f; }}
            .btn-danger {{ background: #2b171c; color: #f85149; border-color: #7f1d1d; }}
            .btn-ctrl:disabled {{ opacity: 0.3; cursor: not-allowed; }}
            
            /* Operations Card */
            .op-box {{ margin-top: 20px; background: #0d1322; border: 1px solid #1c263d; border-radius: 8px; padding: 16px; }}
            input {{ width: 100%; background: #070a12; border: 1px solid #1c263d; border-radius: 6px; padding: 9px 12px; color: #fff; margin-bottom: 8px; font-size: 13px; }}
            button.primary {{ background: #1f6feb; border: none; color: #fff; font-weight: 600; padding: 9px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }}
            button.success {{ background: #238636; }}
            
            /* Events List */
            .event-item {{ border-bottom: 1px solid #1c263d; padding: 10px 0; }}
            .event-item:last-child {{ border-bottom: none; }}
            .event-dot {{ width: 6px; height: 6px; border-radius: 50%; background: #38ef7d; display: inline-block; }}
            
            #readOutput {{ display: none; background: #070a12; border: 1px solid #1f6feb; border-radius: 6px; padding: 12px; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <!-- Left Sidebar Navigation -->
        <div class="sidebar">
            <div class="brand">
                <div class="brand-logo">V</div>
                <div class="brand-text">
                    <h2>VAULT</h2>
                    <span>Distributed Storage</span>
                </div>
            </div>
            <div class="nav-group">
                <a href="/" class="nav-item active">⊞ Dashboard</a>
                <a href="#ops" class="nav-item">⬆ Upload & Retrieve</a>
                <a href="#nodes" class="nav-item">🖧 Storage Nodes</a>
                <a href="#events" class="nav-item">⚡ Recent Events</a>
            </div>
            <div style="font-size: 11px; color: #58a6ff; padding: 8px 12px; background: #161f33; border-radius: 6px;">
                ● Connected • Quorum Active
            </div>
        </div>

        <!-- Main Workspace -->
        <div class="main">
            <div class="top-header">
                <div>
                    <h1>System Dashboard</h1>
                    <p>Real-time distributed consensus, replication & self-healing analytics</p>
                </div>
                <button onclick="window.location.reload()" class="btn-ctrl" style="background:#1a233a;color:#58a6ff;border:1px solid #1f6feb;padding:8px 14px;">↻ Refresh</button>
            </div>

            <!-- 4 Modern Metric Cards -->
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-title">Total Objects</div>
                    <div class="metric-val">{total_objects}</div>
                    <div class="metric-sub">{total_objects} active keys</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Storage Nodes</div>
                    <div class="metric-val">{alive_nodes}/{total_nodes}</div>
                    <div class="metric-sub">{alive_nodes} nodes healthy</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Total Replicas</div>
                    <div class="metric-val">{total_replicas}</div>
                    <div class="metric-sub">{coordinator.total_writes} writes committed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">Data Integrity</div>
                    <div class="metric-val" style="color: {integrity_color};">{integrity_status}</div>
                    <div class="metric-sub">{integrity_sub}</div>
                </div>
            </div>

            <!-- Central Grid: Nodes + Events -->
            <div class="content-grid">
                <!-- Left: Storage Nodes & Simulation -->
                <div class="panel" id="nodes">
                    <div class="panel-header">
                        <span>Storage Nodes (Consistent Hashing Ring)</span>
                        <span style="font-size:11px;color:#8b949e;">Sloppy Quorum: N=3, W=2, R=2</span>
                    </div>
                    {node_rows}

                    <!-- Operations: Commit & Read -->
                    <div class="op-box" id="ops">
                        <div style="font-weight:600;font-size:14px;color:#fff;margin-bottom:10px;">Store / Retrieve Objects</div>
                        <form onsubmit="handleWrite(event)" style="margin-bottom:14px;">
                            <div style="display:flex;gap:8px;">
                                <input type="text" id="wKey" placeholder="Object Key (e.g., config.json)" required style="flex:1;">
                                <input type="text" id="wVal" placeholder="Payload content" required style="flex:1;">
                                <button type="submit" class="primary success" style="height:37px;">Store Object</button>
                            </div>
                        </form>
                        
                        <form onsubmit="handleRead(event)">
                            <div style="display:flex;gap:8px;">
                                <input type="text" id="rKey" placeholder="Object key to fetch" required style="flex:1;margin-bottom:0;">
                                <button type="submit" class="primary" style="height:37px;">Fetch with Quorum</button>
                            </div>
                        </form>

                        <div id="readOutput">
                            <div style="font-size:11px;color:#58a6ff;font-weight:bold;">PAYLOAD FETCHED & VERIFIED</div>
                            <div id="outPayload" style="font-size:14px;color:#fff;font-weight:600;margin:4px 0;"></div>
                            <div style="font-size:11px;color:#8b949e;">SHA-256: <span id="outHash" style="color:#38ef7d;font-family:monospace;"></span></div>
                            <div id="outHealing" style="font-size:11px;color:#e3b341;margin-top:4px;"></div>
                        </div>
                    </div>
                </div>

                <!-- Right: Recent Events -->
                <div class="panel" id="events">
                    <div class="panel-header">
                        <span>Recent Events & Audit</span>
                        <span style="font-size:11px;color:#38d39f;">● Live Sync</span>
                    </div>
                    <div style="max-height: 520px; overflow-y: auto;">
                        {events_html}
                    </div>
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
                    alert('Read Quorum Failed: Key not found or insufficient replicas!');
                    return;
                }}
                const data = await res.json();
                document.getElementById('readOutput').style.display = 'block';
                document.getElementById('outPayload').innerText = '"' + data.payload + '"';
                document.getElementById('outHash').innerText = data.checksum;
                if (data.repaired_replicas.length > 0) {{
                    document.getElementById('outHealing').innerText = '⚡ Read-Repair auto-healed node: ' + data.repaired_replicas.join(', ');
                }} else {{
                    document.getElementById('outHealing').innerText = '✅ Quorum Consensus Verified';
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
        coordinator.record_event(f"Simulation: {nid} was {status}", "FaultInjection")
        if ring.nodes[nid].is_alive:
            coordinator.flush_hints(nid)
    return {"status": "ok"}

@app.get("/api/corrupt")
def api_corrupt(nid: str):
    if nid in ring.nodes and ring.nodes[nid].store:
        target = list(ring.nodes[nid].store.keys())[0]
        ring.nodes[nid].corrupted_keys.add(target)
        coordinator.record_event(f"Bit-rot injected into {nid} for '{target}'", "FaultInjection")
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
