"""
CERNIS PRO Remote Agent
Lightweight FastAPI server that runs on a remote host (e.g. Netcup VPS).
The main CERNIS PRO instance connects to it and proxies scan commands.

Deploy on remote host:
  pip install fastapi uvicorn requests
  python agent.py --host 0.0.0.0 --port 8766 --token YOUR_SECRET_TOKEN

Then in CERNIS PRO: add agent at https://your-server.de:8766
"""
import asyncio
import json
import os
import sys
import argparse
import hashlib
import platform
from dataclasses import dataclass, asdict
from typing import Optional

try:
    from fastapi import FastAPI, WebSocket, Header, HTTPException, Body, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


# ── Agent registration (stored in main CERNIS PRO DB) ─────────────

@dataclass
class RemoteAgent:
    id: str
    name: str
    url: str               # e.g. "http://192.168.2.1:8766"
    token: str             # shared secret
    enabled: bool  = True
    last_seen: str = ""
    version: str   = ""
    platform: str  = ""
    cidrs: list    = None  # CIDRs this agent can scan

    def to_dict(self):
        d = asdict(self)
        d["token"] = "••••••••"  # never expose token in UI
        return d


import sqlite3
from pathlib import Path

from modules.db_path import DB_PATH  # noqa


def init_agents_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS remote_agents (
            id        TEXT PRIMARY KEY,
            name      TEXT,
            url       TEXT,
            token     TEXT,
            enabled   INTEGER DEFAULT 1,
            last_seen TEXT,
            version   TEXT,
            platform  TEXT,
            cidrs     TEXT DEFAULT '[]'
        )
    """)
    conn.commit()
    conn.close()


def get_agents() -> list[dict]:
    init_agents_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM remote_agents WHERE enabled=1").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["token"] = "••••••••"
        d["cidrs"] = json.loads(d.get("cidrs") or "[]")
        result.append(d)
    return result


def save_agent(agent: dict):
    init_agents_db()
    from modules.crypto import encrypt
    token = agent.get("token", "")
    if token and not token.startswith("enc:"):
        token = encrypt(token)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT OR REPLACE INTO remote_agents
        (id, name, url, token, enabled, cidrs)
        VALUES (?,?,?,?,?,?)
    """, (
        agent["id"], agent["name"], agent["url"],
        token, int(agent.get("enabled", 1)),
        json.dumps(agent.get("cidrs", []))
    ))
    conn.commit()
    conn.close()


def delete_agent(agent_id: str):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM remote_agents WHERE id=?", (agent_id,))
    conn.commit()
    conn.close()


def get_agent_token(agent_id: str) -> str:
    conn = sqlite3.connect(str(DB_PATH))
    row = conn.execute("SELECT token FROM remote_agents WHERE id=?", (agent_id,)).fetchone()
    conn.close()
    if not row:
        return ""
    from modules.crypto import decrypt
    return decrypt(row[0])


# ── Agent client (runs in main CERNIS PRO, talks to remote) ───────

async def ping_agent(url: str, token: str) -> dict:
    """Check if remote agent is reachable and return its info."""
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{url}/agent/info",
            headers={"X-Agent-Token": token},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e), "reachable": False}


async def proxy_scan(url: str, token: str, config: dict) -> list[dict]:
    """
    Send a scan config to a remote agent via WebSocket,
    collect results and return them as a list of host dicts.
    """
    try:
        import websockets
    except ImportError:
        return [{"error": "websockets library not installed"}]

    results = []
    ws_url = url.replace("http://", "ws://").replace("https://", "wss://") + "/agent/scan"

    try:
        async with websockets.connect(
            ws_url,
            extra_headers={"X-Agent-Token": token},
            ping_timeout=10,
        ) as ws:
            await ws.send(json.dumps(config))
            async for msg in ws:
                data = json.loads(msg)
                if data.get("type") == "host_detail":
                    results.append(data)
                elif data.get("type") == "scan_complete":
                    break
                elif data.get("type") == "error":
                    break
    except Exception as e:
        results.append({"error": str(e)})

    return results


# ── Standalone Agent Server ────────────────────────────────────
# Run this on the remote host: python agent.py

def create_agent_app(token: str) -> "FastAPI":
    """Create the lightweight FastAPI app that runs on remote host."""
    if not HAS_FASTAPI:
        raise RuntimeError("fastapi not installed")

    app = FastAPI(title="CERNIS PRO Remote Agent", version="1.0b")
    app.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_methods=["*"], allow_headers=["*"])

    def check_token(x_agent_token: str = Header(default="")):
        if x_agent_token != token:
            raise HTTPException(status_code=401, detail="Invalid token")

    @app.get("/agent/info")
    async def agent_info(x_agent_token: str = Header(default="")):
        check_token(x_agent_token)
        return {
            "reachable": True,
            "version": "1.0b",
            "platform": platform.platform(),
            "hostname": platform.node(),
        }

    @app.websocket("/agent/scan")
    async def agent_scan(websocket: WebSocket):
        await websocket.accept()
        # Verify token from first message
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=5)
            config = json.loads(raw)
            if config.get("token") != token:
                await websocket.send_json({"type": "error", "message": "Invalid token"})
                return
        except Exception:
            return

        # Run scan using local modules
        sys.path.insert(0, os.path.dirname(__file__))
        try:
            from modules.discovery import discover_subnet
            from modules.vendor import lookup_vendor

            cidr = config.get("cidr", "192.168.1.0/24")

            async def on_progress(completed, total, host):
                if host.is_alive:
                    await websocket.send_json({
                        "type": "host_found",
                        "ip": host.ip, "mac": host.mac,
                        "vendor": lookup_vendor(host.mac) if host.mac else "",
                        "rtt_ms": host.rtt_ms,
                    })

            discovered = await discover_subnet(cidr, max_concurrent=64,
                                               timeout=1.0, progress_cb=on_progress)
            for host in discovered:
                await websocket.send_json({
                    "type": "host_detail",
                    "ip": host.ip, "mac": host.mac,
                    "vendor": lookup_vendor(host.mac) if host.mac else "",
                    "rtt_ms": host.rtt_ms,
                    "agent": platform.node(),
                })
            await websocket.send_json({"type": "scan_complete",
                                       "total_found": len(discovered)})
        except Exception as e:
            await websocket.send_json({"type": "error", "message": str(e)})

    return app


if __name__ == "__main__":
    if not HAS_FASTAPI:
        print("Install: pip install fastapi uvicorn")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="CERNIS PRO Remote Agent")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--token", default=os.environ.get("CERNIS PRO_TOKEN", "changeme"))
    args = parser.parse_args()

    print(f"CERNIS PRO Remote Agent v1.0b")
    print(f"Listening on {args.host}:{args.port}")
    print(f"Token: {args.token[:4]}{'*' * (len(args.token)-4)}")

    app = create_agent_app(args.token)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
