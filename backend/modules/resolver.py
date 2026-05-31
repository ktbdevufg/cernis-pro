"""DNS and NetBIOS hostname resolution."""
import asyncio
import socket
import subprocess
import re
from functools import lru_cache


async def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """Reverse DNS lookup."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=timeout,
        )
        return result[0]
    except Exception:
        return ""


def get_smb_info(ip: str) -> tuple[str, str]:
    """Try to get NetBIOS name and workgroup via nmblookup."""
    try:
        out = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, encoding="utf-8", errors="replace", timeout=3
        ).stdout
        name = ""
        group = ""
        for line in out.splitlines():
            m = re.search(r"^\s+(\S+)\s+<00>\s+-\s+[BH]", line)
            if m and not name:
                name = m.group(1).strip()
            m2 = re.search(r"^\s+(\S+)\s+<00>\s+-\s+<GROUP>", line)
            if m2 and not group:
                group = m2.group(1).strip()
        return name, group
    except Exception:
        return "", ""
