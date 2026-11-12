"""tools/list and resources/list must be byte-identical across processes.

Clients send the tool list at the start of every prompt, and prompt caching only
reuses an identical prefix. Python randomizes set iteration per process
(PYTHONHASHSEED), so any set feeding registration order or a schema array would
reorder the lists between server restarts.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DUMP_SCRIPT = """
import asyncio, json
from unittest.mock import MagicMock, patch

with patch("falcon_mcp.server.FalconClient") as client_class:
    client = MagicMock()
    client.authenticate.return_value = True
    client_class.return_value = client
    from falcon_mcp.server import FalconMCPServer
    server = FalconMCPServer()

async def dump():
    tools = await server.server.list_tools()
    resources = await server.server.list_resources()
    return {
        "tools": [t.model_dump(mode="json") for t in tools],
        "resources": [r.model_dump(mode="json") for r in resources],
    }

print(json.dumps(asyncio.run(dump()), sort_keys=False))
"""


def _dump(hash_seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": hash_seed, "PYTHONPATH": str(REPO_ROOT)}
    result = subprocess.run(
        [sys.executable, "-c", DUMP_SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    return result.stdout.strip().splitlines()[-1]


class TestListOrder(unittest.TestCase):
    def test_lists_identical_across_hash_seeds(self):
        first = _dump("1")
        self.assertIn('"tools"', first)
        for seed in ("2", "12345"):
            self.assertEqual(
                first,
                _dump(seed),
                f"tools/list or resources/list changed with PYTHONHASHSEED={seed}",
            )


if __name__ == "__main__":
    unittest.main()
