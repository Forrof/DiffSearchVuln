import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.codex_client import _sandbox_configuration


class CodexClientTests(unittest.TestCase):
    def test_unsolicited_codex_events_reach_live_activity_handler(self) -> None:
        from diffsearchvuln.codex_client import CodexAppServerClient

        client = CodexAppServerClient(command=["unused"])
        received = []
        event = {"method": "turn/started", "params": {"threadId": "thread"}}
        client._handle_unsolicited(event, event_handler=received.append)
        self.assertEqual([event], received)
        self.assertEqual([event], client.events)

    def test_dynamic_tool_request_is_executed_by_the_client_handler(self) -> None:
        from diffsearchvuln.codex_client import CodexAppServerClient

        client = CodexAppServerClient(command=["unused"])
        sent = []
        client._send = sent.append
        client._handle_unsolicited(
            {
                "method": "item/tool/call",
                "id": 41,
                "params": {
                    "tool": "run_target",
                    "arguments": {"version": "old"},
                },
            },
            dynamic_tool_handler=lambda tool, arguments: {
                "tool": tool,
                "version": arguments["version"],
                "exit_code": 0,
            },
        )
        self.assertEqual(41, sent[0]["id"])
        self.assertTrue(sent[0]["result"]["success"])
        self.assertIn("run_target", sent[0]["result"]["contentItems"][0]["text"])

    def test_workspace_write_uses_installed_app_server_wire_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            thread_sandbox, turn_policy = _sandbox_configuration(
                directory, workspace_write=True
            )

        self.assertEqual("workspace-write", thread_sandbox)
        self.assertEqual(
            {
                "type": "workspaceWrite",
                "writableRoots": [str(directory)],
                "networkAccess": False,
            },
            turn_policy,
        )
        self.assertNotIn("readOnlyAccess", turn_policy)

    def test_read_only_uses_installed_app_server_wire_format(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            thread_sandbox, turn_policy = _sandbox_configuration(
                directory, workspace_write=False
            )

        self.assertEqual("read-only", thread_sandbox)
        self.assertEqual(
            {"type": "readOnly", "networkAccess": False}, turn_policy
        )
        self.assertNotIn("access", turn_policy)


if __name__ == "__main__":
    unittest.main()
