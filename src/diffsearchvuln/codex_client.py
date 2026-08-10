from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


class CodexClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class CodexTurnResult:
    thread_id: str
    turn_id: str
    model: str
    final_response: dict[str, Any]
    duration_ms: int | None
    token_usage: dict[str, Any] | None
    event_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sandbox_configuration(
    working_directory: Path, *, workspace_write: bool
) -> tuple[str, dict[str, Any]]:
    """Return the two sandbox representations expected by Codex 0.146."""
    # thread/start uses the CLI configuration enum while turn/start uses the
    # JSON policy enum. They intentionally have different casing.
    if workspace_write:
        return (
            "workspace-write",
            {
                "type": "workspaceWrite",
                "writableRoots": [str(working_directory)],
                "networkAccess": False,
            },
        )
    return "read-only", {"type": "readOnly", "networkAccess": False}


class CodexAppServerClient:
    """Minimal synchronous JSONL client for the local Codex app-server."""

    def __init__(
        self,
        *,
        codex_binary: str | Path = "/opt/homebrew/bin/codex",
        command: Sequence[str] | None = None,
    ) -> None:
        self.codex_binary = Path(codex_binary).expanduser().resolve()
        self.command = list(command) if command else [
            str(self.codex_binary),
            "app-server",
            "--stdio",
            "-c",
            "mcp_servers={}",
            "-c",
            "features.apps=false",
            "-c",
            "features.plugins=false",
        ]
        self.process: subprocess.Popen[str] | None = None
        self.messages: queue.Queue[dict[str, Any] | Exception] = queue.Queue()
        self.events: list[dict[str, Any]] = []
        self.stderr_lines: list[str] = []
        self._request_id = 0
        self._write_lock = threading.Lock()

    def __enter__(self) -> "CodexAppServerClient":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def start(self, timeout_seconds: int = 30) -> None:
        if self.process is not None:
            return
        if not self.codex_binary.is_file() and self.command[0] == str(self.codex_binary):
            raise CodexClientError(f"Codex executable does not exist: {self.codex_binary}")
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        self._request(
            "initialize",
            {
                "clientInfo": {
                    "name": "diffsearchvuln",
                    "title": "DiffSearchVuln",
                    "version": "0.2.0",
                },
                "capabilities": {
                    "experimentalApi": True,
                    "optOutNotificationMethods": [
                        "item/agentMessage/delta",
                        "item/reasoning/textDelta",
                    ]
                },
            },
            timeout_seconds=timeout_seconds,
        )
        self._send({"method": "initialized", "params": {}})

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        if process.stdin:
            process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def list_models(self, timeout_seconds: int = 30) -> list[dict[str, Any]]:
        result = self._request(
            "model/list", {"limit": 100}, timeout_seconds=timeout_seconds
        )
        data = result.get("data")
        if not isinstance(data, list):
            raise CodexClientError("Codex model/list returned no model catalog")
        return data

    def default_model(self) -> str:
        models = self.list_models()
        for model in models:
            if model.get("isDefault") and not model.get("hidden"):
                return str(model["model"])
        for model in models:
            if not model.get("hidden"):
                return str(model["model"])
        raise CodexClientError("Codex reports no available model")

    def run_isolated(
        self,
        prompt: str,
        *,
        output_schema: dict[str, Any],
        cwd: str | Path,
        model: str | None = None,
        effort: str = "high",
        thread_name: str | None = None,
        timeout_seconds: int = 900,
        workspace_write: bool = False,
        event_handler: Callable[[dict[str, Any]], None] | None = None,
        dynamic_tools: list[dict[str, Any]] | None = None,
        dynamic_tool_handler: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> CodexTurnResult:
        if self.process is None:
            raise CodexClientError("Codex app-server is not running")
        selected_model = model or self.default_model()
        working_directory = Path(cwd).expanduser().resolve()
        working_directory.mkdir(parents=True, exist_ok=True)
        thread_sandbox, sandbox_policy = _sandbox_configuration(
            working_directory, workspace_write=workspace_write
        )
        event_start = len(self.events)
        thread_parameters: dict[str, Any] = {
            "model": selected_model,
            "cwd": str(working_directory),
            "approvalPolicy": "never",
            "sandbox": thread_sandbox,
            "personality": "none",
            "serviceName": "diffsearchvuln",
        }
        if dynamic_tools:
            if dynamic_tool_handler is None:
                raise CodexClientError("dynamic tools require a client-side handler")
            thread_parameters["dynamicTools"] = dynamic_tools
        thread_result = self._request(
            "thread/start",
            thread_parameters,
            timeout_seconds=30,
            event_handler=event_handler,
            dynamic_tool_handler=dynamic_tool_handler,
        )
        try:
            thread_id = str(thread_result["thread"]["id"])
        except (KeyError, TypeError) as error:
            raise CodexClientError("thread/start returned no thread identity") from error
        if thread_name:
            self._request(
                "thread/name/set",
                {"threadId": thread_id, "name": thread_name},
                timeout_seconds=30,
                event_handler=event_handler,
                dynamic_tool_handler=dynamic_tool_handler,
            )
        turn_result = self._request(
            "turn/start",
            {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
                "cwd": str(working_directory),
                "approvalPolicy": "never",
                "sandboxPolicy": sandbox_policy,
                "model": selected_model,
                "effort": effort,
                "personality": "none",
                "outputSchema": output_schema,
            },
            timeout_seconds=30,
            event_handler=event_handler,
            dynamic_tool_handler=dynamic_tool_handler,
        )
        try:
            turn_id = str(turn_result["turn"]["id"])
        except (KeyError, TypeError) as error:
            raise CodexClientError("turn/start returned no turn identity") from error

        completed = self._wait_for_turn(
            thread_id,
            turn_id,
            event_start=event_start,
            timeout_seconds=timeout_seconds,
            event_handler=event_handler,
            dynamic_tool_handler=dynamic_tool_handler,
        )
        turn = completed["params"]["turn"]
        if turn.get("status") != "completed":
            raise CodexClientError(
                f"Codex turn ended as {turn.get('status')}: {turn.get('error')}"
            )
        agent_messages = [
            item.get("text")
            for item in turn.get("items", [])
            if item.get("type") == "agentMessage" and isinstance(item.get("text"), str)
        ]
        if not agent_messages:
            for event in self.events[event_start:]:
                if event.get("method") != "item/completed":
                    continue
                params = event.get("params", {})
                item = params.get("item", {})
                if (
                    params.get("threadId") == thread_id
                    and params.get("turnId") == turn_id
                    and item.get("type") == "agentMessage"
                    and isinstance(item.get("text"), str)
                ):
                    agent_messages.append(item["text"])
        if not agent_messages:
            raise CodexClientError("Codex completed without an agent response")
        try:
            final_response = json.loads(agent_messages[-1])
        except json.JSONDecodeError as error:
            raise CodexClientError("Codex final response was not valid structured JSON") from error
        token_usage = None
        for event in self.events[event_start:]:
            if event.get("method") == "thread/tokenUsage/updated":
                params = event.get("params", {})
                if params.get("threadId") == thread_id:
                    token_usage = params.get("tokenUsage")
        return CodexTurnResult(
            thread_id=thread_id,
            turn_id=turn_id,
            model=selected_model,
            final_response=final_response,
            duration_ms=turn.get("durationMs"),
            token_usage=token_usage,
            event_count=len(self.events) - event_start,
        )

    def _request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout_seconds: int,
        event_handler: Callable[[dict[str, Any]], None] | None = None,
        dynamic_tool_handler: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._request_id += 1
        request_id = self._request_id
        self._send({"method": method, "id": request_id, "params": params})
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CodexClientError(f"Codex request {method} timed out")
            message = self._next_message(remaining)
            if message.get("id") == request_id:
                if "error" in message:
                    raise CodexClientError(f"Codex {method} failed: {message['error']}")
                result = message.get("result")
                if not isinstance(result, dict):
                    raise CodexClientError(f"Codex {method} returned an invalid result")
                return result
            self._handle_unsolicited(
                message,
                event_handler=event_handler,
                dynamic_tool_handler=dynamic_tool_handler,
            )

    def _wait_for_turn(
        self,
        thread_id: str,
        turn_id: str,
        *,
        event_start: int,
        timeout_seconds: int,
        event_handler: Callable[[dict[str, Any]], None] | None = None,
        dynamic_tool_handler: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        checked = event_start
        while True:
            while checked < len(self.events):
                event = self.events[checked]
                checked += 1
                if event.get("method") != "turn/completed":
                    continue
                params = event.get("params", {})
                turn = params.get("turn", {})
                if params.get("threadId") == thread_id and turn.get("id") == turn_id:
                    return event
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CodexClientError(f"Codex turn {turn_id} timed out")
            message = self._next_message(remaining)
            self._handle_unsolicited(
                message,
                event_handler=event_handler,
                dynamic_tool_handler=dynamic_tool_handler,
            )

    def _handle_unsolicited(
        self,
        message: dict[str, Any],
        *,
        event_handler: Callable[[dict[str, Any]], None] | None = None,
        dynamic_tool_handler: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        if "method" in message and "id" in message:
            if message.get("method") == "item/tool/call" and dynamic_tool_handler is not None:
                params = message.get("params")
                params = params if isinstance(params, dict) else {}
                tool = params.get("tool")
                arguments = params.get("arguments")
                if not isinstance(tool, str) or not isinstance(arguments, dict):
                    response = {
                        "contentItems": [{"type": "inputText", "text": "Invalid dynamic tool request."}],
                        "success": False,
                    }
                else:
                    try:
                        value = dynamic_tool_handler(tool, arguments)
                        response = {
                            "contentItems": [
                                {
                                    "type": "inputText",
                                    "text": json.dumps(value, sort_keys=True),
                                }
                            ],
                            "success": True,
                        }
                    except Exception as error:
                        response = {
                            "contentItems": [
                                {
                                    "type": "inputText",
                                    "text": f"Dynamic tool failed: {type(error).__name__}: {error}",
                                }
                            ],
                            "success": False,
                        }
                self._send({"id": message["id"], "result": response})
                return
            self._send(
                {
                    "id": message["id"],
                    "error": {
                        "code": -32601,
                        "message": "DiffSearchVuln does not allow server-initiated interactions",
                    },
                }
            )
            return
        self.events.append(message)
        if event_handler is not None:
            try:
                event_handler(message)
            except Exception as error:
                self.stderr_lines.append(
                    f"activity event handler failed: {type(error).__name__}: {error}"
                )

    def _send(self, message: dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None:
            raise CodexClientError("Codex app-server stdin is unavailable")
        encoded = json.dumps(message, separators=(",", ":")) + "\n"
        with self._write_lock:
            try:
                process.stdin.write(encoded)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                raise CodexClientError(f"Codex app-server closed: {self._stderr_tail()}") from error

    def _next_message(self, timeout_seconds: float) -> dict[str, Any]:
        try:
            message = self.messages.get(timeout=timeout_seconds)
        except queue.Empty as error:
            raise CodexClientError("Codex app-server response timed out") from error
        if isinstance(message, Exception):
            raise CodexClientError(f"Codex protocol failed: {message}; {self._stderr_tail()}")
        return message

    def _read_stdout(self) -> None:
        process = self.process
        assert process is not None and process.stdout is not None
        try:
            for line in process.stdout:
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("app-server emitted a non-object message")
                self.messages.put(value)
        except Exception as error:
            self.messages.put(error)
        finally:
            if process.poll() is not None:
                self.messages.put(
                    RuntimeError(f"app-server exited with code {process.returncode}")
                )

    def _read_stderr(self) -> None:
        process = self.process
        assert process is not None and process.stderr is not None
        for line in process.stderr:
            self.stderr_lines.append(line.rstrip())
            if len(self.stderr_lines) > 200:
                del self.stderr_lines[:50]

    def _stderr_tail(self) -> str:
        return "\n".join(self.stderr_lines[-30:])
