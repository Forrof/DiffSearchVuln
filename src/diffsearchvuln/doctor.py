from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping, Sequence


class CheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class CommandOutput:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    summary: str
    detail: str | None = None
    path: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[CheckResult, ...]

    @property
    def ok(self) -> bool:
        return all(check.status != CheckStatus.FAIL for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "checks": [asdict(check) for check in self.checks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


Runner = Callable[[Sequence[str], int], CommandOutput]
Which = Callable[[str], str | None]
Exists = Callable[[Path], bool]


def _default_runner(command: Sequence[str], timeout: int) -> CommandOutput:
    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandOutput(result.returncode, result.stdout.strip(), result.stderr.strip())
    except (OSError, subprocess.TimeoutExpired) as error:
        return CommandOutput(124, "", str(error))


class EnvironmentDoctor:
    def __init__(
        self,
        *,
        runner: Runner = _default_runner,
        which: Which = shutil.which,
        exists: Exists = Path.exists,
        environ: Mapping[str, str] | None = None,
        system: str | None = None,
        machine: str | None = None,
    ) -> None:
        self.runner = runner
        self.which = which
        self.exists = exists
        self.environ = dict(os.environ if environ is None else environ)
        self.system = system or platform.system()
        self.machine = machine or platform.machine()

    def run(self, *, deep: bool = False) -> DoctorReport:
        checks = [
            self._check_host(),
            self._check_xcode(),
            self._check_swift(),
            self._check_python(),
            self._check_go(),
            self._check_java(),
            self._check_ghidra(),
            self._check_codex(),
            self._check_sqlite(),
            self._check_apple_tools(),
        ]
        if deep:
            checks.append(self._check_ghidra_smoke())
        return DoctorReport(tuple(checks))

    def _check_host(self) -> CheckResult:
        if self.system != "Darwin":
            return CheckResult("host", CheckStatus.FAIL, "macOS is required", self.system)
        if self.machine != "arm64":
            return CheckResult(
                "host",
                CheckStatus.FAIL,
                "Apple Silicon arm64 is required for the first release",
                self.machine,
            )
        return CheckResult("host", CheckStatus.PASS, "macOS on Apple Silicon", self.machine)

    def _check_xcode(self) -> CheckResult:
        output = self.runner(["/usr/bin/xcode-select", "-p"], 10)
        if output.returncode != 0:
            return CheckResult("xcode", CheckStatus.FAIL, "full Xcode is not configured", output.stderr)
        developer_dir = output.stdout
        if developer_dir == "/Library/Developer/CommandLineTools" or "Xcode.app" not in developer_dir:
            return CheckResult(
                "xcode",
                CheckStatus.FAIL,
                "Command Line Tools are present, but full Xcode is required for SwiftUI",
                "Install Xcode, then select it with xcode-select.",
                developer_dir,
            )
        return CheckResult("xcode", CheckStatus.PASS, "full Xcode selected", path=developer_dir)

    def _check_swift(self) -> CheckResult:
        path = self.which("swift")
        if not path:
            return CheckResult("swift", CheckStatus.FAIL, "Swift is not installed")
        output = self.runner([path, "--version"], 10)
        if output.returncode != 0:
            return CheckResult("swift", CheckStatus.FAIL, "Swift could not run", output.stderr, path)
        version = _first_version(output.stdout)
        return CheckResult("swift", CheckStatus.PASS, "Swift is available", path=path, version=version)

    def _check_python(self) -> CheckResult:
        candidates = [
            self.environ.get("DIFFSEARCHVULN_PYTHON"),
            "/opt/homebrew/bin/python3.12",
            self.which("python3.12"),
        ]
        path = self._first_existing(candidates)
        if not path:
            return CheckResult("python", CheckStatus.FAIL, "Python 3.12 is required")
        output = self.runner([path, "--version"], 10)
        version = _first_version(f"{output.stdout} {output.stderr}")
        if output.returncode != 0 or _version_tuple(version) < (3, 12):
            return CheckResult(
                "python", CheckStatus.FAIL, "Python 3.12 or newer is required", output.stderr, path, version
            )
        return CheckResult("python", CheckStatus.PASS, "supported Python is available", path=path, version=version)

    def _check_java(self) -> CheckResult:
        path = self._java_executable()
        if not path:
            return CheckResult("java", CheckStatus.FAIL, "OpenJDK 21 is required")
        output = self.runner([path, "-version"], 10)
        version = _first_version(f"{output.stdout} {output.stderr}")
        if output.returncode != 0 or _version_tuple(version)[:1] != (21,):
            return CheckResult(
                "java", CheckStatus.FAIL, "OpenJDK 21 is required", output.stderr, path, version
            )
        return CheckResult("java", CheckStatus.PASS, "supported Java is available", path=path, version=version)

    def _check_go(self) -> CheckResult:
        path = self._first_existing(("/opt/homebrew/bin/go", self.which("go")))
        if not path:
            return CheckResult(
                "go",
                CheckStatus.WARN,
                "Go is unavailable; pclntab name recovery will be disabled",
            )
        output = self.runner([path, "version"], 10)
        version = _first_version(f"{output.stdout} {output.stderr}")
        if output.returncode != 0:
            return CheckResult(
                "go", CheckStatus.WARN, "Go could not run; pclntab name recovery will be disabled",
                output.stderr, path, version
            )
        return CheckResult(
            "go", CheckStatus.PASS, "Go symbol helper toolchain is available", path=path, version=version
        )

    def _ghidra_root(self) -> Path | None:
        roots = [
            self.environ.get("GHIDRA_INSTALL_DIR"),
            "/opt/homebrew/opt/ghidra/libexec",
            "/Applications/ghidra",
        ]
        for value in roots:
            if not value:
                continue
            root = Path(value)
            if self.exists(root / "support/analyzeHeadless"):
                return root
        direct = self.which("analyzeHeadless")
        if direct:
            return Path(direct).resolve().parent.parent
        return None

    def _check_ghidra(self) -> CheckResult:
        root = self._ghidra_root()
        if root is None:
            return CheckResult("ghidra", CheckStatus.FAIL, "Ghidra analyzeHeadless was not found")
        application_properties = root / "Ghidra/application.properties"
        version = None
        try:
            if self.exists(application_properties):
                for line in application_properties.read_text(encoding="utf-8").splitlines():
                    if line.startswith("application.version="):
                        version = line.split("=", 1)[1].strip()
                        break
        except OSError:
            pass
        status = CheckStatus.PASS if version == "12.1.2" else CheckStatus.WARN
        summary = "supported Ghidra is available" if status == CheckStatus.PASS else "Ghidra found; version is unverified"
        return CheckResult("ghidra", status, summary, path=str(root), version=version)

    def _check_codex(self) -> CheckResult:
        path = self.which("codex")
        if not path:
            return CheckResult("codex", CheckStatus.FAIL, "Codex CLI is not installed")
        version_output = self.runner([path, "--version"], 10)
        login_output = self.runner([path, "login", "status"], 15)
        version = _first_version(f"{version_output.stdout} {version_output.stderr}")
        if version_output.returncode != 0:
            return CheckResult("codex", CheckStatus.FAIL, "Codex CLI could not run", version_output.stderr, path)
        login_text = f"{login_output.stdout} {login_output.stderr}".lower()
        if login_output.returncode != 0 or "logged in" not in login_text:
            return CheckResult("codex", CheckStatus.FAIL, "Codex CLI is not authenticated", path=path, version=version)
        method = "ChatGPT" if "chatgpt" in login_text else "configured account"
        return CheckResult(
            "codex", CheckStatus.PASS, f"Codex CLI authenticated with {method}", path=path, version=version
        )

    def _check_sqlite(self) -> CheckResult:
        version = sqlite3.sqlite_version
        return CheckResult("sqlite", CheckStatus.PASS, "Python SQLite is available", version=version)

    def _check_apple_tools(self) -> CheckResult:
        required = ("codesign", "lipo", "shasum", "hdiutil", "pkgutil")
        missing = [tool for tool in required if not self.which(tool)]
        if missing:
            return CheckResult(
                "apple_tools", CheckStatus.FAIL, "required Apple tools are missing", ", ".join(missing)
            )
        return CheckResult("apple_tools", CheckStatus.PASS, "required Apple artifact tools are available")

    def _check_ghidra_smoke(self) -> CheckResult:
        root = self._ghidra_root()
        sample = Path("/usr/bin/true")
        if root is None or not self.exists(sample):
            return CheckResult("ghidra_smoke", CheckStatus.FAIL, "Ghidra smoke-test prerequisites are missing")
        with tempfile.TemporaryDirectory(prefix="diffsearchvuln-doctor-") as temp_dir:
            command = [
                "/usr/bin/env",
                f"JAVA_HOME={self._java_home()}",
                str(root / "support/analyzeHeadless"),
                temp_dir,
                "doctor-project",
                "-import",
                str(sample),
                "-analysisTimeoutPerFile",
                "120",
                "-deleteProject",
            ]
            output = self.runner(command, 180)
        combined = f"{output.stdout}\n{output.stderr}"
        if output.returncode != 0 or "Import succeeded" not in combined:
            return CheckResult(
                "ghidra_smoke", CheckStatus.FAIL, "Ghidra could not analyze a Mach-O sample", combined[-2000:]
            )
        return CheckResult("ghidra_smoke", CheckStatus.PASS, "Ghidra headless Mach-O import succeeded")

    def _java_executable(self) -> str | None:
        java_home = self.environ.get("DIFFSEARCHVULN_JAVA_HOME")
        candidates = [
            str(Path(java_home) / "bin/java") if java_home else None,
            "/opt/homebrew/opt/openjdk@21/bin/java",
            self.which("java"),
        ]
        return self._first_existing(candidates)

    def _java_home(self) -> str:
        java_path = self._java_executable()
        if java_path is None:
            return ""
        return str(Path(java_path).resolve().parent.parent)

    def _first_existing(self, candidates: Sequence[str | None]) -> str | None:
        for value in candidates:
            if value and self.exists(Path(value)):
                return value
        return None


def _first_version(text: str) -> str | None:
    match = re.search(r"\b(\d+(?:\.\d+){0,3})\b", text)
    return match.group(1) if match else None


def _version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    return tuple(int(piece) for piece in version.split("."))
