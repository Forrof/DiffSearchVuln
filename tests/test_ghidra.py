import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.ghidra import GhidraError, GhidraRunner, GhidraSettings
from diffsearchvuln.macho import _digest_file


class FakeExecutor:
    def __init__(self, return_code: int = 0) -> None:
        self.return_code = return_code
        self.calls = []

    def __call__(self, command, environment, log_path: Path, timeout: int) -> int:
        self.calls.append((list(command), dict(environment), timeout))
        log_path.write_text("fake Ghidra log\n", encoding="utf-8")
        if self.return_code == 0:
            script_index = command.index("ExportFunctionDossiers.java")
            output_path = Path(command[script_index + 1])
            output_path.write_text(
                json.dumps({"schema_version": "1.0.0", "function": {"address": "1000"}}) + "\n",
                encoding="utf-8",
            )
        return self.return_code


class GhidraRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ghidra_root = self.root / "ghidra"
        (self.ghidra_root / "support").mkdir(parents=True)
        (self.ghidra_root / "support/analyzeHeadless").write_text("launcher", encoding="utf-8")
        (self.ghidra_root / "Ghidra").mkdir()
        (self.ghidra_root / "Ghidra/application.properties").write_text(
            "application.version=12.1.2\n", encoding="utf-8"
        )
        self.java_home = self.root / "jdk"
        (self.java_home / "bin").mkdir(parents=True)
        (self.java_home / "bin/java").write_text("java", encoding="utf-8")
        self.script_path = self.root / "scripts"
        self.script_path.mkdir()
        (self.script_path / "ExportFunctionDossiers.java").write_text("script", encoding="utf-8")
        self.artifact = self.root / "artifact"
        self.artifact.write_bytes(b"artifact bytes")
        self.artifact_sha256, _ = _digest_file(self.artifact)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runner(self, executor: FakeExecutor) -> GhidraRunner:
        return GhidraRunner(
            analysis_root=self.root / "analysis",
            ghidra_root=self.ghidra_root,
            java_home=self.java_home,
            script_path=self.script_path,
            executor=executor,
        )

    def test_success_is_cached_and_uses_pinned_java(self) -> None:
        executor = FakeExecutor()
        runner = self.runner(executor)
        first = runner.analyze(
            self.artifact,
            artifact_sha256=self.artifact_sha256,
            architecture="arm64",
            settings=GhidraSettings(analysis_timeout_seconds=5, process_timeout_seconds=10),
        )
        second = runner.analyze(
            self.artifact,
            artifact_sha256=self.artifact_sha256,
            architecture="arm64",
            settings=GhidraSettings(analysis_timeout_seconds=5, process_timeout_seconds=10),
        )
        self.assertFalse(first.cached)
        self.assertTrue(second.cached)
        self.assertEqual(1, len(executor.calls))
        self.assertEqual(str(self.java_home.resolve()), executor.calls[0][1]["JAVA_HOME"])
        self.assertEqual(first.dossier_sha256, second.dossier_sha256)

    def test_failure_is_preserved_and_not_cached(self) -> None:
        executor = FakeExecutor(return_code=7)
        with self.assertRaisesRegex(GhidraError, "exit code 7"):
            self.runner(executor).analyze(
                self.artifact,
                artifact_sha256=self.artifact_sha256,
                architecture="arm64",
                settings=GhidraSettings(analysis_timeout_seconds=5, process_timeout_seconds=10),
            )
        failures = list((self.root / "analysis/failed").glob("*/failure.json"))
        self.assertEqual(1, len(failures))

    def test_rejects_digest_mismatch_before_launch(self) -> None:
        executor = FakeExecutor()
        with self.assertRaisesRegex(GhidraError, "digest"):
            self.runner(executor).analyze(
                self.artifact,
                artifact_sha256="0" * 64,
                architecture="arm64",
            )
        self.assertEqual([], executor.calls)


if __name__ == "__main__":
    unittest.main()
