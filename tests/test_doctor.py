import unittest
from pathlib import Path

from diffsearchvuln.doctor import CheckStatus, CommandOutput, EnvironmentDoctor


class FakeEnvironment:
    paths = {
        "swift": "/usr/bin/swift",
        "python3.12": "/opt/homebrew/bin/python3.12",
        "go": "/opt/homebrew/bin/go",
        "java": "/opt/homebrew/opt/openjdk@21/bin/java",
        "codex": "/opt/homebrew/bin/codex",
        "codesign": "/usr/bin/codesign",
        "lipo": "/usr/bin/lipo",
        "shasum": "/usr/bin/shasum",
        "hdiutil": "/usr/bin/hdiutil",
        "pkgutil": "/usr/sbin/pkgutil",
    }

    existing = {
        "/opt/homebrew/bin/python3.12",
        "/opt/homebrew/bin/go",
        "/opt/homebrew/opt/openjdk@21/bin/java",
        "/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless",
        "/opt/homebrew/opt/ghidra/libexec/Ghidra/application.properties",
        "/usr/bin/true",
    }

    def which(self, name: str) -> str | None:
        return self.paths.get(name)

    def exists(self, path: Path) -> bool:
        return str(path) in self.existing

    def run(self, command, timeout: int) -> CommandOutput:
        del timeout
        key = tuple(command)
        if key == ("/usr/bin/xcode-select", "-p"):
            return CommandOutput(0, "/Applications/Xcode.app/Contents/Developer", "")
        if key[-1:] == ("--version",) and "swift" in key[0]:
            return CommandOutput(0, "Swift version 6.1.2", "")
        if key[-1:] == ("--version",) and "python" in key[0]:
            return CommandOutput(0, "Python 3.12.13", "")
        if key[-1:] == ("version",) and key[0].endswith("/go"):
            return CommandOutput(0, "go version go1.26.5 darwin/arm64", "")
        if key[-1:] == ("-version",) and "java" in key[0]:
            return CommandOutput(0, "", 'openjdk version "21.0.12"')
        if key[-1:] == ("--version",) and "codex" in key[0]:
            return CommandOutput(0, "codex-cli 0.146.0", "")
        if key[-2:] == ("login", "status"):
            return CommandOutput(0, "Logged in using ChatGPT", "")
        if any("analyzeHeadless" in part for part in key):
            return CommandOutput(0, "Import succeeded", "")
        raise AssertionError(f"unexpected command: {command}")


class DoctorTests(unittest.TestCase):
    def make_doctor(self, fake: FakeEnvironment) -> EnvironmentDoctor:
        return EnvironmentDoctor(
            runner=fake.run,
            which=fake.which,
            exists=fake.exists,
            system="Darwin",
            machine="arm64",
        )

    def test_all_expected_checks_pass(self) -> None:
        fake = FakeEnvironment()
        report = self.make_doctor(fake).run(deep=True)
        self.assertTrue(report.ok)
        self.assertTrue(all(check.status == CheckStatus.PASS for check in report.checks))

    def test_command_line_tools_are_not_full_xcode(self) -> None:
        fake = FakeEnvironment()

        def runner(command, timeout: int) -> CommandOutput:
            if tuple(command) == ("/usr/bin/xcode-select", "-p"):
                return CommandOutput(0, "/Library/Developer/CommandLineTools", "")
            return fake.run(command, timeout)

        doctor = EnvironmentDoctor(
            runner=runner,
            which=fake.which,
            exists=fake.exists,
            system="Darwin",
            machine="arm64",
        )
        report = doctor.run()
        xcode = next(check for check in report.checks if check.name == "xcode")
        self.assertEqual(CheckStatus.FAIL, xcode.status)
        self.assertFalse(report.ok)


if __name__ == "__main__":
    unittest.main()
