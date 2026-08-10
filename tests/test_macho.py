import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.doctor import CommandOutput
from diffsearchvuln.macho import MachOError, MachOInspector


class FakeMachORunner:
    def __call__(self, command, timeout: int) -> CommandOutput:
        del timeout
        if command[1:2] == ["-archs"]:
            return CommandOutput(0, "arm64 arm64e", "")
        if command[1:2] == ["--uuid"]:
            return CommandOutput(
                0,
                "UUID: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE (arm64) /sample\n"
                "UUID: 11111111-2222-3333-4444-555555555555 (arm64e) /sample",
                "",
            )
        if command[1:2] == ["--verify"]:
            return CommandOutput(0, "", "/sample: valid on disk")
        if command[1:2] == ["-d"]:
            return CommandOutput(
                0,
                "",
                "Identifier=example\nTeamIdentifier=TEAM\nCDHash=abc123\n"
                "Authority=Developer ID\nFormat=Mach-O universal",
            )
        raise AssertionError(command)


class ThinMachORunner(FakeMachORunner):
    def __call__(self, command, timeout: int) -> CommandOutput:
        if "-thin" in command:
            output_path = Path(command[command.index("-output") + 1])
            output_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"thin")
            return CommandOutput(0, "", "")
        inspected_path = Path(command[-1])
        is_thin = inspected_path.is_file() and inspected_path.read_bytes()[:4] == b"\xcf\xfa\xed\xfe"
        if command[1:2] == ["-archs"] and is_thin:
            return CommandOutput(0, "arm64", "")
        if command[1:2] == ["--uuid"] and is_thin:
            return CommandOutput(
                0,
                "UUID: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE (arm64) /thin",
                "",
            )
        return super().__call__(command, timeout)


class MachOInspectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_inspects_universal_macho_metadata(self) -> None:
        path = self.root / "sample"
        path.write_bytes(b"\xca\xfe\xba\xbf" + b"payload")
        inspection = MachOInspector(FakeMachORunner()).inspect(path)
        self.assertTrue(inspection.universal)
        self.assertEqual(("arm64", "arm64e"), tuple(item.architecture for item in inspection.slices))
        self.assertTrue(inspection.signature.valid)
        self.assertEqual("TEAM", inspection.signature.team_identifier)

    def test_rejects_non_macho_input_before_tool_execution(self) -> None:
        path = self.root / "text"
        path.write_text("not a binary", encoding="utf-8")
        with self.assertRaisesRegex(MachOError, "header"):
            MachOInspector(FakeMachORunner()).inspect(path)

    def test_materializes_and_revalidates_requested_slice(self) -> None:
        source = self.root / "universal"
        source.write_bytes(b"\xca\xfe\xba\xbf" + b"payload")
        destination = self.root / "arm64"
        inspection = MachOInspector(ThinMachORunner()).materialize_slice(
            source, "arm64", destination
        )
        self.assertEqual(str(destination.resolve()), inspection.path)
        self.assertFalse(inspection.universal)
        self.assertEqual(("arm64",), tuple(item.architecture for item in inspection.slices))


if __name__ == "__main__":
    unittest.main()
