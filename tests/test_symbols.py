import json
import tempfile
import unittest
from pathlib import Path

from diffsearchvuln.symbols import SymbolError, load_symbol_map


class SymbolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "symbols.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_loads_normalized_address_map(self) -> None:
        self.path.write_text(
            json.dumps({"address": "0x1000", "end": "1010", "name": "main.example"})
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual({"1000": "main.example"}, load_symbol_map(self.path))

    def test_rejects_duplicate_addresses(self) -> None:
        value = {"address": "1000", "end": "1010", "name": "main.example"}
        self.path.write_text(
            json.dumps(value) + "\n" + json.dumps(value) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(SymbolError, "ordering or identity"):
            load_symbol_map(self.path)


if __name__ == "__main__":
    unittest.main()
