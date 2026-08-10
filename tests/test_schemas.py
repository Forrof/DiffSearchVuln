import json
import unittest
from pathlib import Path


class SchemaTests(unittest.TestCase):
    def test_all_schemas_are_valid_json_with_unique_ids(self) -> None:
        schema_dir = Path(__file__).resolve().parents[1] / "schemas"
        schemas = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(schema_dir.glob("*.json"))]
        self.assertEqual(8, len(schemas))
        self.assertEqual(len(schemas), len({schema["$id"] for schema in schemas}))
        for schema in schemas:
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertEqual("object", schema["type"])
            self.assertTrue(
                "schema_version" in schema["properties"]
                or "protocol_version" in schema["properties"]
            )


if __name__ == "__main__":
    unittest.main()
