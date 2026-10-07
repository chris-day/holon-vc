"""Negative and determinism checks for the read-only product profile helper."""
import json
from pathlib import Path
import tempfile
import unittest
from product_profile import build_product_profile, infer_schema

class ProductProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'product.jsonld'
        self.product = {'@context': 'https://schema.org', '@id': 'https://example.org/p',
                        '@type': 'Product', 'name': 'Example', 'gtin14': '09506000134352'}

    def generate(self, product):
        self.path.write_text(json.dumps(product))
        return build_product_profile(self.root)

    def test_unknown_and_nested_context_fail(self):
        for extra in [{'madeUpClaim': 'x'}, {'brand': {'@context': 'https://evil.example', 'name': 'x'}},
                      {'color': None}, {'@context': 'https://evil.example'}, {'gtin14': 9506000134352}]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.generate({**self.product, **extra})

    def test_duplicate_keys_fail(self):
        self.path.write_text('{"name":"one","name":"two"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            build_product_profile(self.root)

    def test_no_products_fail(self):
        with self.assertRaisesRegex(ValueError, 'no product'):
            build_product_profile(self.root)

    def test_deterministic_and_no_source_edits(self):
        first = self.generate(self.product)
        before = self.path.read_bytes()
        self.assertEqual(first, build_product_profile(self.root))
        self.assertEqual(before, self.path.read_bytes())
        properties = first['schema.json']['properties']['claims']['properties']['product']['properties']
        self.assertNotIn('review', properties)
        self.assertNotIn('gs1:ingredientStatement', properties)

    def test_duplicate_identity_fails(self):
        self.generate(self.product)
        (self.root / 'other').mkdir()
        (self.root / 'other/product.jsonld').write_text(json.dumps(self.product))
        with self.assertRaisesRegex(ValueError, 'duplicate product'):
            build_product_profile(self.root)

    def test_union_preserves_types_and_optionality(self):
        s = infer_schema([{'price': '4.49'}, {'price': 4.49, 'color': 'White'}])
        self.assertNotIn('required', s)
        self.assertEqual(s['properties']['price']['anyOf'], [{'type': 'number'}, {'type': 'string'}])
        self.assertFalse(s['additionalProperties'])

if __name__ == '__main__':
    unittest.main()
