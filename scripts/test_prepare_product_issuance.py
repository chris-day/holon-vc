"""Preparation must preserve claims and refuse stale profiles or overwrites."""
import json
from pathlib import Path
import tempfile
import tomllib
import unittest

from product_profile import build_product_profile, sha
from prepare_product_issuance import prepare


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.products = self.root / 'products'
        self.products.mkdir()
        self.product = {'@context': 'https://schema.org', '@id': 'https://example.org/product',
                        '@type': 'Product', 'name': 'Rice', 'gtin14': '09506000134352',
                        'offers': {'@type': 'Offer', 'price': '4.49'}}
        self.source = self.products / 'product.jsonld'
        self.source.write_text(json.dumps(self.product))
        self.profile = self.root / 'profile'
        self.profile.mkdir()
        for name, value in build_product_profile(self.products).items():
            (self.profile / name).write_text(json.dumps(value))
        self.output = self.root / 'inputs'

    def run_prepare(self):
        return prepare(self.products, self.profile, self.output,
                       'did:web:gs1-product.perdl.com', 'https://gs1-product.perdl.com')

    def test_preserves_values_pins_and_refuses_overwrite(self):
        before = self.source.read_bytes()
        self.assertEqual(self.run_prepare(), 1)
        holon = json.loads((self.output / 'holons/09506000134352.json').read_text())
        self.assertEqual(holon['claims']['product'],
                         {k: v for k, v in self.product.items() if k != '@context'})
        config = tomllib.loads((self.output / 'product-config.toml').read_text())
        pin = next(iter(config['contexts'].values()))
        self.assertEqual(pin['sha256'], sha(Path(pin['path']).read_bytes()))
        self.assertEqual(before, self.source.read_bytes())
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.run_prepare()

    def test_changed_source_rejected_before_writes(self):
        self.product['name'] = 'Changed rice'
        self.source.write_text(json.dumps(self.product))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_changed_schema_rejected_before_writes(self):
        (self.profile / 'schema.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.run_prepare()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
