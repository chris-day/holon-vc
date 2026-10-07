#!/usr/bin/env python3
"""Prepare pinned configuration and unsigned product Holons; never sign or publish."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

from product_profile import build_product_profile, sha, strict_json


def prepare(products_dir, profile_dir, output, issuer_did, origin):
    products_dir = products_dir.resolve()
    profile_dir = profile_dir.resolve()
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError(f'output already exists: {output}')
    if not origin.startswith('https://') or '/' in origin.removeprefix('https://'):
        raise ValueError('origin must be an HTTPS origin without a trailing slash or path')
    if issuer_did != 'did:web:' + origin.removeprefix('https://'):
        raise ValueError('this helper requires a root did:web matching the origin')
    report = strict_json((profile_dir / 'profile.json').read_bytes())
    # Recheck discovery, mappings, inventory and schemas before writing anything.
    expected = build_product_profile(products_dir, report['profileId'], report['contextId'])
    for name, value in expected.items():
        if strict_json((profile_dir / name).read_bytes()) != value:
            raise ValueError(f'{name} does not match current products; regenerate and review the profile')
    now = datetime.now(timezone.utc)
    created = now.isoformat()
    expires = (now + timedelta(days=365)).isoformat()
    holons = {}
    for item in report['products']:
        data = (products_dir / item['path']).read_bytes()
        if sha(data) != item['sha256']:
            raise ValueError(f'product changed during preparation: {item["path"]}')
        product = strict_json(data)
        del product['@context']
        gtin = item['gtin14']
        holons[gtin] = {
            'id': f'{origin}/products/{gtin}/#holon', 'type': 'ProductHolon',
            'schemaVersion': '1.0', 'createdAt': created, 'claims': {'product': product},
            'source': {'id': issuer_did, 'kind': 'demonstration-publisher'},
            'evidence': [], 'relatedHolons': [],
        }
    # JSON basic strings also encode these TOML strings, including paths and quotes.
    q = lambda value: json.dumps(str(value), ensure_ascii=False)
    context = profile_dir / 'context.jsonld'
    full = profile_dir / 'schema.json'
    disclosure = profile_dir / 'disclosure.schema.json'
    config = f'''[contexts.{q(report['contextId'])}]
path = {q(context)}
sha256 = {q(sha(context.read_bytes()))}
expires = {q(expires)}
media_type = "application/ld+json"

[schemas.{q(report['profileId'])}]
full = {q(full)}
disclosure = {q(disclosure)}
context = {q(report['contextId'])}
sha256 = {q(sha(full.read_bytes()))}
disclosure_sha256 = {q(sha(disclosure.read_bytes()))}
'''
    output.mkdir(parents=True, mode=0o700)
    (output / 'holons').mkdir(mode=0o700)
    (output / 'product-config.toml').write_text(config, encoding='utf-8')
    for gtin, holon in holons.items():
        (output / 'holons' / f'{gtin}.json').write_text(
            json.dumps(holon, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return len(holons)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--products-dir', type=Path, required=True)
    parser.add_argument('--profile-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New directory for config and holons/')
    parser.add_argument('--issuer-did', default='did:web:gs1-product.perdl.com')
    parser.add_argument('--origin', default='https://gs1-product.perdl.com')
    args = parser.parse_args()
    try:
        count = prepare(args.products_dir, args.profile_dir, args.output, args.issuer_did, args.origin)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print(f'prepare-product-issuance: {error}', file=sys.stderr)
        return 1
    print(f'Prepared {count} unsigned Holons and product-config.toml in {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
