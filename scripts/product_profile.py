#!/usr/bin/env python3
"""Discover Schema.org product sidecars and generate a shared Holon profile."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
PROFILE_ID = 'https://gs1-product.perdl.com/schemas/product-holon-v1'
CONTEXT_ID = 'https://gs1-product.perdl.com/contexts/product-holon-v1.jsonld'
SNAPSHOT = REPO / 'contexts/vendor/schemaorg-2026-10-07.jsonld'
SCHEMA_CONTEXTS = {'https://schema.org', 'https://schema.org/', 'http://schema.org', 'http://schema.org/'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError(f'duplicate JSON property: {k}')
            result[k] = v
        return result
    def invalid(value):
        raise ValueError(f'non-finite JSON number: {value}')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def schemaorg():
    data = SNAPSHOT.read_bytes()
    provenance = strict_json(SNAPSHOT.with_suffix('.provenance.json').read_bytes())
    if sha(data) != provenance['sha256']:
        raise ValueError('Schema.org snapshot does not match its recorded digest')
    return strict_json(data)['@context'], provenance


def infer_schema(values):
    """Union observed shapes; no inferred business requirements or value coercion."""
    groups = {}
    for v in values:
        if isinstance(v, bool): kind = 'boolean'
        elif isinstance(v, (int, float)):
            if isinstance(v, float) and not math.isfinite(v):
                raise ValueError('non-finite number')
            kind = 'number'
        elif isinstance(v, str): kind = 'string'
        elif isinstance(v, dict): kind = 'object'
        elif isinstance(v, list): kind = 'array'
        else: raise ValueError('null values are unsupported by the Holon VC profile')
        groups.setdefault(kind, []).append(v)
    alternatives = []
    for kind, samples in sorted(groups.items()):
        result = {'type': kind}
        if kind == 'object':
            names = sorted(set().union(*(v.keys() for v in samples)))
            result['properties'] = {k: infer_schema([v[k] for v in samples if k in v]) for k in names}
            result['additionalProperties'] = False
        elif kind == 'array':
            members = [v for sample in samples for v in sample]
            # An empty-only array cannot establish its item type: fail closed on additions.
            result['items'] = infer_schema(members) if members else False
        alternatives.append(result)
    return alternatives[0] if len(alternatives) == 1 else {'anyOf': alternatives}


def inspect_product(product, official):
    if not isinstance(product, dict) or product.get('@context') not in SCHEMA_CONTEXTS:
        raise ValueError('expected a product object with a single Schema.org context URL')
    terms = set()
    def walk(v, root=False):
        if isinstance(v, dict):
            for key, value in v.items():
                if key == '@context':
                    if not root: raise ValueError('nested contexts require an explicitly reviewed profile')
                    continue
                if key.startswith('@') and key not in ('@id', '@type'):
                    raise ValueError(f'unsupported JSON-LD keyword: {key}')
                if not key.startswith('@'): terms.add(key)
                if key in ('@id', 'id'):
                    if not isinstance(value, str) or not urlsplit(value).scheme:
                        raise ValueError('node identifiers must be absolute IRIs')
                if key in ('@type', 'type'):
                    types = value if isinstance(value, list) else [value]
                    if not types or not all(isinstance(t, str) for t in types):
                        raise ValueError('invalid JSON-LD type')
                    terms.update(types)
                walk(value)
        elif isinstance(v, list):
            for item in v: walk(item)
        elif v is None:
            raise ValueError('null values are unsupported by the Holon VC profile')
    walk(product, True)
    for a, b in [('@id', 'id'), ('@type', 'type')]:
        if a in product and b in product:
            raise ValueError(f'ambiguous product aliases: {a} and {b}')
    id_key = '@id' if '@id' in product else 'id'
    type_key = '@type' if '@type' in product else 'type'
    if id_key not in product or type_key not in product:
        raise ValueError('product requires @id/id and @type/type')
    types = product[type_key] if isinstance(product[type_key], list) else [product[type_key]]
    if 'Product' not in types:
        raise ValueError('product type must include Product')
    if not isinstance(product.get('name'), str) or not product['name'].strip():
        raise ValueError('product name must be nonempty')
    if not isinstance(product.get('gtin14'), str) or not re.fullmatch(r'[0-9]{14}', product['gtin14']):
        raise ValueError('gtin14 must be a 14-digit string')
    unknown = terms - official.keys()
    if unknown:
        raise ValueError('unmapped Schema.org terms: ' + ', '.join(sorted(unknown)))
    return terms, id_key, type_key


def build_product_profile(products_dir, profile_id=PROFILE_ID, context_id=CONTEXT_ID):
    """Read-only discovery. Return generated artifacts; never edit product values."""
    if not profile_id.startswith('https://') or not context_id.startswith('https://'):
        raise ValueError('profile and context identifiers must be HTTPS URLs')
    official, provenance = schemaorg()
    paths = sorted(Path(products_dir).rglob('product.jsonld'))
    if not paths:
        raise ValueError('no product.jsonld files found')
    products, sources, terms, aliases = [], [], set(), set()
    ids, gtins = set(), set()
    for path in paths:
        data = path.read_bytes()
        if len(data) > 4 * 1024 * 1024: raise ValueError(f'{path}: file exceeds 4 MiB')
        try:
            product = strict_json(data)
            found, id_key, type_key = inspect_product(product, official)
        except (ValueError, TypeError) as e:
            raise ValueError(f'{path}: {e}') from e
        if product[id_key] in ids or product['gtin14'] in gtins:
            raise ValueError(f'{path}: duplicate product identifier or GTIN')
        ids.add(product[id_key]); gtins.add(product['gtin14'])
        terms.update(found); aliases.add((id_key, type_key))
        products.append({k: v for k, v in product.items() if k != '@context'})
        sources.append({'path': path.relative_to(products_dir).as_posix(),
                        'sha256': sha(data), 'id': product[id_key],
                        'gtin14': product['gtin14'], 'name': product['name']})
    scoped = {k: copy.deepcopy(official[k]) for k in sorted(terms)}
    # Include every referenced prefix/term from the official context unchanged.
    pending = list(scoped.values())
    while pending:
        definition = pending.pop()
        if isinstance(definition, dict): pending.extend(definition.values())
        elif isinstance(definition, list): pending.extend(definition)
        elif isinstance(definition, str) and not definition.startswith('@'):
            dependency = definition.split(':', 1)[0] if ':' in definition else definition
            if dependency in official and dependency not in scoped:
                scoped[dependency] = copy.deepcopy(official[dependency])
                pending.append(scoped[dependency])
    context = {'@context': ['urn:holon:context:1.0', {
        'ProductHolon': profile_id + '#ProductHolon',
        'product': {'@id': profile_id + '#product', '@context': dict(sorted(scoped.items()))},
    }]}
    product_schema = infer_schema(products)
    product_schema['required'] = ['gtin14', 'name']
    product_schema['anyOf'] = [{'required': list(pair)} for pair in sorted(aliases)]
    for id_key, type_key in aliases:
        product_schema['properties'][id_key] = {'type': 'string', 'format': 'uri', 'minLength': 1}
        product_schema['properties'][type_key] = {'anyOf': [
            {'const': 'Product'},
            {'type': 'array', 'items': {'type': 'string', 'minLength': 1},
             'contains': {'const': 'Product'}},
        ]}
    product_schema['properties']['gtin14'] = {'type': 'string', 'pattern': '^[0-9]{14}$'}
    product_schema['properties']['name'] = {'type': 'string', 'minLength': 1}
    full = strict_json((REPO / 'schemas/holon-v1.schema.json').read_bytes())
    full.update({'$id': profile_id, 'title': 'Shared Schema.org product Holon'})
    full['properties']['type'] = {'const': 'ProductHolon'}
    full['properties']['claims'] = {'type': 'object', 'required': ['product'],
                                    'properties': {'product': product_schema}, 'additionalProperties': False}
    disclosure = copy.deepcopy(full)
    disclosure['required'].remove('createdAt')
    report = {'profileId': profile_id, 'contextId': context_id, 'products': sources,
              'schemaorg': provenance, 'terms': sorted(terms),
              'requiredProductFields': ['@id/id', '@type/type', 'gtin14', 'name'],
              'notes': ['Other product fields are optional; observed value types are preserved.',
                        'No claims are added, coerced or corrected.',
                        'Schemas describe observed shapes, not GS1 business-rule conformance.']}
    return {'context.jsonld': context, 'schema.json': full,
            'disclosure.schema.json': disclosure, 'profile.json': report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--products-dir', type=Path, default=Path('docs/products'))
    parser.add_argument('--output', type=Path, required=True, help='New profile directory')
    parser.add_argument('--profile-id', default=PROFILE_ID)
    parser.add_argument('--context-id', default=CONTEXT_ID)
    args = parser.parse_args()
    try:
        artifacts = build_product_profile(args.products_dir.resolve(), args.profile_id, args.context_id)
        # Refuse replacement: changing a published profile needs deliberate versioning.
        args.output.mkdir(parents=True, exist_ok=False)
        for name, value in artifacts.items():
            (args.output / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
        (args.output / 'NOTICE.txt').write_text(
            'Schema.org term mappings: Google, Yahoo, Microsoft and Yandex.\n'
            'Source: https://schema.org/docs/jsonldcontext.json (2026-10-07).\n'
            'License: https://creativecommons.org/licenses/by-sa/3.0/\n'
            'Changes: selected definitions and dependencies, scoped under a Holon product property.\n')
        print(f'Generated shared profile for {len(artifacts["profile.json"]["products"])} products: {args.output}')
        print(f'Profile: {args.profile_id}')
    except (OSError, ValueError, RecursionError) as e:
        print(f'product-profile: {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
