#!/usr/bin/env python3
"""Issue the supplied product as a real VC under an isolated demonstration DID."""
import argparse
import copy
import datetime as dt
import hashlib
import html
import json
import pathlib
import secrets
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/release/holon-vc')
    parser.add_argument('--output', help='New private directory to retain artifacts')
    args = parser.parse_args()
    repo = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary).resolve()
    example = repo / 'examples/product'
    temporary = None
    if args.output:
        work = pathlib.Path(args.output).resolve()
        work.mkdir(mode=0o700, parents=True, exist_ok=False)
    else:
        temporary = tempfile.TemporaryDirectory(prefix='holon-product-')
        work = pathlib.Path(temporary.name)
    data = work / 'data'
    password = secrets.token_urlsafe(32)
    issuer = 'did:web:product-issuer.example'
    schema = 'urn:example:product-holon:1.0'
    context = 'urn:example:product-context:1.0'
    now = dt.datetime.now(dt.timezone.utc)
    expiry = (now + dt.timedelta(days=1)).isoformat()

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write(name, value):
        path = work / name
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')
        return path

    config = work / 'config.toml'
    config.write_text(f'''[contexts."{context}"]
path = {json.dumps(str(example / 'context.jsonld'))}
sha256 = "{digest(example / 'context.jsonld')}"
expires = "{expiry}"
media_type = "application/ld+json"

[schemas."{schema}"]
full = {json.dumps(str(example / 'schema.json'))}
disclosure = {json.dumps(str(example / 'disclosure.schema.json'))}
context = "{context}"
sha256 = "{digest(example / 'schema.json')}"
disclosure_sha256 = "{digest(example / 'disclosure.schema.json')}"
''')
    count = 0

    def run(*args, secret=False, expected=0):
        nonlocal count
        command = [str(binary), '--data-dir', str(data), '--config', str(config),
                   '--offline', '--output-format', 'json', *map(str, args)]
        if secret:
            command.append('--password-stdin')
        result = subprocess.run(command, input=password + '\n' if secret else '',
                                text=True, capture_output=True, timeout=90)
        if result.returncode != expected:
            raise AssertionError(f'{args[:2]}: expected {expected}, got '
                                 f'{result.returncode}: {result.stdout} {result.stderr}')
        count += 1
        return json.loads(result.stdout)

    original = json.loads((example / 'product.jsonld').read_text())
    product = {k: v for k, v in original.items() if k != '@context'}
    holon = write('product.holon.json', {
        'id': 'urn:example:holon:product:09506000134352',
        'type': 'ProductHolon', 'schemaVersion': '1.0',
        'createdAt': now.isoformat(), 'claims': {'product': product},
        'source': {'id': issuer, 'kind': 'demonstration-publisher'},
        'evidence': [], 'relatedHolons': [],
    })
    for name, algorithm, suite in [('issuer', 'ed25519', 'eddsa-rdfc-2022'),
                                    ('selective', 'p256', 'ecdsa-sd-2023')]:
        key = run('key', 'setup', '--id', name, '--controller', issuer,
                  '--algorithm', algorithm, secret=True)
        run('suite', 'setup', '--name', name, '--key', data / f'keys/private/{name}.json',
            '--verification-method', key['id'], '--cryptosuite', suite)
        run('trust', 'add', '--id', name, '--issuer', issuer,
            '--verification-method', key['id'], '--fingerprint', key['fingerprint'],
            '--credential-type', 'HolonCredential', '--schema', schema,
            '--purpose', 'holon-assertion')
    run('well-known', 'generate', '--origin', 'https://product-issuer.example',
        '--issuer-did', issuer, '--suite', 'issuer', secret=True)
    run('status', 'create', '--id', 'products',
        '--url', 'https://product-issuer.example/status/products',
        '--suite', 'issuer', secret=True)
    for name in ['issuer', 'selective']:
        credential = work / f'{name}.vc.json'
        run('credential', 'issue', '--holon', holon, '--schema-id', schema,
            '--suite', name, '--status-list', data / 'status/products.json',
            '--expires', expiry, '--output', credential, secret=True)
        report = run('credential', 'verify', '--credential', credential,
                     '--threshold', 'trusted-assertion',
                     '--output', work / f'{name}.report.json')
        assert report['cryptographicallyValid'] and report['decision'] == 'trusted-assertion'
        assert json.loads(credential.read_text())['credentialSubject']['claims']['product'] == product

    issued = json.loads((work / 'issuer.vc.json').read_text())
    for field in ['price', 'ingredients', 'review']:
        changed = copy.deepcopy(issued)
        p = changed['credentialSubject']['claims']['product']
        if field == 'price':
            p['offers']['price'] = 0.01
        elif field == 'ingredients':
            p['gs1:ingredientStatement'] = 'Changed after signing'
        else:
            p['review'][0]['reviewBody'] = 'Changed after signing'
        path = write(f'tampered-{field}.json', changed)
        report = run('credential', 'verify', '--credential', path, expected=5)
        assert not report['cryptographicallyValid']

    derived = work / 'derived.vc.json'
    run('credential', 'derive', '--credential', work / 'selective.vc.json',
        '--reveal', example / 'reveal.json', '--output', derived)
    report = run('credential', 'verify', '--credential', derived,
                 '--threshold', 'trusted-assertion', '--output', work / 'derived.report.json')
    assert report['cryptographicallyValid'] and report['decision'] == 'trusted-assertion'
    disclosed = json.loads(derived.read_text())['credentialSubject']['claims']['product']
    assert disclosed['gs1:ingredientStatement'] == product['gs1:ingredientStatement']
    assert disclosed['gtin14'] == product['gtin14']
    assert not {'offers', 'review', 'aggregateRating', 'sku'} & disclosed.keys()

    # HTML escaping in a JSON script must preserve JSON, not turn quotes into entities.
    embedded = json.dumps(issued, indent=2, ensure_ascii=True).replace('<', '\\u003c')
    page = f'''<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>Product Holon credential demonstration</title>
<h1>{html.escape(product['name'])}</h1>
<p>Demonstration assertion issued by {html.escape(issuer)}. Not a brand-owner endorsement.</p>
<p>The local workflow verified this credential when generated. This page performs no live verification.</p>
<p><a href="issuer.vc.json">Download full Ed25519 credential</a> ·
<a href="derived.vc.json">Download selectively disclosed P-256 credential</a></p>
<script id="product-credential" type="application/ld+json">{embedded}</script>
<h2>Signed product claims</h2>
<pre>{html.escape(json.dumps(product, indent=2, ensure_ascii=False))}</pre>
</html>
'''
    (work / 'product.html').write_text(page)
    assert json.loads(embedded) == issued
    print(f'PASS: {count} CLI operations; full Ed25519/P-256 credentials, three tamper '
          'rejections, real selective disclosure, product preservation and HTML embedding.')
    if args.output:
        print(f'Artifacts: {work}\nPrivate data is in data/; do not publish the entire directory. '
              'The random key password is not retained. Status pins expire after five minutes.')
    if temporary:
        temporary.cleanup()


if __name__ == '__main__':
    main()
