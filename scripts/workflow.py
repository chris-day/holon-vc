#!/usr/bin/env python3
"""Executable documentation: real cryptography, isolated keys, no passwords in argv."""
import argparse, json, pathlib, secrets, subprocess, tempfile
P=argparse.ArgumentParser();P.add_argument('--binary',default='target/release/holon-vc');P.add_argument('--output');args=P.parse_args()
repo=pathlib.Path(__file__).resolve().parents[1];binary=pathlib.Path(args.binary).resolve()
owned=None
if args.output:
    work=pathlib.Path(args.output).resolve();work.mkdir(mode=0o700,parents=True,exist_ok=False)
else:
    owned=tempfile.TemporaryDirectory(prefix='holon-vc-workflow-');work=pathlib.Path(owned.name)
data=work/'data';password=secrets.token_urlsafe(32)
count=0

def run(*args,expected=0,secret=False):
    global count
    cmd=[str(binary),'--data-dir',str(data),'--offline','--output-format','json',*map(str,args)]
    if secret:cmd+=['--password-stdin']
    result=subprocess.run(cmd,input=(password+'\n') if secret else '',capture_output=True,text=True,timeout=90)
    if result.returncode!=expected:
        raise AssertionError(f'{args[0:2]}: expected exit {expected}, got {result.returncode}; {result.stdout}; {result.stderr}')
    value=json.loads(result.stdout);count+=1;return value

def output(name):return work/name
issuer='did:web:issuer.example'
key=run('key','setup','--id','issuer','--controller',issuer,secret=True)
sdkey=run('key','setup','--id','sd','--controller',issuer,'--algorithm','p256',secret=True)
for name,k,kind,purpose in [('issuer','issuer','eddsa-rdfc-2022','assertionMethod'),('holder','issuer','eddsa-rdfc-2022','authentication'),('sd','sd','ecdsa-sd-2023','assertionMethod')]:
    run('suite','setup','--name',name,'--key',data/f'keys/private/{k}.json','--verification-method',issuer+'#'+k,'--cryptosuite',kind,'--purpose',purpose)
run('suite','setup','--name','legacy','--key',data/'keys/private/issuer.json','--verification-method',issuer+'#issuer','--cryptosuite','Ed25519Signature2020','--legacy')
site=data/'site/.well-known'
run('well-known','generate','--origin','https://issuer.example','--issuer-did',issuer,'--suite','issuer','--jwks',secret=True)
run('well-known','validate','--origin','https://issuer.example','--issuer-did',issuer,'--expected-fingerprint',key['fingerprint'],'--output-dir',site)
for name,k in [('issuer',key),('sd',sdkey)]:
    run('trust','add','--id',name,'--issuer',issuer,'--verification-method',k['id'],'--fingerprint',k['fingerprint'],'--credential-type','HolonCredential','--schema','urn:holon:schema:1.0','--purpose','holon-assertion')
run('status','create','--id','main','--url','https://issuer.example/status/main','--suite','issuer',secret=True)
registry=data/'status/main.json';holon=repo/'examples/holon.json';reveal=repo/'examples/disclosure/reveal-document.json'
for name,suite,extra in [('holon','issuer',[]),('selective','sd',[]),('legacy','legacy',['--legacy'])]:
    run('credential','issue','--holon',holon,'--schema',repo/'schemas/holon-v1.schema.json','--suite',suite,'--status-list',registry,'--output',output(name+'.vc.json'),*extra,secret=True)
    report=run('credential','verify','--credential',output(name+'.vc.json'),'--threshold','trusted-assertion','--output',output(name+'.report.json'))
    assert report['decision']=='trusted-assertion' and report['status']=='active'
run('presentation','create','--credential',output('holon.vc.json'),'--output',output('unsigned.vp.json'))
r=run('presentation','verify','--presentation',output('unsigned.vp.json'));assert not r['holderAuthenticated']
challenge=secrets.token_hex(32)  # Cannot begin with a CLI option prefix.
run('presentation','create','--credential',output('holon.vc.json'),'--holder',issuer,'--suite','holder','--challenge',challenge,'--domain','verifier.example','--sign','--output',output('signed.vp.json'),secret=True)
r=run('presentation','verify','--presentation',output('signed.vp.json'),'--challenge',challenge,'--domain','verifier.example');assert r['holderAuthenticated']
r=run('presentation','verify','--presentation',output('signed.vp.json'),'--challenge',challenge,'--domain','verifier.example',expected=5);assert 'REPLAYED' in r['errors']
r=run('credential','derive','--credential',output('selective.vc.json'),'--reveal',reveal,'--output',output('derived.vc.json'));assert 'HIDDEN-CANARY' not in json.dumps(r)
run('credential','verify','--credential',output('derived.vc.json'),'--threshold','trusted-assertion')
run('credential','reissue-redacted','--credential',output('holon.vc.json'),'--reveal',reveal,'--suite','issuer','--status-list',registry,'--output',output('redacted.vc.json'),secret=True)
r=run('credential','verify','--credential',output('redacted.vc.json'));assert r['cryptographicallyValid']
assert 'HIDDEN-CANARY' not in output('redacted.vc.json').read_text()
run('status','suspend','--status-list',registry,'--credential',output('holon.vc.json'),'--suite','issuer',secret=True)
r=run('credential','verify','--credential',output('holon.vc.json'),expected=5);assert r['status']=='suspended'
run('status','restore','--status-list',registry,'--credential',output('holon.vc.json'),'--suite','issuer',secret=True)
run('credential','verify','--credential',output('holon.vc.json'))
run('status','revoke','--status-list',registry,'--credential',output('holon.vc.json'),'--suite','issuer',secret=True)
r=run('credential','verify','--credential',output('holon.vc.json'),'--output',output('revoked.report.json'),expected=5);assert r['status']=='revoked'
for group,extra in [('key',['--key',data/'keys/public/issuer.json']),('suite',['--name','issuer']),('trust',['--id','issuer']),('credential',['--credential',output('derived.vc.json')]),('presentation',['--presentation',output('unsigned.vp.json')]),('status',['--status-list',registry]),('well-known',['--output-dir',site])]:run(group,'inspect',*extra)
for group in ['key','suite','trust']:run(group,'list')
run('key','export-public','--key',data/'keys/private/issuer.json','--output',output('public-key.json'),secret=True)
run('trust','disable','--id','sd');run('trust','enable','--id','sd');run('trust','remove','--id','sd')
r=run('credential','verify','--credential',output('derived.vc.json'),'--threshold','trusted-assertion',expected=6);assert r['decision']=='authentic-assertion'
next_key=run('key','rotate','--key',data/'keys/private/issuer.json','--id','successor',secret=True)
run('suite','setup','--name','successor','--key',data/'keys/private/successor.json','--verification-method',next_key['id'])
run('well-known','generate','--origin','https://issuer.example','--issuer-did',issuer,'--suite','successor','--jwks','--force',secret=True)
run('well-known','validate','--origin','https://issuer.example','--issuer-did',issuer,'--expected-fingerprint',next_key['fingerprint'])
run('well-known','validate','--origin','https://issuer.example','--issuer-did',issuer,'--expected-fingerprint',key['fingerprint'],expected=5)
print(f'PASS: all 14 workflow steps; {count} CLI operations, real cryptography, replay rejection, redaction, rotation, revocation.')
if args.output:print(f'Artifacts: {work}')
if owned:owned.cleanup()
