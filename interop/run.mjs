import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import jsigs from 'jsonld-signatures';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import * as sd from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {cryptosuite as edSuite} from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import * as ec from '@digitalbazaar/ecdsa-multikey';
import * as ed from '@digitalbazaar/ed25519-multikey';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from '@digitalbazaar/ed25519-verification-key-2020';

const contexts=new Map(Object.entries({
  'https://www.w3.org/ns/credentials/v2':'w3c-ns-credentials-v2.jsonld',
  'https://w3id.org/security/data-integrity/v2':'w3id-data-integrity-v2.jsonld',
  'https://w3id.org/security/multikey/v1':'w3id-multikey-v1.jsonld',
  'https://w3id.org/security/suites/ed25519-2020/v1':'w3id-ed25519-signature-2020-v1.jsonld',
  'https://www.w3.org/ns/did/v1':'w3c-did-v1.jsonld'
}).map(([url,file])=>[url,JSON.parse(readFileSync(new URL('../contexts/'+file,import.meta.url)))]));
const controller='did:web:issuer.example',id=controller+'#key-1';
const mandatory=['/issuer','/type','/id','/validFrom','/credentialSubject/id'];
const reveal=['/credentialSubject/name','/credentialSubject/items/0/name'];
function rust(v) {
  const r=spawnSync('target/debug/examples/interop',[],{input:JSON.stringify(v),encoding:'utf8',maxBuffer:8*1024*1024,timeout:20000});
  assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);
}
function loaderFor(vm) {
  return async url=>{
    const document=url===id?vm:url===controller?{'@context':'https://www.w3.org/ns/did/v1',id:controller,verificationMethod:[vm],assertionMethod:[id]}:contexts.get(url);
    assert.ok(document,'No unpinned context or DID: '+url);
    return {contextUrl:null,documentUrl:url,document};
  };
}
function unsigned() { return {
  '@context':['https://www.w3.org/ns/credentials/v2',{'name':'https://schema.org/name','secret':'https://schema.org/description','items':'https://schema.org/hasPart'}],
  id:'urn:uuid:8764226a-441c-45cd-85d1-3d838e808036',type:['VerifiableCredential'],issuer:controller,validFrom:'2026-01-01T00:00:00Z',
  credentialSubject:{id:'urn:uuid:97c796de-2b35-4cb3-86a4-b9d77e88e0da',name:'Public',secret:'hidden-canary',items:[{name:'one',secret:'nested-canary'},{name:'two',secret:'another-canary'}]}
}; }
const purpose=()=>new jsigs.purposes.AssertionProofPurpose();
for(const kind of ['eddsa-rdfc-2022','Ed25519Signature2020','ecdsa-sd-2023']) {
  console.log('Testing '+kind);
  const selective=kind==='ecdsa-sd-2023',legacy=kind==='Ed25519Signature2020';
  const pair=generateKeyPairSync(selective?'ec':'ed25519',selective?{namedCurve:'prime256v1'}:{});
  const jwk=pair.privateKey.export({format:'jwk'});
  console.log('  key generated');
  let key=selective?await ec.fromJwk({jwk,secretKey:true,id,controller}):await ed.fromJwk({jwk,secretKey:true,id,controller});
  let vm=await key.export({publicKey:true,includeContext:true});
  console.log('  key imported');
  if(legacy) { key=await Ed25519VerificationKey2020.generate({seed:Buffer.from(jwk.d,'base64url'),id,controller});vm=key.export({publicKey:true,includeContext:true}); }
  const loader=loaderFor(vm);
  const doc=unsigned();if(legacy)doc['@context'].push('https://w3id.org/security/suites/ed25519-2020/v1');
  const proof={type:legacy?kind:'DataIntegrityProof',...(!legacy&&{cryptosuite:kind}),verificationMethod:id,proofPurpose:'assertionMethod',created:'2026-01-01T00:00:00Z'};
  const makeSuite=(mode)=>legacy?new Ed25519Signature2020({key}):new DataIntegrityProof({signer:mode==='sign'?key.signer():undefined,cryptosuite:selective?(mode==='sign'?sd.createSignCryptosuite({mandatoryPointers:mandatory}):mode==='derive'?sd.createDiscloseCryptosuite({selectivePointers:reveal}):sd.createVerifyCryptosuite()):edSuite});
  const fromRust=rust({operation:'sign',algorithm:selective?'p256':'ed25519',secret:jwk.d,document:doc,proof,pointers:mandatory});
  console.log('  Rust signed');
  const forJS=selective?rust({operation:'derive',document:fromRust,public:vm.publicKeyMultibase,pointers:reveal}):fromRust;
  const checked=await jsigs.verify(forJS,{suite:makeSuite('verify'),purpose:purpose(),documentLoader:loader});
  assert.equal(checked.verified,true,checked.error?.stack);
  const fromJS=await jsigs.sign(doc,{suite:makeSuite('sign'),purpose:purpose(),documentLoader:loader});
  rust({operation:'verify',document:fromJS,public:vm.publicKeyMultibase});
  if(selective) {
    const derivedRust=rust({operation:'derive',document:fromJS,public:vm.publicKeyMultibase,pointers:reveal});
    const checked=await jsigs.verify(derivedRust,{suite:makeSuite('verify'),purpose:purpose(),documentLoader:loader});assert.equal(checked.verified,true,checked.error?.stack);
    const derivedJS=await jsigs.derive(fromRust,{suite:makeSuite('derive'),purpose:purpose(),documentLoader:loader});
    rust({operation:'verify',document:derivedJS,public:vm.publicKeyMultibase});
    for(const d of [derivedRust,derivedJS])assert.ok(!JSON.stringify(d).includes('canary'));
  }
  console.log('PASS independent bidirectional interoperability: '+kind);
}
