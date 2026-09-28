//! ECDSA-SD-2023 orchestration, using RustCrypto primitives and SSI JSON-LD selection.
//! Grouping follows SSI 0.3.0 (Apache-2.0), replacing canonicalization with bounded
//! Sophia RDFC-1.0. See THIRD_PARTY.md for provenance.
use crate::{
    canonicalization::{canonical_labels, quads},
    errors::{Result, crypto_error, error},
    keys::{Algorithm, PrivateKey, PublicKey},
    suites,
};
use rand::RngCore;
use rdf_types::{BlankIdBuf, LexicalQuad};
use serde_cbor::Value as Cbor;
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssi_core::JsonPointerBuf;
use ssi_di_sd_primitives::{
    HmacShaAnyKey,
    canonicalize::{create_hmac_id_label_map_function, relabel_quads},
    select::{select_canonical_nquads, select_json_ld},
    skolemize::{Skolemize, expanded_to_deskolemized_nquads},
};
use ssi_json_ld::{CompactJsonLd, Loader};
use ssi_rdf::IntoNQuads;
use std::collections::{BTreeMap, HashMap, HashSet};

struct Group {
    matching: BTreeMap<usize, LexicalQuad>,
    rest: BTreeMap<usize, LexicalQuad>,
    deskolemized: Vec<LexicalQuad>,
}
struct Grouped {
    groups: HashMap<&'static str, Group>,
    labels: HashMap<BlankIdBuf, BlankIdBuf>,
}

fn pointers(values: &[String]) -> Result<Vec<JsonPointerBuf>> {
    values
        .iter()
        .map(|v| {
            v.parse()
                .map_err(|_| error("INVALID_REVEAL", "disclosure", "Invalid JSON pointer"))
        })
        .collect()
}

async fn group(
    document: &Value,
    hmac_bytes: &[u8],
    definitions: &[(&'static str, Vec<String>)],
    loader: &impl Loader,
) -> Result<Grouped> {
    if hmac_bytes.len() != 32 {
        return Err(crypto_error());
    }
    // Strict expansion before the skolemizer, which otherwise permits undefined terms.
    quads(document, loader).await?;
    let doc = CompactJsonLd(json_syntax::to_value(document).map_err(|_| crypto_error())?);
    let mut skolem = Skolemize::default();
    let (expanded, compact) = skolem
        .compact_document(loader, &doc)
        .await
        .map_err(|_| crypto_error())?;
    let raw = expanded_to_deskolemized_nquads(&skolem.urn_scheme, &expanded)
        .map_err(|_| crypto_error())?;
    let mut hmac = HmacShaAnyKey::from_bytes(hmac_bytes)
        .map_err(|_| crypto_error())?
        .to_hmac();
    let normalizing = canonical_labels(&raw)?.into_iter().collect();
    let labels = create_hmac_id_label_map_function(&mut hmac)(&normalizing);
    let mut canonical = relabel_quads(&labels, &raw);
    canonical.sort_by_cached_key(|q| format!("{q} .\n"));
    canonical.dedup();
    let mut groups = HashMap::new();
    for (name, paths) in definitions {
        let chosen = select_canonical_nquads(
            loader,
            &skolem.urn_scheme,
            &pointers(paths)?,
            &labels,
            &compact,
        )
        .await
        .map_err(|_| {
            error(
                "INVALID_REVEAL",
                "disclosure",
                "Selection does not match the credential",
            )
        })?;
        let selected: HashSet<_> = chosen.quads.into_iter().collect();
        let (mut matching, mut rest) = (BTreeMap::new(), BTreeMap::new());
        for (i, q) in canonical.iter().enumerate() {
            if selected.contains(q) {
                matching.insert(i, q.clone());
            } else {
                rest.insert(i, q.clone());
            }
        }
        groups.insert(
            *name,
            Group {
                matching,
                rest,
                deskolemized: chosen.deskolemized_quads,
            },
        );
    }
    Ok(Grouped { groups, labels })
}

fn hash_lines<'a>(quads: impl Iterator<Item = &'a LexicalQuad>) -> [u8; 32] {
    Sha256::digest(quads.into_nquads().as_bytes()).into()
}
fn sign_data(proof_hash: &[u8], public: &[u8], mandatory_hash: &[u8]) -> Vec<u8> {
    [proof_hash, public, mandatory_hash].concat()
}
fn encode(kind: u8, values: Vec<Cbor>) -> Result<String> {
    let mut bytes = vec![0xd9, 0x5d, kind];
    bytes.extend(serde_cbor::to_vec(&values).map_err(|_| crypto_error())?);
    Ok(multibase::encode(multibase::Base::Base64Url, bytes))
}
fn decode(proof: &Value) -> Result<(u8, Vec<Cbor>)> {
    let s = proof["proofValue"].as_str().ok_or_else(crypto_error)?;
    if s.len() > 8 * 1024 * 1024 {
        return Err(crypto_error());
    }
    let (base, bytes) = multibase::decode(s).map_err(|_| crypto_error())?;
    if base != multibase::Base::Base64Url
        || bytes.len() < 4
        || bytes[..2] != [0xd9, 0x5d]
        || bytes[2] > 1
    {
        return Err(crypto_error());
    }
    let fields: Vec<Cbor> = serde_cbor::from_slice(&bytes[3..]).map_err(|_| crypto_error())?;
    if fields.len() != 5 {
        return Err(crypto_error());
    }
    Ok((bytes[2], fields))
}
fn bytes(v: &Cbor) -> Result<&[u8]> {
    if let Cbor::Bytes(b) = v {
        Ok(b)
    } else {
        Err(crypto_error())
    }
}
fn array(v: &Cbor) -> Result<&[Cbor]> {
    if let Cbor::Array(a) = v {
        Ok(a)
    } else {
        Err(crypto_error())
    }
}
fn strings(v: &Cbor) -> Result<Vec<String>> {
    array(v)?
        .iter()
        .map(|x| {
            if let Cbor::Text(s) = x {
                Ok(s.clone())
            } else {
                Err(crypto_error())
            }
        })
        .collect()
}

pub async fn issue(
    document: &Value,
    key: &PrivateKey,
    proof: &Value,
    mandatory: &[String],
    loader: &impl Loader,
) -> Result<Value> {
    if key.algorithm() != Algorithm::P256 || suites::suite(proof)? != suites::SELECTIVE {
        return Err(crypto_error());
    }
    let ephemeral = PrivateKey::generate(Algorithm::P256);
    let mut hmac = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(hmac.as_mut());
    let grouped = group(
        document,
        hmac.as_ref(),
        &[("mandatory", mandatory.to_vec())],
        loader,
    )
    .await?;
    let g = &grouped.groups["mandatory"];
    let pub_bytes = ephemeral.public().multicodec();
    let message = sign_data(
        &suites::proof_hash(document, proof, loader, false).await?,
        &pub_bytes,
        &hash_lines(g.matching.values()),
    );
    let signatures = g
        .rest
        .values()
        .map(|q| Cbor::Bytes(ephemeral.sign(format!("{q} .\n").as_bytes())))
        .collect();
    let value = encode(
        0,
        vec![
            Cbor::Bytes(key.sign(&message)),
            Cbor::Bytes(pub_bytes),
            Cbor::Bytes(hmac.to_vec()),
            Cbor::Array(signatures),
            Cbor::Array(mandatory.iter().map(|p| Cbor::Text(p.clone())).collect()),
        ],
    )?;
    let mut result = document.clone();
    result["proof"] = proof.clone();
    result["proof"]["proofValue"] = value.into();
    verify(&result, &key.public(), loader).await?;
    Ok(result)
}

pub async fn verify(document: &Value, issuer: &PublicKey, loader: &impl Loader) -> Result<()> {
    if issuer.algorithm != Algorithm::P256 {
        return Err(crypto_error());
    }
    let (unsigned, proof) = suites::split(document)?;
    if suites::suite(&proof)? != suites::SELECTIVE {
        return Err(crypto_error());
    }
    let (kind, fields) = decode(&proof)?;
    let ephemeral = PublicKey::from_multicodec(bytes(&fields[1])?)?;
    if ephemeral.algorithm != Algorithm::P256 {
        return Err(crypto_error());
    }
    let (mandatory, nonmandatory, signatures): (Vec<LexicalQuad>, Vec<LexicalQuad>, &[Cbor]) =
        if kind == 0 {
            let paths = strings(&fields[4])?;
            let mut grouped = group(
                &unsigned,
                bytes(&fields[2])?,
                &[("mandatory", paths)],
                loader,
            )
            .await?;
            let g = grouped
                .groups
                .remove("mandatory")
                .ok_or_else(crypto_error)?;
            (
                g.matching.into_values().collect(),
                g.rest.into_values().collect(),
                array(&fields[3])?,
            )
        } else {
            let raw = quads(&unsigned, loader).await?;
            let canonical = canonical_labels(&raw)?;
            let Cbor::Map(compressed) = &fields[3] else {
                return Err(crypto_error());
            };
            if compressed.len() != canonical.len() {
                return Err(crypto_error());
            }
            let mut labels = HashMap::new();
            for (original, label) in canonical {
                let index: i128 = label
                    .as_str()
                    .strip_prefix("_:c14n")
                    .ok_or_else(crypto_error)?
                    .parse()
                    .map_err(|_| crypto_error())?;
                let value = bytes(
                    compressed
                        .get(&Cbor::Integer(index))
                        .ok_or_else(crypto_error)?,
                )?;
                if value.len() != 32 {
                    return Err(crypto_error());
                }
                let new_label = format!("_:u{}", multibase::Base::Base64Url.encode(value));
                labels.insert(
                    original,
                    BlankIdBuf::new(new_label).map_err(|_| crypto_error())?,
                );
            }
            let mut canonical = relabel_quads(&labels, &raw);
            canonical.sort_by_cached_key(|q| format!("{q} .\n"));
            canonical.dedup();
            let indexes: Vec<usize> = array(&fields[4])?
                .iter()
                .map(|v| {
                    if let Cbor::Integer(n) = v {
                        (*n).try_into().map_err(|_| crypto_error())
                    } else {
                        Err(crypto_error())
                    }
                })
                .collect::<Result<_>>()?;
            if indexes.windows(2).any(|p| p[0] >= p[1])
                || indexes.last().is_some_and(|i| *i >= canonical.len())
            {
                return Err(crypto_error());
            }
            let (mut m, mut n) = (Vec::new(), Vec::new());
            for (i, q) in canonical.into_iter().enumerate() {
                if indexes.binary_search(&i).is_ok() {
                    m.push(q);
                } else {
                    n.push(q);
                }
            }
            (m, n, array(&fields[2])?)
        };
    if signatures.len() != nonmandatory.len() {
        return Err(crypto_error());
    }
    let message = sign_data(
        &suites::proof_hash(&unsigned, &proof, loader, false).await?,
        bytes(&fields[1])?,
        &hash_lines(mandatory.iter()),
    );
    issuer.verify(&message, bytes(&fields[0])?)?;
    for (quad, signature) in nonmandatory.iter().zip(signatures) {
        ephemeral.verify(format!("{quad} .\n").as_bytes(), bytes(signature)?)?;
    }
    Ok(())
}

pub async fn derive(
    document: &Value,
    issuer: &PublicKey,
    reveal: &[String],
    loader: &impl Loader,
) -> Result<Value> {
    let (unsigned, proof) = suites::split(document)?;
    if suites::suite(&proof)? != suites::SELECTIVE {
        return Err(error(
            "NOT_SELECTIVE",
            "disclosure",
            "Ed25519 credentials cannot be derived; use issuer-controlled reissue-redacted",
        ));
    }
    verify(document, issuer, loader).await?;
    let (kind, fields) = decode(&proof)?;
    if kind != 0 {
        return Err(error(
            "BASE_PROOF_REQUIRED",
            "disclosure",
            "Derivation requires the original base credential",
        ));
    }
    for path in reveal {
        if path.is_empty()
            || path.starts_with("/proof")
            || path.starts_with("/@context")
            || unsigned.pointer(path).is_none()
        {
            return Err(error(
                "INVALID_REVEAL",
                "disclosure",
                "Reveal pointer is absent or targets protected metadata",
            ));
        }
    }
    let mandatory = strings(&fields[4])?;
    let combined: Vec<String> = mandatory.iter().chain(reveal).cloned().collect();
    let groups = group(
        &unsigned,
        bytes(&fields[2])?,
        &[
            ("mandatory", mandatory),
            ("selective", reveal.to_vec()),
            ("combined", combined.clone()),
        ],
        loader,
    )
    .await?;
    let m = &groups.groups["mandatory"];
    let selected = &groups.groups["selective"];
    let combined_group = &groups.groups["combined"];
    let mandatory_indexes = combined_group
        .matching
        .keys()
        .enumerate()
        .filter_map(|(relative, absolute)| {
            m.matching
                .contains_key(absolute)
                .then_some(Cbor::Integer(relative as i128))
        })
        .collect();
    let original_signatures = array(&fields[3])?;
    let signatures = m
        .rest
        .keys()
        .zip(original_signatures)
        .filter_map(|(i, s)| selected.matching.contains_key(i).then_some(s.clone()))
        .collect();
    let canonical_map = canonical_labels(&combined_group.deskolemized)?;
    let mut compressed = BTreeMap::new();
    for (original, canonical) in canonical_map {
        let mapped = groups.labels.get(&original).ok_or_else(crypto_error)?;
        let i: i128 = canonical
            .as_str()
            .strip_prefix("_:c14n")
            .ok_or_else(crypto_error)?
            .parse()
            .map_err(|_| crypto_error())?;
        let b = multibase::Base::Base64Url
            .decode(
                mapped
                    .as_str()
                    .strip_prefix("_:u")
                    .ok_or_else(crypto_error)?,
            )
            .map_err(|_| crypto_error())?;
        compressed.insert(Cbor::Integer(i), Cbor::Bytes(b));
    }
    let object = json_syntax::to_value(&unsigned)
        .map_err(|_| crypto_error())?
        .into_object()
        .ok_or_else(crypto_error)?;
    let selected = select_json_ld(&pointers(&combined)?, &object)
        .map_err(|_| crypto_error())?
        .ok_or_else(crypto_error)?;
    let mut result = serde_json::to_value(selected).map_err(|_| crypto_error())?;
    result["proof"] = proof;
    result["proof"]["proofValue"] = encode(
        1,
        vec![
            fields[0].clone(),
            fields[1].clone(),
            Cbor::Array(signatures),
            Cbor::Map(compressed),
            Cbor::Array(mandatory_indexes),
        ],
    )?
    .into();
    verify(&result, issuer, loader).await?;
    Ok(result)
}
