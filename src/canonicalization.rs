//! Explicit separation of RDFC-1.0 and the legacy URDNA2015 algorithm.
use crate::errors::{Result, error};
use rdf_types::{BlankIdBuf, LexicalQuad};
use sophia_api::parser::QuadParser;
use sophia_api::source::QuadSource;
use sophia_c14n::rdfc10;
use sophia_inmem::dataset::LightDataset;
use ssi_json_ld::{CompactJsonLd, Expandable, Loader};
use ssi_rdf::{AnyLdEnvironment, IntoNQuads, LdEnvironment};
use std::collections::HashMap;

pub fn rdfc_nquads(input: &str) -> Result<(String, HashMap<BlankIdBuf, BlankIdBuf>)> {
    let fail = || {
        error(
            "CANONICALIZATION_FAILED",
            "canonicalization",
            "Invalid or overly complex RDF dataset",
        )
    };
    if input.len() > 8 * 1024 * 1024 {
        return Err(fail());
    }
    let dataset: LightDataset = sophia_turtle::parser::nq::NQuadsParser::new()
        .with_preserve_bn_labels(true)
        .parse_str(input)
        .collect_quads()
        .map_err(|_| fail())?;
    let (_, labels) = rdfc10::relabel_with::<sophia_c14n::hash::Sha256, _>(&dataset, 1.0, 6)
        .map_err(|_| fail())?;
    let mut output = Vec::new();
    rdfc10::normalize_with::<sophia_c14n::hash::Sha256, _, _>(&dataset, &mut output, 1.0, 6)
        .map_err(|_| fail())?;
    let labels = labels
        .into_iter()
        .map(|(a, b)| {
            Ok((
                BlankIdBuf::new(format!("_:{a}")).map_err(|_| fail())?,
                BlankIdBuf::new(format!("_:{}", b.as_str())).map_err(|_| fail())?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok((String::from_utf8(output).map_err(|_| fail())?, labels))
}

pub fn canonical_labels(quads: &[LexicalQuad]) -> Result<HashMap<BlankIdBuf, BlankIdBuf>> {
    Ok(rdfc_nquads(&quads.into_nquads())?.1)
}

pub async fn quads(document: &serde_json::Value, loader: &impl Loader) -> Result<Vec<LexicalQuad>> {
    let fail = || {
        error(
            "JSONLD_INVALID",
            "jsonld",
            "JSON-LD expansion or RDF conversion failed",
        )
    };
    let doc = CompactJsonLd(json_syntax::to_value(document).map_err(|_| fail())?);
    let mut ld = LdEnvironment::default();
    let mut expanded = doc.expand_with(&mut ld, loader).await.map_err(|_| fail())?;
    expanded.canonicalize();
    let result = ld.quads_of(&expanded).map_err(|_| fail())?;
    if result.len() > 50_000 {
        return Err(fail());
    }
    Ok(result)
}

pub async fn canonicalize(
    document: &serde_json::Value,
    loader: &impl Loader,
    legacy: bool,
) -> Result<String> {
    let quads = quads(document, loader).await?;
    // Apply bounded RDFC before the legacy algorithm as a complexity preflight.
    let modern = rdfc_nquads(&quads.as_slice().into_nquads())?.0;
    if legacy {
        Ok(
            ssi_rdf::urdna2015::normalize(quads.iter().map(LexicalQuad::as_lexical_quad_ref))
                .into_nquads(),
        )
    } else {
        Ok(modern)
    }
}
