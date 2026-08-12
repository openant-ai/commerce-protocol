use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openant_commerce_verifier::{digest_structured, SignatureEnvelope};
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustAnchor {
    issuer: String,
    kid: String,
    jwk: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Corpus {
    trust_anchor: TrustAnchor,
    snapshot: Value,
    canonical_snapshot: String,
    etag: String,
}

#[test]
fn rust_replays_the_literal_snapshot_digest_etag_and_ed25519_signature() {
    let bytes = include_bytes!("../../../vectors/openant-trust-snapshot-v1.json");
    assert_eq!(
        hex::encode(sha2::Sha256::digest(bytes)),
        "93215bccc6dcd11e9bb00e6f9334cfbde542faae05bfebd020b69c91b6c654f4"
    );
    let corpus: Corpus = serde_json::from_slice(bytes).expect("trust snapshot corpus must parse");
    assert_eq!(
        serde_json_canonicalizer::to_string(&corpus.snapshot).unwrap(),
        corpus.canonical_snapshot
    );

    let mut preimage = corpus.snapshot.clone();
    let envelope: SignatureEnvelope = serde_json::from_value(
        preimage
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap(),
    )
    .unwrap();
    let digest = digest_structured("OPENANT_TRUST_SNAPSHOT", &preimage, "0.1").unwrap();
    assert_eq!(
        digest,
        "sha256:0074ec6d799ec83846f644c4eefd337ee6639c4b7f021ec91b235792d7b231fd"
    );
    assert_eq!(digest, envelope.signed_object_digest);
    assert_eq!(corpus.trust_anchor.issuer, envelope.issuer);
    assert_eq!(corpus.trust_anchor.kid, envelope.key_id);

    let segments: Vec<_> = envelope.signature.split('.').collect();
    assert_eq!(segments.len(), 3);
    assert!(segments[1].is_empty());
    let x = URL_SAFE_NO_PAD
        .decode(corpus.trust_anchor.jwk["x"].as_str().unwrap())
        .unwrap();
    let key = VerifyingKey::from_bytes(x.as_slice().try_into().unwrap()).unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(segments[2]).unwrap()).unwrap();
    let payload = URL_SAFE_NO_PAD.encode(digest.as_bytes());
    key.verify(
        format!("{}.{}", segments[0], payload).as_bytes(),
        &signature,
    )
    .expect("independent Rust verifier must accept the snapshot signature");

    let etag = format!(
        "\"sha256:{}\"",
        hex::encode(sha2::Sha256::digest(corpus.canonical_snapshot.as_bytes()))
    );
    assert_eq!(etag, corpus.etag);
    assert_eq!(
        etag,
        "\"sha256:c2bc504de781106fcbb9edc1f3e13a9d74bce532eb20adb698fbcbd1b754fe04\""
    );
}

#[test]
fn corpus_exposes_only_verify_only_metadata_and_no_commerce_authority() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../vectors/openant-trust-snapshot-v1.json"
    ))
    .unwrap();
    let serialized = corpus.to_string();
    for forbidden in [
        "tenantCredential",
        "membership",
        "Bearer ",
        "requestBody",
        "responseBody",
        "MANDATE_PROTECTED",
        "\"d\"",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "forbidden value: {forbidden}"
        );
    }
    assert_eq!(
        corpus["snapshot"]["capabilities"]["mintsCommerceAuthority"],
        false
    );
}
