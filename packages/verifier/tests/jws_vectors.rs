use openant_commerce_verifier::{
    canonicalize_jcs, digest_structured, DigestBoundStatement, HistoricalJwk,
    HistoricalKeyRegistry, HistoricalKeyWindow, JwsAlgorithm, KeyRole, SignatureEnvelope,
    SignatureScheme, StatementLifecycleField, VerificationContext, VerificationErrorCode,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JwsVectors {
    audience: String,
    statement_profile: String,
    statement: Value,
    rotated_statement: Value,
    keys: Vec<HistoricalJwk>,
    es256: SignatureEnvelope,
    es256_high_s: String,
    es256_der: String,
    eddsa: SignatureEnvelope,
    rotated_eddsa: SignatureEnvelope,
}

#[test]
fn imports_standard_jwks_with_separate_trusted_historical_windows() {
    let vectors = vectors();
    let jwks = serde_json::json!({
        "keys": vectors.keys.iter().map(|key| {
            let mut jwk = key.jwk.clone();
            jwk["kid"] = Value::String(key.kid.clone());
            jwk["alg"] = Value::String(match key.algorithm {
                JwsAlgorithm::ES256 => "ES256",
                JwsAlgorithm::EdDSA => "EdDSA",
            }.into());
            jwk
        }).collect::<Vec<_>>()
    });
    let windows = vectors
        .keys
        .iter()
        .map(|key| HistoricalKeyWindow {
            kid: key.kid.clone(),
            role: key.role,
            algorithm: key.algorithm,
            not_before_unix_ms: key.not_before_unix_ms,
            not_after_unix_ms: key.not_after_unix_ms,
            revoked_at_unix_ms: key.revoked_at_unix_ms,
        })
        .collect();
    let registry =
        HistoricalKeyRegistry::from_jwks("issuer:openant:example", &jwks, windows).unwrap();

    registry
        .verify_detached_jws(&vectors.es256, &context(&vectors))
        .unwrap();

    let missing = HistoricalKeyRegistry::from_jwks(
        "issuer:openant:example",
        &serde_json::json!({"keys": []}),
        vec![HistoricalKeyWindow {
            kid: "missing".into(),
            role: KeyRole::Issuer,
            algorithm: JwsAlgorithm::EdDSA,
            not_before_unix_ms: 0,
            not_after_unix_ms: None,
            revoked_at_unix_ms: None,
        }],
    )
    .unwrap_err();
    assert_eq!(missing.code(), VerificationErrorCode::InvalidKeyRegistry);
}

fn vectors() -> JwsVectors {
    serde_json::from_str(include_str!("../test-vectors/jws-v1.json"))
        .expect("shared JWS vectors are valid")
}

fn context<'a>(vectors: &'a JwsVectors) -> VerificationContext<'a> {
    context_for(vectors, &vectors.statement)
}

fn context_for<'a>(vectors: &'a JwsVectors, statement: &'a Value) -> VerificationContext<'a> {
    VerificationContext {
        audience: &vectors.audience,
        required_role: KeyRole::Issuer,
        statement: DigestBoundStatement {
            profile: &vectors.statement_profile,
            preimage: statement,
            wire_version: "0.1",
            lifecycle_field: StatementLifecycleField::IssuedAt,
        },
    }
}

fn sign_eddsa_statement(
    vectors: &JwsVectors,
    key_id: &str,
    private_seed_base64url: &str,
    statement: &Value,
) -> SignatureEnvelope {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    let digest = digest_structured(&vectors.statement_profile, statement, "0.1").unwrap();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "aud": vectors.audience,
        "iss": "issuer:openant:example",
        "kid": key_id,
        "typ": "openant-commerce+jws"
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(canonicalize_jcs(&header).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(digest.as_bytes());
    let signing_input = format!("{encoded_header}.{payload}");
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(private_seed_base64url)
        .unwrap()
        .try_into()
        .unwrap();
    let signature = SigningKey::from_bytes(&seed).sign(signing_input.as_bytes());
    SignatureEnvelope {
        scheme: SignatureScheme::DetachedJwsEddsa,
        issuer: "issuer:openant:example".into(),
        key_id: key_id.into(),
        signed_object_digest: digest,
        signature: format!(
            "{encoded_header}..{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
    }
}

fn replace_signature(envelope: &SignatureEnvelope, signature: &str) -> SignatureEnvelope {
    let mut changed = envelope.clone();
    let header = envelope.signature.split('.').next().unwrap();
    changed.signature = format!("{header}..{signature}");
    changed
}

#[test]
fn verifies_cross_language_es256_and_eddsa_vectors() {
    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();

    registry
        .verify_detached_jws(&vectors.es256, &context(&vectors))
        .unwrap();
    registry
        .verify_detached_jws(&vectors.eddsa, &context(&vectors))
        .unwrap();
}

#[test]
fn rejects_high_s_and_der_encoded_es256_signatures() {
    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();

    let high_s = replace_signature(&vectors.es256, &vectors.es256_high_s);
    assert_eq!(
        registry
            .verify_detached_jws(&high_s, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::SignatureNonCanonical
    );

    let der = replace_signature(&vectors.es256, &vectors.es256_der);
    assert_eq!(
        registry
            .verify_detached_jws(&der, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::SignatureEncodingInvalid
    );
}

#[test]
fn rejects_non_detached_or_malformed_jws() {
    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();

    let mut embedded = vectors.es256.clone();
    embedded.signature = embedded.signature.replacen("..", ".payload.", 1);
    assert_eq!(
        registry
            .verify_detached_jws(&embedded, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::JwsMalformed
    );

    let mut extra = vectors.es256.clone();
    extra.signature.push_str(".extra");
    assert_eq!(
        registry
            .verify_detached_jws(&extra, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::JwsMalformed
    );
}

#[test]
fn handles_header_serialization_without_algorithm_confusion() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();
    let mut segments = vectors.es256.signature.split('.');
    let protected = segments.next().unwrap();
    segments.next();
    let signature_segment = segments.next().unwrap();
    // RFC 7515 signs the protected bytes but does not prescribe JSON member order.
    let noncanonical_header = r#"{"typ":"openant-commerce+jws", "kid":"ed-key-2026-08", "iss":"issuer:openant:example", "aud":"openant-commerce-verifier", "alg":"EdDSA"}"#;
    let encoded_header = URL_SAFE_NO_PAD.encode(noncanonical_header);
    let payload = URL_SAFE_NO_PAD.encode(vectors.eddsa.signed_object_digest.as_bytes());
    let signing_input = format!("{encoded_header}.{payload}");
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
        .unwrap()
        .try_into()
        .unwrap();
    let noncanonical_signature = SigningKey::from_bytes(&seed).sign(signing_input.as_bytes());
    let mut noncanonical = vectors.eddsa.clone();
    noncanonical.signature = format!(
        "{encoded_header}..{}",
        URL_SAFE_NO_PAD.encode(noncanonical_signature.to_bytes())
    );
    registry
        .verify_detached_jws(&noncanonical, &context(&vectors))
        .unwrap();

    let missing_typ_header = r#"{"alg":"EdDSA","aud":"openant-commerce-verifier","iss":"issuer:openant:example","kid":"ed-key-2026-08"}"#;
    let encoded_header = URL_SAFE_NO_PAD.encode(missing_typ_header);
    let signing_input = format!("{encoded_header}.{payload}");
    let signature = SigningKey::from_bytes(&seed).sign(signing_input.as_bytes());
    let mut missing_typ = vectors.eddsa.clone();
    missing_typ.signature = format!(
        "{encoded_header}..{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    assert_eq!(
        registry
            .verify_detached_jws(&missing_typ, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::JwsHeaderInvalid
    );

    let mut confused = vectors.es256.clone();
    confused.scheme = openant_commerce_verifier::SignatureScheme::DetachedJwsEddsa;
    assert_eq!(
        registry
            .verify_detached_jws(&confused, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::JwsHeaderInvalid
    );

    let mut corrupt = vectors.es256.clone();
    let mut signature_bytes = URL_SAFE_NO_PAD.decode(signature_segment).unwrap();
    signature_bytes[0] ^= 1;
    corrupt.signature = format!("{protected}..{}", URL_SAFE_NO_PAD.encode(signature_bytes));
    assert_eq!(
        registry
            .verify_detached_jws(&corrupt, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::SignatureInvalid
    );
}

#[test]
fn refuses_private_jwks_and_relabeling_one_key_as_custody() {
    let vectors = vectors();
    let mut private = vectors.keys[0].clone();
    private.jwk["d"] = Value::String("test-private-material".into());
    assert_eq!(
        HistoricalKeyRegistry::new(vec![private])
            .unwrap_err()
            .code(),
        VerificationErrorCode::InvalidKeyRegistry
    );

    let mut mismatched_kid = vectors.keys[0].clone();
    mismatched_kid.jwk["kid"] = Value::String("another-key".into());
    assert_eq!(
        HistoricalKeyRegistry::new(vec![mismatched_kid])
            .unwrap_err()
            .code(),
        VerificationErrorCode::InvalidKeyRegistry
    );

    let issuer = vectors.keys[1].clone();
    let mut custody = issuer.clone();
    custody.kid = "custody-alias".into();
    custody.role = KeyRole::Custody;
    assert_eq!(
        HistoricalKeyRegistry::new(vec![issuer, custody])
            .unwrap_err()
            .code(),
        VerificationErrorCode::InvalidKeyRegistry
    );

    let mut cross_issuer = vectors.keys[1].clone();
    cross_issuer.issuer = "issuer:another:example".into();
    cross_issuer.kid = "another-issuer-key".into();
    assert_eq!(
        HistoricalKeyRegistry::new(vec![vectors.keys[1].clone(), cross_issuer])
            .unwrap_err()
            .code(),
        VerificationErrorCode::InvalidKeyRegistry
    );

    let mut missing_use = vectors.keys[0].clone();
    missing_use.jwk.as_object_mut().unwrap().remove("use");
    assert_eq!(
        HistoricalKeyRegistry::new(vec![missing_use])
            .unwrap_err()
            .code(),
        VerificationErrorCode::InvalidKeyRegistry
    );

    let mut broad_key_ops = vectors.keys[0].clone();
    broad_key_ops.jwk["use"] = Value::String("sig".into());
    broad_key_ops.jwk["key_ops"] = serde_json::json!(["verify", "sign"]);
    assert_eq!(
        HistoricalKeyRegistry::new(vec![broad_key_ops])
            .unwrap_err()
            .code(),
        VerificationErrorCode::InvalidKeyRegistry
    );
}

#[test]
fn binds_audience_issuer_kid_and_key_role_without_fallback() {
    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();

    let wrong_audience = VerificationContext {
        audience: "other-service",
        ..context(&vectors)
    };
    assert_eq!(
        registry
            .verify_detached_jws(&vectors.es256, &wrong_audience)
            .unwrap_err()
            .code(),
        VerificationErrorCode::AudienceMismatch
    );

    let mut wrong_issuer = vectors.es256.clone();
    wrong_issuer.issuer = "issuer:attacker:example".into();
    assert_eq!(
        registry
            .verify_detached_jws(&wrong_issuer, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::IssuerMismatch
    );

    let mut unknown_kid = vectors.es256.clone();
    unknown_kid.key_id = "key:unknown".into();
    assert_eq!(
        registry
            .verify_detached_jws(&unknown_kid, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyIdMismatch
    );

    let custody = VerificationContext {
        required_role: KeyRole::Custody,
        ..context(&vectors)
    };
    assert_eq!(
        registry
            .verify_detached_jws(&vectors.es256, &custody)
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyRoleMismatch
    );
}

#[test]
fn applies_activation_expiry_and_revocation_only_at_live_observation_time() {
    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();

    // A signer-claimed historical issuedAt is not a trusted time anchor. First observation
    // after revocation fails closed even if the statement is backdated before the cutoff.
    let mut revoked_es256_keys = vectors.keys.clone();
    revoked_es256_keys[0].revoked_at_unix_ms = Some(4_000);
    let revoked_es256_registry = HistoricalKeyRegistry::new(revoked_es256_keys).unwrap();
    assert_eq!(
        revoked_es256_registry
            .verify_detached_jws(&vectors.es256, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyRevoked
    );
    let before_activation = serde_json::json!({
        "issuedAt": "1970-01-01T00:00:00Z", "kind": "test", "nonce": "early"
    });
    let early = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-08",
        "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        &before_activation,
    );
    let mut future_activation_keys = vectors.keys.clone();
    future_activation_keys[1].not_before_unix_ms = i64::MAX;
    let future_activation_registry = HistoricalKeyRegistry::new(future_activation_keys).unwrap();
    assert_eq!(
        future_activation_registry
            .verify_detached_jws(&early, &context_for(&vectors, &before_activation))
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyNotActive
    );

    let at_revocation = serde_json::json!({
        "issuedAt": "1970-01-01T00:00:04Z", "kind": "test", "nonce": "revoked"
    });
    let revoked = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-08",
        "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        &at_revocation,
    );
    let mut revoked_keys = vectors.keys.clone();
    revoked_keys[1].revoked_at_unix_ms = Some(4000);
    let revoked_registry = HistoricalKeyRegistry::new(revoked_keys).unwrap();
    assert_eq!(
        revoked_registry
            .verify_detached_jws(&revoked, &context_for(&vectors, &at_revocation))
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyRevoked
    );
    let runtime_backdated_statement = serde_json::json!({
        "issuedAt": "1970-01-01T00:00:02Z",
        "kind": "test",
        "nonce": "new-signature-created-after-revocation"
    });
    let runtime_backdated = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-08",
        "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        &runtime_backdated_statement,
    );
    assert_eq!(
        revoked_registry
            .verify_detached_jws(
                &runtime_backdated,
                &context_for(&vectors, &runtime_backdated_statement),
            )
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyRevoked
    );

    let at_expiry = serde_json::json!({
        "issuedAt": "1970-01-01T00:00:05Z", "kind": "test", "nonce": "expired"
    });
    let expired = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-08",
        "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        &at_expiry,
    );
    let mut expired_keys = vectors.keys.clone();
    expired_keys[1].not_after_unix_ms = Some(5000);
    let expired_registry = HistoricalKeyRegistry::new(expired_keys).unwrap();
    assert_eq!(
        expired_registry
            .verify_detached_jws(&expired, &context_for(&vectors, &at_expiry))
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyNotActive
    );

    let future_statement = serde_json::json!({
        "issuedAt": "9999-12-31T23:59:59Z", "kind": "test", "nonce": "future"
    });
    let future = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-08",
        "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        &future_statement,
    );
    assert_eq!(
        registry
            .verify_detached_jws(&future, &context_for(&vectors, &future_statement))
            .unwrap_err()
            .code(),
        VerificationErrorCode::StatementFromFuture
    );

    let mut tampered = vectors.statement.clone();
    tampered["nonce"] = Value::String("attacker".into());
    assert_eq!(
        registry
            .verify_detached_jws(&vectors.eddsa, &context_for(&vectors, &tampered))
            .unwrap_err()
            .code(),
        VerificationErrorCode::StatementDigestMismatch
    );

    let missing_issued_at = serde_json::json!({"kind": "test", "nonce": "missing-time"});
    let missing_time = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-08",
        "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        &missing_issued_at,
    );
    assert_eq!(
        registry
            .verify_detached_jws(&missing_time, &context_for(&vectors, &missing_issued_at),)
            .unwrap_err()
            .code(),
        VerificationErrorCode::StatementIssuedAtInvalid
    );
}

#[test]
fn selects_the_exact_rotated_kid_and_never_falls_back_to_an_old_key() {
    let vectors = vectors();
    let registry = HistoricalKeyRegistry::new(vectors.keys.clone()).unwrap();
    let after_rotation = VerificationContext {
        ..context_for(&vectors, &vectors.rotated_statement)
    };
    registry
        .verify_detached_jws(&vectors.rotated_eddsa, &after_rotation)
        .unwrap();

    let before_rotation_statement = serde_json::json!({
        "issuedAt": "1970-01-01T00:00:02Z", "kind": "test", "nonce": "early-rotation"
    });
    let before_rotation_envelope = sign_eddsa_statement(
        &vectors,
        "ed-key-2026-09",
        "Y-0vXE3HEaCmvS24vTc-qkot0o8bcfZw4zBHxOYM8xI",
        &before_rotation_statement,
    );
    let mut future_rotation_keys = vectors.keys.clone();
    future_rotation_keys[2].not_before_unix_ms = i64::MAX;
    let future_rotation_registry = HistoricalKeyRegistry::new(future_rotation_keys).unwrap();
    assert_eq!(
        future_rotation_registry
            .verify_detached_jws(
                &before_rotation_envelope,
                &context_for(&vectors, &before_rotation_statement),
            )
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyNotActive
    );

    let mut old_signature_under_new_kid = vectors.eddsa.clone();
    old_signature_under_new_kid.key_id = vectors.rotated_eddsa.key_id.clone();
    assert_eq!(
        registry
            .verify_detached_jws(&old_signature_under_new_kid, &context(&vectors))
            .unwrap_err()
            .code(),
        VerificationErrorCode::KeyIdMismatch
    );
}
