use openant_commerce_verifier::{
    DigestBoundStatement, HistoricalJwk, HistoricalKeyRegistry, KeyRole, SignatureEnvelope,
    StatementLifecycleField, VerificationContext, VerificationErrorCode,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedChallengeVector {
    audience: String,
    keys: Vec<HistoricalJwk>,
    listing_mandate: Value,
    payment_required_outcome: Value,
    standard_x402_without_extension: Value,
}

fn vector() -> SignedChallengeVector {
    serde_json::from_str(include_str!(
        "../../../vectors/openant-x402-challenge-v1.json"
    ))
    .expect("public signed Challenge vector must parse")
}

fn envelope(value: &Value) -> SignatureEnvelope {
    serde_json::from_value(value["signature"].clone()).expect("signature envelope must parse")
}

fn preimage(value: &Value) -> Value {
    let mut value = value.clone();
    value
        .as_object_mut()
        .expect("signed statement must be an object")
        .remove("signature")
        .expect("signed statement must have an envelope");
    value
}

fn context<'a>(
    audience: &'a str,
    profile: &'a str,
    preimage: &'a Value,
    lifecycle_field: StatementLifecycleField,
) -> VerificationContext<'a> {
    VerificationContext {
        audience,
        required_role: KeyRole::Issuer,
        statement: DigestBoundStatement {
            profile,
            preimage,
            wire_version: "0.1",
            lifecycle_field,
        },
    }
}

fn extension(value: &SignedChallengeVector) -> &Value {
    &value.payment_required_outcome["paymentRequired"]["extensions"]["openant"]
}

#[test]
fn verifies_real_listing_and_openant_extension_with_explicit_lifecycle_fields() {
    let vector = vector();
    let registry =
        HistoricalKeyRegistry::new(vector.keys.clone()).expect("public keys must be trusted");
    let listing_preimage = preimage(&vector.listing_mandate);
    let extension_preimage = preimage(extension(&vector));

    let listing_verified = registry
        .verify_detached_jws(
            &envelope(&vector.listing_mandate),
            &context(
                &vector.audience,
                "LISTING_MANDATE",
                &listing_preimage,
                StatementLifecycleField::ValidFrom,
            ),
        )
        .expect("seller Listing signature must verify");
    assert_eq!(listing_verified.issuer, "seller_acme");

    let challenge_verified = registry
        .verify_detached_jws(
            &envelope(extension(&vector)),
            &context(
                &vector.audience,
                "OPENANT_X402_EXTENSION",
                &extension_preimage,
                StatementLifecycleField::IssuedAt,
            ),
        )
        .expect("authorized gateway Challenge signature must verify");
    assert_eq!(challenge_verified.issuer, "openant_gateway");

    // Selecting ValidFrom for signature verification does not silently validate the
    // mandate's upper bound; the adapter must make this explicit policy check.
    assert!(
        vector.listing_mandate["validFrom"].as_str().unwrap()
            <= extension_preimage["issuedAt"].as_str().unwrap()
    );
    assert!(
        extension_preimage["issuedAt"].as_str().unwrap()
            <= extension_preimage["expiresAt"].as_str().unwrap()
    );
    assert!(
        extension_preimage["expiresAt"].as_str().unwrap()
            <= vector.listing_mandate["validUntil"].as_str().unwrap(),
        "Challenge expiry must not exceed Listing validity"
    );
}

#[test]
fn rejects_every_signed_challenge_claim_tamper() {
    let vector = vector();
    let registry = HistoricalKeyRegistry::new(vector.keys.clone()).unwrap();
    let original_extension = extension(&vector);
    let signed_envelope = envelope(original_extension);
    let attacks = [
        ("amountAtomic", Value::String("100001".into())),
        (
            "payoutAddress",
            Value::String("0x2222222222222222222222222222222222222222".into()),
        ),
        (
            "skuVersionDigest",
            Value::String(format!("sha256:{}", "45".repeat(32))),
        ),
        (
            "requestDigest",
            Value::String(format!("sha256:{}", "67".repeat(32))),
        ),
        (
            "nonce",
            Value::String("challenge_nonce_2026_08_13_attacker".into()),
        ),
        ("expiresAt", Value::String("2098-12-30T23:59:59Z".into())),
        (
            "listingMandateDigest",
            Value::String(format!("sha256:{}", "99".repeat(32))),
        ),
    ];

    for (field, changed) in attacks {
        let mut attacked = preimage(original_extension);
        attacked[field] = changed;
        let error = registry
            .verify_detached_jws(
                &signed_envelope,
                &context(
                    &vector.audience,
                    "OPENANT_X402_EXTENSION",
                    &attacked,
                    StatementLifecycleField::IssuedAt,
                ),
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            VerificationErrorCode::StatementDigestMismatch,
            "{field} must be signature-bound"
        );
    }
}

#[test]
fn rejects_envelope_issuer_and_kid_tamper_without_key_fallback() {
    let vector = vector();
    let registry = HistoricalKeyRegistry::new(vector.keys.clone()).unwrap();
    let extension_preimage = preimage(extension(&vector));
    let verify = |changed: &SignatureEnvelope| {
        registry
            .verify_detached_jws(
                changed,
                &context(
                    &vector.audience,
                    "OPENANT_X402_EXTENSION",
                    &extension_preimage,
                    StatementLifecycleField::IssuedAt,
                ),
            )
            .unwrap_err()
            .code()
    };

    let mut wrong_issuer = envelope(extension(&vector));
    wrong_issuer.issuer = "attacker_gateway".into();
    assert_eq!(verify(&wrong_issuer), VerificationErrorCode::IssuerMismatch);

    let mut wrong_kid = envelope(extension(&vector));
    wrong_kid.key_id = "attacker_key".into();
    assert_eq!(verify(&wrong_kid), VerificationErrorCode::KeyIdMismatch);
}

#[test]
fn listing_signature_binds_sku_seller_authorized_issuer_and_window() {
    let vector = vector();
    let registry = HistoricalKeyRegistry::new(vector.keys.clone()).unwrap();
    let signed_envelope = envelope(&vector.listing_mandate);
    for field in [
        "serviceSkuId",
        "skuVersionDigest",
        "sellerIdentityRef",
        "authorizedChallengeIssuers",
        "validFrom",
        "validUntil",
    ] {
        let mut attacked = preimage(&vector.listing_mandate);
        attacked[field] = match field {
            "authorizedChallengeIssuers" => serde_json::json!([{
                "issuer": "attacker_gateway", "keyId": "attacker_key"
            }]),
            "validFrom" => Value::String("2025-01-01T23:59:59Z".into()),
            "validUntil" => Value::String("2098-12-31T23:59:59Z".into()),
            "skuVersionDigest" => Value::String(format!("sha256:{}", "45".repeat(32))),
            _ => Value::String(format!("attacked_{field}")),
        };
        assert_eq!(
            registry
                .verify_detached_jws(
                    &signed_envelope,
                    &context(
                        &vector.audience,
                        "LISTING_MANDATE",
                        &attacked,
                        StatementLifecycleField::ValidFrom,
                    ),
                )
                .unwrap_err()
                .code(),
            VerificationErrorCode::StatementDigestMismatch,
            "{field} must be Listing-signature-bound"
        );
    }
}

#[test]
fn standard_x402_without_extension_has_no_mandate_upgrade_evidence() {
    let vector = vector();
    assert!(vector
        .standard_x402_without_extension
        .get("extensions")
        .is_none());
    assert!(!vector
        .standard_x402_without_extension
        .to_string()
        .contains("MANDATE_PROTECTED"));
}
