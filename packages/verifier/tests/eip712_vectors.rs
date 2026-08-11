use openant_commerce_verifier::{
    digest_structured, verify_eip712_wallet, PaymentAuthorizationMessage, SignatureEnvelope,
    VerificationErrorCode, WalletAuthorizationProofClaims, WalletVerificationContext,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Eip712Vector {
    payer_address: String,
    wallet_proof_claims: WalletAuthorizationProofClaims,
    typed_data: Value,
    envelope: SignatureEnvelope,
    high_s_signature: String,
    payment_authorization_digest: String,
    claims_digest: String,
    eip712_signing_hash: String,
}

fn vector() -> Eip712Vector {
    serde_json::from_str(include_str!("../test-vectors/eip712-v1.json"))
        .expect("shared EIP-712 vector is valid")
}

fn context(vector: &Eip712Vector) -> WalletVerificationContext<'_> {
    WalletVerificationContext {
        wallet_proof_claims: &vector.wallet_proof_claims,
        claimed_claims_digest: &vector.claims_digest,
        wire_version: "0.1",
    }
}

#[test]
fn verifies_standard_x402_exact_eip3009_and_derives_both_digests() {
    let vector = vector();
    let verified =
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &context(&vector)).unwrap();

    assert_eq!(verified.payer_address, vector.payer_address.to_lowercase());
    assert_eq!(
        verified.payment_authorization_digest,
        vector.payment_authorization_digest
    );
    assert_eq!(verified.claims_digest, vector.claims_digest);
    assert_eq!(verified.eip712_signing_hash, vector.eip712_signing_hash);
    assert_eq!(
        verified.message,
        PaymentAuthorizationMessage {
            from: vector.payer_address.to_lowercase(),
            to: "0x2222222222222222222222222222222222222222".into(),
            value: "1250000".into(),
            valid_after: "0".into(),
            valid_before: "4070908800".into(),
            nonce: format!("0x{}", "aa".repeat(32)),
        }
    );
}

#[test]
fn rejects_caller_reported_or_claimed_authorization_digests() {
    let vector = vector();
    let wrong_digest = format!("sha256:{}", "ee".repeat(32));

    let mut envelope = vector.envelope.clone();
    envelope.signed_object_digest = wrong_digest.clone();
    assert_eq!(
        verify_eip712_wallet(&envelope, &vector.typed_data, &context(&vector))
            .unwrap_err()
            .code(),
        VerificationErrorCode::AuthorizationDigestMismatch
    );

    let mut claims = vector.wallet_proof_claims.clone();
    claims.payment_authorization_digest = wrong_digest;
    let tampered_context = WalletVerificationContext {
        wallet_proof_claims: &claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &tampered_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::AuthorizationDigestMismatch
    );
}

#[test]
fn commercial_metadata_requires_a_new_receipt_claims_digest_but_not_a_new_eip3009_signature() {
    let vector = vector();
    let mut claims = vector.wallet_proof_claims.clone();
    claims.receipt_id = "receipt:wallet:2".into();
    let changed_context = WalletVerificationContext {
        wallet_proof_claims: &claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &changed_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::WalletClaimsDigestMismatch
    );
}

#[test]
fn fingerprint_is_the_eip3009_nonce_and_binds_commercial_context() {
    let vector = vector();
    let mut claims = vector.wallet_proof_claims.clone();
    claims.payment_intent_fingerprint_digest = format!("sha256:{}", "ee".repeat(32));
    let changed_context = WalletVerificationContext {
        wallet_proof_claims: &claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &changed_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::AuthorizationMessageMismatch
    );
}

#[test]
fn rejects_uint256_overflow_before_typed_data_verification() {
    let vector = vector();
    let mut claims = vector.wallet_proof_claims.clone();
    claims.amount_atomic =
        "115792089237316195423570985008687907853269984665640564039457584007913129639936".into();
    let changed_context = WalletVerificationContext {
        wallet_proof_claims: &claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &changed_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::Eip712Malformed
    );
}

#[test]
fn rejects_wallet_claim_addresses_outside_the_public_schema_lexical_set() {
    let vector = vector();
    let mut claims = vector.wallet_proof_claims.clone();
    claims.payer_address = claims.payer_address.trim_start_matches("0x").into();
    let changed_context = WalletVerificationContext {
        wallet_proof_claims: &claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &changed_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::Eip712Malformed
    );
}

#[test]
fn rejects_an_unregistered_wallet_wire_version_even_if_all_reported_digests_are_reframed() {
    let vector = vector();
    let mut claims = vector.wallet_proof_claims.clone();
    claims.payment_authorization_digest =
        digest_structured("PAYMENT_AUTHORIZATION", &vector.typed_data, "0.2").unwrap();
    let claimed_claims_digest = digest_structured(
        "RECEIPT_CLAIMS",
        &serde_json::to_value(&claims).unwrap(),
        "0.2",
    )
    .unwrap();
    let mut envelope = vector.envelope.clone();
    envelope.signed_object_digest = claims.payment_authorization_digest.clone();
    let unsupported_context = WalletVerificationContext {
        wallet_proof_claims: &claims,
        claimed_claims_digest: &claimed_claims_digest,
        wire_version: "0.2",
    };
    assert_eq!(
        verify_eip712_wallet(&envelope, &vector.typed_data, &unsupported_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::Eip712Malformed
    );
}

#[test]
fn rejects_every_nonstandard_domain_type_message_and_extra_surface() {
    let vector = vector();
    type Mutation = (&'static str, Box<dyn Fn(&mut Value)>);
    let mutations: Vec<Mutation> = vec![
        ("top-level", Box::new(|v| v["unsigned"] = Value::Bool(true))),
        (
            "domain extra",
            Box::new(|v| v["domain"]["salt"] = Value::String("0x00".into())),
        ),
        (
            "domain name",
            Box::new(|v| v["domain"]["name"] = Value::String("OpenAnt Commerce".into())),
        ),
        (
            "contract",
            Box::new(|v| {
                v["domain"]["verifyingContract"] =
                    Value::String("0x1111111111111111111111111111111111111111".into())
            }),
        ),
        (
            "types",
            Box::new(|v| v["types"]["Attacker"] = serde_json::json!([])),
        ),
        (
            "primary type",
            Box::new(|v| v["primaryType"] = Value::String("PaymentAuthorization".into())),
        ),
        (
            "message extra",
            Box::new(|v| {
                v["message"]["challengeDigest"] =
                    Value::String(format!("sha256:{}", "bb".repeat(32)))
            }),
        ),
        (
            "validAfter",
            Box::new(|v| v["message"]["validAfter"] = Value::String("1".into())),
        ),
        (
            "nonce",
            Box::new(|v| v["message"]["nonce"] = Value::String(format!("0x{}", "ee".repeat(32)))),
        ),
    ];
    for (name, mutate) in mutations {
        let mut altered = vector.typed_data.clone();
        mutate(&mut altered);
        assert!(
            verify_eip712_wallet(&vector.envelope, &altered, &context(&vector)).is_err(),
            "{name} mutation"
        );
    }
}

#[test]
fn live_clock_rejects_expired_wallet_proofs_and_fractional_receipt_times() {
    let vector = vector();
    let mut expired_claims = vector.wallet_proof_claims.clone();
    expired_claims.issued_at = "2019-01-01T00:00:00Z".into();
    expired_claims.expires_at = "2020-01-01T00:00:00Z".into();
    let expired_context = WalletVerificationContext {
        wallet_proof_claims: &expired_claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &expired_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::AuthorizationTimeInvalid
    );

    let mut claims = vector.wallet_proof_claims.clone();
    claims.expires_at = "2026-08-11T04:00:00.000Z".into();
    let fractional_claims = WalletVerificationContext {
        wallet_proof_claims: &claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &fractional_claims)
            .unwrap_err()
            .code(),
        VerificationErrorCode::Eip712Malformed
    );

    let mut zero_length_claims = vector.wallet_proof_claims.clone();
    zero_length_claims.issued_at = zero_length_claims.expires_at.clone();
    let zero_length_context = WalletVerificationContext {
        wallet_proof_claims: &zero_length_claims,
        ..context(&vector)
    };
    assert_eq!(
        verify_eip712_wallet(&vector.envelope, &vector.typed_data, &zero_length_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::AuthorizationTimeInvalid
    );
}

#[test]
fn rejects_high_s_zero_scalar_and_noncanonical_parity() {
    let vector = vector();
    let verification_context = context(&vector);
    let mut envelope = vector.envelope.clone();
    envelope.signature = vector.high_s_signature.clone();
    assert_eq!(
        verify_eip712_wallet(&envelope, &vector.typed_data, &verification_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::SignatureNonCanonical
    );

    envelope.signature = format!("0x{}1b", "00".repeat(64));
    assert_eq!(
        verify_eip712_wallet(&envelope, &vector.typed_data, &verification_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::SignatureEncodingInvalid
    );

    envelope.signature = vector.envelope.signature[..130].to_owned() + "00";
    assert_eq!(
        verify_eip712_wallet(&envelope, &vector.typed_data, &verification_context)
            .unwrap_err()
            .code(),
        VerificationErrorCode::SignatureEncodingInvalid
    );
}
