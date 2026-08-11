use openant_commerce_verifier::{
    is_non_zero_evm_address, is_positive_uint256_decimal, is_protocol_identifier,
    is_rfc3339_utc_whole_seconds,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LexicalVector {
    valid_identifiers: Vec<String>,
    invalid_identifiers: Vec<String>,
    valid_rfc3339_utc_whole_seconds: Vec<String>,
    invalid_rfc3339_utc_whole_seconds: Vec<String>,
    valid_non_zero_evm_addresses: Vec<String>,
    invalid_non_zero_evm_addresses: Vec<String>,
    valid_positive_uint256_decimals: Vec<String>,
    invalid_positive_uint256_decimals: Vec<String>,
}

#[test]
fn matches_the_shared_non_zero_evm_address_lexical_set() {
    let vector = vector();
    for value in vector.valid_non_zero_evm_addresses {
        assert!(is_non_zero_evm_address(&value), "{value}");
    }
    for value in vector.invalid_non_zero_evm_addresses {
        assert!(!is_non_zero_evm_address(&value), "{value}");
    }
}

#[test]
fn matches_the_shared_positive_uint256_decimal_lexical_set() {
    let vector = vector();
    for value in vector.valid_positive_uint256_decimals {
        assert!(is_positive_uint256_decimal(&value), "{value}");
    }
    for value in vector.invalid_positive_uint256_decimals {
        assert!(!is_positive_uint256_decimal(&value), "{value}");
    }
}

fn vector() -> LexicalVector {
    serde_json::from_str(include_str!("../test-vectors/lexical-v1.json")).unwrap()
}

#[test]
fn matches_the_shared_protocol_identifier_lexical_set() {
    let vector = vector();
    for value in vector.valid_identifiers {
        assert!(is_protocol_identifier(&value), "{value}");
    }
    for value in vector.invalid_identifiers {
        assert!(!is_protocol_identifier(&value), "{value}");
    }
}

#[test]
fn matches_the_shared_rfc3339_utc_whole_second_lexical_set() {
    let vector = vector();
    for value in vector.valid_rfc3339_utc_whole_seconds {
        assert!(is_rfc3339_utc_whole_seconds(&value), "{value}");
    }
    for value in vector.invalid_rfc3339_utc_whole_seconds {
        assert!(!is_rfc3339_utc_whole_seconds(&value), "{value}");
    }
}
