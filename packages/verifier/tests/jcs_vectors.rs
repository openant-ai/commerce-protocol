use openant_commerce_verifier::{canonicalize_jcs, digest_structured};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JcsVector {
    wire_version: String,
    profile: String,
    value: Value,
    canonical: String,
    digest: String,
    unicode_sorting_value: Value,
    unicode_sorting_canonical: String,
    rfc8785_appendix_b: Vec<NumberVector>,
    invalid_json_texts: Vec<InvalidJsonVector>,
    rfc8785_invalid_numbers: Vec<InvalidNumberVector>,
}

#[derive(Deserialize)]
struct NumberVector {
    ieee754: String,
    canonical: String,
}

#[derive(Deserialize)]
struct InvalidJsonVector {
    name: String,
    json: String,
}

#[derive(Deserialize)]
struct InvalidNumberVector {
    ieee754: String,
    name: String,
}

#[test]
fn rust_matches_the_shared_rfc_8785_vector() {
    let fixture: JcsVector = serde_json::from_str(include_str!("../test-vectors/jcs-v1.json"))
        .expect("shared JCS fixture is valid JSON");

    assert_eq!(
        canonicalize_jcs(&fixture.value).expect("JCS canonicalization succeeds"),
        fixture.canonical.as_bytes()
    );
    assert_eq!(
        digest_structured(&fixture.profile, &fixture.value, &fixture.wire_version)
            .expect("structured digest succeeds"),
        fixture.digest
    );
    assert_eq!(
        canonicalize_jcs(&fixture.unicode_sorting_value).expect("UTF-16 property sorting succeeds"),
        fixture.unicode_sorting_canonical.as_bytes()
    );
    for sample in fixture.rfc8785_appendix_b {
        let bits = u64::from_str_radix(&sample.ieee754, 16).unwrap();
        let value = Value::from(f64::from_bits(bits));
        assert_eq!(
            canonicalize_jcs(&value).expect("finite Appendix B number canonicalizes"),
            sample.canonical.as_bytes(),
            "IEEE-754 {}",
            sample.ieee754
        );
    }
    for sample in fixture.invalid_json_texts {
        assert!(
            serde_json::from_str::<Value>(&sample.json).is_err(),
            "{} must be rejected before canonicalization",
            sample.name
        );
    }
    for sample in fixture.rfc8785_invalid_numbers {
        let bits = u64::from_str_radix(&sample.ieee754, 16).unwrap();
        let number = f64::from_bits(bits);
        assert!(
            serde_json::Number::from_f64(number).is_none(),
            "{} must be rejected at the I-JSON value boundary",
            sample.name
        );
    }
}
