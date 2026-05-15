//! Canonical FHIR JSON emission.
//!
//! FHIR doesn't ship a canonicalisation spec, but for the Kimberlite
//! audit log to hash-chain resource bytes deterministically we need
//! one. The rules here are:
//!
//! 1. **Object key order**: sorted lexicographically by key (RFC 8259
//!    permits any order; we pick the most predictable).
//! 2. **No insignificant whitespace**: compact form (no spaces).
//! 3. **UTF-8**: standard JSON encoding.
//! 4. **Numbers**: serde-json's default `f64` formatting (round-trip
//!    safe for FHIR `decimal`/`integer`).
//!
//! Inputs are `serde_json::Value` — typed resources serialise to
//! `Value` first, then to canonical bytes. This routes around the fact
//! that derived `Serialize` impls don't respect key ordering on their
//! own.

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("JSON serialisation failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Emit a value as canonical FHIR JSON bytes.
///
/// Keys at every nesting level are sorted; arrays preserve their
/// original order (semantic ordering is meaningful in FHIR — e.g. the
/// first `HumanName.given` is the primary given name).
pub fn to_canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf)?;
    Ok(buf)
}

/// Convenience: serialise any `Serialize` value to canonical JSON.
pub fn to_canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v: Value = serde_json::to_value(value)?;
    to_canonical_json(&v)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
        }
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            let encoded = serde_json::to_string(s)?;
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            // Sort keys lexicographically for determinism.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let key_str = serde_json::to_string(key)?;
                out.extend_from_slice(key_str.as_bytes());
                out.push(b':');
                if let Some(v) = map.get(*key) {
                    write_canonical(v, out)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_lexicographically() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        let bytes = to_canonical_json(&v).unwrap();
        assert_eq!(bytes, br#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn preserves_array_order() {
        let v = json!(["second", "first", "third"]);
        let bytes = to_canonical_json(&v).unwrap();
        assert_eq!(bytes, br#"["second","first","third"]"#);
    }

    #[test]
    fn nested_objects_canonicalise_recursively() {
        let v = json!({ "outer": { "z": 1, "a": 2 }, "alpha": [{"b": 1, "a": 2}] });
        let bytes = to_canonical_json(&v).unwrap();
        assert_eq!(
            bytes,
            br#"{"alpha":[{"a":2,"b":1}],"outer":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn determinism_across_unsorted_inputs() {
        let a = json!({ "b": 1, "a": 2 });
        let b = json!({ "a": 2, "b": 1 });
        assert_eq!(to_canonical_json(&a).unwrap(), to_canonical_json(&b).unwrap());
    }

    #[test]
    fn escapes_special_characters() {
        let v = json!({ "name": "O'Reilly\n\"quoted\"" });
        let bytes = to_canonical_json(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Embedded quotes must be escaped, newline must become \n.
        assert!(s.contains("\\\""));
        assert!(s.contains("\\n"));
    }
}
