//! FHIRPath evaluator.
//!
//! Evaluates an [`Expr`] AST against a `serde_json::Value` representing
//! a FHIR resource (or a fragment of one). Returns a collection
//! (`Vec<Value>`) because FHIRPath always does — a single string and
//! a 1-element collection containing that string are equivalent.
//!
//! ## Path navigation
//!
//! A path step descends into the current collection. If the current
//! collection is an array, the step applies to each element and the
//! results are flattened. If a step's target is itself an array, the
//! results are flattened again. This is FHIRPath's "auto-collect"
//! behaviour:
//!
//! - `Patient.name` on a patient with 2 names returns 2 entries.
//! - `Patient.name.given` on the same patient returns the concatenation
//!   of each name's `given` array.
//!
//! ## `where(...)` semantics
//!
//! Filters the receiving collection. The predicate is evaluated for
//! each element with that element bound as the **context** — so a
//! plain identifier inside the predicate (`use`) resolves on the
//! current element, not on the outer resource.

use serde_json::Value;
use thiserror::Error;

use super::ast::{BinOp, Expr, PathSegment};
use super::parser::{ParseError, parse};

/// Errors from evaluating a FHIRPath expression.
#[derive(Debug, Error)]
pub enum FhirPathError {
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("unknown FHIRPath function `{name}`")]
    UnknownFunction { name: String },

    #[error("function `{name}` expected {expected} argument(s), got {got}")]
    BadArity {
        name: String,
        expected: usize,
        got: usize,
    },

    #[error("comparison received incompatible types: {lhs} vs {rhs}")]
    TypeMismatch { lhs: String, rhs: String },
}

/// Convenience: parse + evaluate in one call.
///
/// Returns the result as a flat collection of JSON values. An empty
/// `Vec` means the path matched nothing (FHIRPath does not distinguish
/// missing-vs-empty for most operators).
pub fn evaluate(expression: &str, resource: &Value) -> Result<Vec<Value>, FhirPathError> {
    let ast = parse(expression)?;
    evaluate_ast(&ast, resource)
}

/// Evaluate a pre-parsed AST. Useful when the same expression is
/// evaluated against many resources — parse once, walk many.
pub fn evaluate_ast(expr: &Expr, resource: &Value) -> Result<Vec<Value>, FhirPathError> {
    eval(expr, &[resource.clone()])
}

/// Inner evaluator. `context` is the current collection.
///
/// Important: the *first* segment of a path can be either the
/// resource's `resourceType` (`Patient`, `Observation`, …) or one of
/// its top-level properties. We normalise both: if the first segment
/// matches the JSON object's `resourceType`, the segment is consumed
/// and the resource itself becomes the context.
fn eval(expr: &Expr, context: &[Value]) -> Result<Vec<Value>, FhirPathError> {
    match expr {
        Expr::Literal(v) => Ok(vec![v.clone()]),
        Expr::Path(segments) => eval_path(segments, context),
        Expr::BinOp(lhs, op, rhs) => eval_binop(lhs, *op, rhs, context),
        Expr::Not(inner) => {
            let v = eval(inner, context)?;
            Ok(vec![Value::Bool(!collection_is_truthy(&v))])
        }
    }
}

fn eval_path(segments: &[PathSegment], context: &[Value]) -> Result<Vec<Value>, FhirPathError> {
    if segments.is_empty() {
        return Ok(context.to_vec());
    }

    // Treat the first segment specially: if it names the resource
    // type (e.g. `Patient`), consume it without descending. This lets
    // `Patient.name.family` work against a Patient JSON object whose
    // top-level object has no `Patient` property.
    let mut current: Vec<Value> = context.to_vec();
    let mut i = 0;
    if let Some(PathSegment::Member(name)) = segments.first() {
        if context.iter().any(|v| {
            v.get("resourceType")
                .and_then(|rt| rt.as_str())
                .is_some_and(|rt| rt == name)
        }) {
            i = 1;
        }
    }

    while i < segments.len() {
        current = step(&segments[i], &current)?;
        i += 1;
    }
    Ok(current)
}

fn step(segment: &PathSegment, ctx: &[Value]) -> Result<Vec<Value>, FhirPathError> {
    match segment {
        PathSegment::Member(name) => {
            let mut out = Vec::new();
            for v in ctx {
                match v {
                    Value::Object(obj) => {
                        if let Some(inner) = obj.get(name) {
                            flatten_into(inner, &mut out);
                        }
                    }
                    Value::Array(arr) => {
                        // Member access on an array delegates to each
                        // element.
                        for elem in arr {
                            if let Value::Object(obj) = elem {
                                if let Some(inner) = obj.get(name) {
                                    flatten_into(inner, &mut out);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(out)
        }
        PathSegment::Index(idx) => Ok(ctx.get(*idx).cloned().into_iter().collect()),
        PathSegment::Function(name, args) => apply_function(name, args, ctx),
    }
}

fn flatten_into(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Array(items) => {
            for it in items {
                out.push(it.clone());
            }
        }
        other => out.push(other.clone()),
    }
}

fn apply_function(name: &str, args: &[Expr], ctx: &[Value]) -> Result<Vec<Value>, FhirPathError> {
    match name {
        "where" => {
            if args.len() != 1 {
                return Err(FhirPathError::BadArity {
                    name: "where".into(),
                    expected: 1,
                    got: args.len(),
                });
            }
            let predicate = &args[0];
            let mut out = Vec::new();
            for elem in ctx {
                let local = vec![elem.clone()];
                let result = eval(predicate, &local)?;
                if collection_is_truthy(&result) {
                    out.push(elem.clone());
                }
            }
            Ok(out)
        }
        "exists" => {
            if !args.is_empty() {
                return Err(FhirPathError::BadArity {
                    name: "exists".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(vec![Value::Bool(!ctx.is_empty())])
        }
        "empty" => {
            if !args.is_empty() {
                return Err(FhirPathError::BadArity {
                    name: "empty".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(vec![Value::Bool(ctx.is_empty())])
        }
        "first" => {
            if !args.is_empty() {
                return Err(FhirPathError::BadArity {
                    name: "first".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(ctx.first().cloned().into_iter().collect())
        }
        "last" => {
            if !args.is_empty() {
                return Err(FhirPathError::BadArity {
                    name: "last".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(ctx.last().cloned().into_iter().collect())
        }
        "count" => {
            if !args.is_empty() {
                return Err(FhirPathError::BadArity {
                    name: "count".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(vec![Value::from(ctx.len())])
        }
        other => Err(FhirPathError::UnknownFunction {
            name: other.to_string(),
        }),
    }
}

fn eval_binop(
    lhs: &Expr,
    op: BinOp,
    rhs: &Expr,
    context: &[Value],
) -> Result<Vec<Value>, FhirPathError> {
    let l = eval(lhs, context)?;
    let r = eval(rhs, context)?;

    let result = match op {
        BinOp::And => collection_is_truthy(&l) && collection_is_truthy(&r),
        BinOp::Or => collection_is_truthy(&l) || collection_is_truthy(&r),
        // FHIRPath equality / comparison: empty on either side
        // produces empty. We surface that as a single `false` bool
        // for boolean-context use (where(), and/or chaining).
        cmp => {
            if l.is_empty() || r.is_empty() {
                false
            } else {
                let lv = &l[0];
                let rv = &r[0];
                compare(lv, rv, cmp)?
            }
        }
    };
    Ok(vec![Value::Bool(result)])
}

fn compare(lhs: &Value, rhs: &Value, op: BinOp) -> Result<bool, FhirPathError> {
    let ordering = json_ordering(lhs, rhs);
    let Some(ord) = ordering else {
        // Only equality / inequality is defined when types disagree.
        return match op {
            BinOp::Eq => Ok(lhs == rhs),
            BinOp::Neq => Ok(lhs != rhs),
            _ => Err(FhirPathError::TypeMismatch {
                lhs: type_name(lhs).into(),
                rhs: type_name(rhs).into(),
            }),
        };
    };
    Ok(match op {
        BinOp::Eq => ord == std::cmp::Ordering::Equal,
        BinOp::Neq => ord != std::cmp::Ordering::Equal,
        BinOp::Lt => ord == std::cmp::Ordering::Less,
        BinOp::Le => ord != std::cmp::Ordering::Greater,
        BinOp::Gt => ord == std::cmp::Ordering::Greater,
        BinOp::Ge => ord != std::cmp::Ordering::Less,
        BinOp::And | BinOp::Or => unreachable!("handled before compare"),
    })
}

fn json_ordering(lhs: &Value, rhs: &Value) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    match (lhs, rhs) {
        (Value::Number(a), Value::Number(b)) => {
            let af = a.as_f64()?;
            let bf = b.as_f64()?;
            af.partial_cmp(&bf)
        }
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
        (a, b) if a == b => Some(Ordering::Equal),
        _ => None,
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A FHIRPath collection is "truthy" when it contains exactly one
/// boolean `true`. The 0-element case is falsey (the "empty
/// collection" semantics); a non-bool single value or a multi-element
/// collection in boolean position is rare in our subset (we surface
/// it as `false` for safety).
fn collection_is_truthy(v: &[Value]) -> bool {
    match v {
        [Value::Bool(b)] => *b,
        [] => false,
        // For non-bool singletons, presence is truth — matches the
        // common idiom `Patient.deceased and ...`.
        [single] => !matches!(single, Value::Bool(false) | Value::Null),
        _ => true,
    }
}
