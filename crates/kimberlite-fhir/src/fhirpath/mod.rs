//! # FHIRPath subset evaluator
//!
//! A minimal FHIRPath evaluator covering the expressions a SMART on
//! FHIR client typically issues against an EHR-adjacent server:
//!
//! - **Path navigation**: `Patient.name.family`, `Patient.name.given`
//! - **Indexing**: `Patient.name[0].family`
//! - **`where()` filter**: `Patient.name.where(use = 'official').family`
//! - **Collection predicates**: `exists()`, `empty()`,
//!   `first()`, `last()`, `count()`
//! - **Comparisons**: `=`, `!=`, `<`, `<=`, `>`, `>=`
//! - **Logical**: `and`, `or`, `not(...)`
//! - **Literals**: single-quoted strings (FHIRPath convention),
//!   numbers, booleans
//!
//! ## Semantics
//!
//! FHIRPath evaluates expressions against a **collection** (even a
//! single value is a 1-element collection). Path navigation
//! auto-flattens — `Patient.name.given` on a patient with two `name`
//! entries each holding three `given` strings returns a 6-element
//! collection. `where(...)` filters its receiving collection by
//! evaluating the predicate against each element with `$this`
//! implicitly bound.
//!
//! ## What this is not
//!
//! Not a full FHIRPath implementation. No `as`/`is`/`ofType`,
//! `resolve()`, date arithmetic, quantity arithmetic, `iif`,
//! `select`, `repeat`, or context variables (`$this`, `$index`,
//! `$total`). These layer in as healthcare workloads demand them —
//! see the roadmap.
//!
//! ## Example
//!
//! ```
//! use serde_json::json;
//! use kimberlite_fhir::fhirpath::evaluate;
//!
//! let patient = json!({
//!     "resourceType": "Patient",
//!     "name": [
//!         { "use": "official", "family": "Smith", "given": ["Alice"] },
//!         { "use": "nickname", "family": "Smith", "given": ["Ali"] }
//!     ]
//! });
//!
//! let result = evaluate("Patient.name.where(use = 'official').given", &patient).unwrap();
//! assert_eq!(result, vec![serde_json::json!("Alice")]);
//! ```

mod ast;
mod eval;
mod lexer;
mod parser;

pub use ast::{BinOp, Expr, PathSegment};
pub use eval::{evaluate, evaluate_ast, FhirPathError};
pub use parser::parse;

#[cfg(test)]
mod tests;
