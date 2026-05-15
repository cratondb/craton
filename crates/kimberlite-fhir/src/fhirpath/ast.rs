//! FHIRPath expression AST.

use serde_json::Value;

/// A FHIRPath expression node.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// `'a string'`, `42`, `3.14`, `true`. Stored as a JSON value
    /// so the evaluator can compare directly without coercion plumbing.
    Literal(Value),

    /// A dotted path with optional indices and function calls along
    /// the way: `Patient.name[0].where(use='official').family`.
    Path(Vec<PathSegment>),

    /// `lhs <op> rhs`.
    BinOp(Box<Expr>, BinOp, Box<Expr>),

    /// `not(expr)`.
    Not(Box<Expr>),
}

/// One segment of a path. `Patient.name[0].where(use='official')`
/// parses as `[Member("Patient"), Member("name"), Index(0),
/// Function("where", [...])]`.
#[derive(Debug, Clone, PartialEq)]
pub enum PathSegment {
    /// A property name — `name`, `family`, `given`.
    Member(String),
    /// `[N]` after a path step — `name[0]`.
    Index(usize),
    /// A function call — `where(expr)`, `exists()`, `count()`.
    Function(String, Vec<Expr>),
}

/// Binary operators supported by the subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}
