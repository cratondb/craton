//! Recursive-descent parser for the FHIRPath subset.
//!
//! Grammar (informal):
//!
//! ```text
//! expr        := or_expr
//! or_expr     := and_expr ( 'or' and_expr )*
//! and_expr    := comparison ( 'and' comparison )*
//! comparison  := unary ( ( '=' | '!=' | '<' | '<=' | '>' | '>=' ) unary )?
//! unary       := 'not' '(' expr ')' | primary
//! primary     := literal | path | '(' expr ')'
//! literal     := number | string | bool
//! path        := identifier path_step*
//! path_step   := '.' identifier ( '(' args? ')' )?
//!              | '[' number ']'
//! args        := expr ( ',' expr )*
//! ```

use serde_json::Value;
use thiserror::Error;

use super::ast::{BinOp, Expr, PathSegment};
use super::lexer::{LexError, Token, lex};

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("lex error: {0}")]
    Lex(#[from] LexError),

    #[error("unexpected end of input")]
    UnexpectedEnd,

    #[error("expected `{expected}`, got `{got:?}`")]
    Expected {
        expected: &'static str,
        got: Option<Token>,
    },

    #[error("unsupported expression: {0}")]
    Unsupported(String),
}

/// Parse a FHIRPath expression source into an [`Expr`] AST.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let tokens = lex(input)?;
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.parse_expr()?;
    if p.pos < p.tokens.len() {
        return Err(ParseError::Unsupported(format!(
            "trailing tokens after expression: {:?}",
            &p.tokens[p.pos..]
        )));
    }
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(
        &mut self,
        expected: &'static str,
        predicate: impl Fn(&Token) -> bool,
    ) -> Result<Token, ParseError> {
        match self.peek() {
            Some(t) if predicate(t) => {
                let t = t.clone();
                self.pos += 1;
                Ok(t)
            }
            Some(t) => Err(ParseError::Expected {
                expected,
                got: Some(t.clone()),
            }),
            None => Err(ParseError::Expected {
                expected,
                got: None,
            }),
        }
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.bump();
            let rhs = self.parse_and()?;
            lhs = Expr::BinOp(Box::new(lhs), BinOp::Or, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_comparison()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.bump();
            let rhs = self.parse_comparison()?;
            lhs = Expr::BinOp(Box::new(lhs), BinOp::And, Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let lhs = self.parse_unary()?;
        let op = match self.peek() {
            Some(Token::Eq) => Some(BinOp::Eq),
            Some(Token::Neq) => Some(BinOp::Neq),
            Some(Token::Lt) => Some(BinOp::Lt),
            Some(Token::Le) => Some(BinOp::Le),
            Some(Token::Gt) => Some(BinOp::Gt),
            Some(Token::Ge) => Some(BinOp::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let rhs = self.parse_unary()?;
            return Ok(Expr::BinOp(Box::new(lhs), op, Box::new(rhs)));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.bump();
            self.expect("(", |t| matches!(t, Token::LParen))?;
            let inner = self.parse_expr()?;
            self.expect(")", |t| matches!(t, Token::RParen))?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().cloned() {
            Some(Token::NumberLit(s)) => {
                self.bump();
                let v: Value = if s.contains('.') {
                    s.parse::<f64>()
                        .map(Value::from)
                        .map_err(|_| ParseError::Unsupported(format!("invalid number `{s}`")))?
                } else {
                    s.parse::<i64>()
                        .map(Value::from)
                        .map_err(|_| ParseError::Unsupported(format!("invalid integer `{s}`")))?
                };
                Ok(Expr::Literal(v))
            }
            Some(Token::StringLit(s)) => {
                self.bump();
                Ok(Expr::Literal(Value::String(s)))
            }
            Some(Token::Bool(b)) => {
                self.bump();
                Ok(Expr::Literal(Value::Bool(b)))
            }
            Some(Token::LParen) => {
                self.bump();
                let inner = self.parse_expr()?;
                self.expect(")", |t| matches!(t, Token::RParen))?;
                Ok(inner)
            }
            Some(Token::Ident(_)) => self.parse_path(),
            other => Err(ParseError::Expected {
                expected: "literal, identifier, or `(`",
                got: other,
            }),
        }
    }

    fn parse_path(&mut self) -> Result<Expr, ParseError> {
        let mut segments = Vec::new();
        // First segment must be a bare identifier.
        let first = self.expect("identifier", |t| matches!(t, Token::Ident(_)))?;
        let Token::Ident(name) = first else {
            unreachable!("expect-predicate guarantees Ident")
        };

        // Could be a top-level function call: `where(...)` standalone
        // is not legal in FHIRPath (no implicit context at root), but
        // `name(args)` as the first path segment IS legal — treat the
        // identifier as a member that's about to be called.
        if matches!(self.peek(), Some(Token::LParen)) {
            self.bump();
            let args = self.parse_args()?;
            self.expect(")", |t| matches!(t, Token::RParen))?;
            segments.push(PathSegment::Function(name, args));
        } else {
            segments.push(PathSegment::Member(name));
        }

        loop {
            match self.peek() {
                Some(Token::Dot) => {
                    self.bump();
                    let ident = self.expect("identifier", |t| matches!(t, Token::Ident(_)))?;
                    let Token::Ident(name) = ident else {
                        unreachable!()
                    };
                    if matches!(self.peek(), Some(Token::LParen)) {
                        self.bump();
                        let args = self.parse_args()?;
                        self.expect(")", |t| matches!(t, Token::RParen))?;
                        segments.push(PathSegment::Function(name, args));
                    } else {
                        segments.push(PathSegment::Member(name));
                    }
                }
                Some(Token::LBracket) => {
                    self.bump();
                    let idx_tok =
                        self.expect("integer index", |t| matches!(t, Token::NumberLit(_)))?;
                    let Token::NumberLit(s) = idx_tok else {
                        unreachable!()
                    };
                    let idx: usize = s
                        .parse()
                        .map_err(|_| ParseError::Unsupported(format!("non-integer index `{s}`")))?;
                    self.expect("]", |t| matches!(t, Token::RBracket))?;
                    segments.push(PathSegment::Index(idx));
                }
                _ => break,
            }
        }
        Ok(Expr::Path(segments))
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>, ParseError> {
        if matches!(self.peek(), Some(Token::RParen)) {
            return Ok(Vec::new());
        }
        let mut args = vec![self.parse_expr()?];
        while matches!(self.peek(), Some(Token::Comma)) {
            self.bump();
            args.push(self.parse_expr()?);
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_path_three_segments() {
        let e = parse("Patient.name.family").unwrap();
        assert_eq!(
            e,
            Expr::Path(vec![
                PathSegment::Member("Patient".into()),
                PathSegment::Member("name".into()),
                PathSegment::Member("family".into()),
            ])
        );
    }

    #[test]
    fn indexed_path() {
        let e = parse("name[0].family").unwrap();
        assert_eq!(
            e,
            Expr::Path(vec![
                PathSegment::Member("name".into()),
                PathSegment::Index(0),
                PathSegment::Member("family".into()),
            ])
        );
    }

    #[test]
    fn where_predicate() {
        let e = parse("name.where(use = 'official').family").unwrap();
        let Expr::Path(segs) = e else {
            panic!("expected path")
        };
        assert_eq!(segs.len(), 3);
        assert!(matches!(&segs[0], PathSegment::Member(n) if n == "name"));
        assert!(matches!(
            &segs[1],
            PathSegment::Function(n, args)
                if n == "where" && args.len() == 1
        ));
    }

    #[test]
    fn comparison_returns_binop() {
        let e = parse("Patient.gender = 'female'").unwrap();
        assert!(matches!(e, Expr::BinOp(_, BinOp::Eq, _)));
    }

    #[test]
    fn logical_and_or() {
        let e = parse("a or b and c").unwrap();
        // Precedence: `b and c` binds first.
        let Expr::BinOp(lhs, BinOp::Or, rhs) = e else {
            panic!("expected or at top");
        };
        assert!(matches!(*lhs, Expr::Path(_)));
        assert!(matches!(*rhs, Expr::BinOp(_, BinOp::And, _)));
    }

    #[test]
    fn not_parens_required() {
        let e = parse("not(a)").unwrap();
        assert!(matches!(e, Expr::Not(_)));
    }

    #[test]
    fn exists_function_zero_args() {
        let e = parse("Patient.identifier.exists()").unwrap();
        let Expr::Path(segs) = e else { panic!() };
        assert!(matches!(
            &segs[2],
            PathSegment::Function(n, args) if n == "exists" && args.is_empty()
        ));
    }

    #[test]
    fn trailing_garbage_errors() {
        let err = parse("a.b foo").unwrap_err();
        assert!(matches!(err, ParseError::Unsupported(_)));
    }

    #[test]
    fn parens_group_expressions() {
        let e = parse("(a or b) and c").unwrap();
        let Expr::BinOp(lhs, BinOp::And, _) = e else {
            panic!("expected outer AND")
        };
        assert!(matches!(*lhs, Expr::BinOp(_, BinOp::Or, _)));
    }
}
