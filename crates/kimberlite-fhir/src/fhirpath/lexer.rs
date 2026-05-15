//! FHIRPath subset lexer.
//!
//! Hand-rolled because the grammar is small and the dep cost of a
//! parser-combinator crate isn't justified. Emits a flat `Vec<Token>`
//! the parser consumes in order.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    /// String literal (FHIRPath: single quotes).
    StringLit(String),
    /// Numeric literal — held as the raw textual form so the parser
    /// can decide between integer and decimal interpretation.
    NumberLit(String),
    Bool(bool),
    Dot,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
}

#[derive(Debug, Error, PartialEq)]
pub enum LexError {
    #[error("unexpected character `{ch}` at position {pos}")]
    UnexpectedChar { ch: char, pos: usize },

    #[error("unterminated string literal starting at position {pos}")]
    UnterminatedString { pos: usize },

    #[error("invalid number at position {pos}: {text}")]
    InvalidNumber { pos: usize, text: String },
}

/// Tokenize a FHIRPath expression.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];

        // Skip whitespace.
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Single-character tokens.
        match b {
            b'.' => {
                out.push(Token::Dot);
                i += 1;
                continue;
            }
            b'[' => {
                out.push(Token::LBracket);
                i += 1;
                continue;
            }
            b']' => {
                out.push(Token::RBracket);
                i += 1;
                continue;
            }
            b'(' => {
                out.push(Token::LParen);
                i += 1;
                continue;
            }
            b')' => {
                out.push(Token::RParen);
                i += 1;
                continue;
            }
            b',' => {
                out.push(Token::Comma);
                i += 1;
                continue;
            }
            b'=' => {
                out.push(Token::Eq);
                i += 1;
                continue;
            }
            _ => {}
        }

        // Two-character operators or single-char comparisons.
        if b == b'!' && i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            out.push(Token::Neq);
            i += 2;
            continue;
        }
        if b == b'<' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                out.push(Token::Le);
                i += 2;
            } else {
                out.push(Token::Lt);
                i += 1;
            }
            continue;
        }
        if b == b'>' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                out.push(Token::Ge);
                i += 2;
            } else {
                out.push(Token::Gt);
                i += 1;
            }
            continue;
        }

        // String literal (FHIRPath uses single quotes).
        if b == b'\'' {
            let start = i;
            i += 1;
            let mut s = String::new();
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    let ch = match next {
                        b'n' => '\n',
                        b't' => '\t',
                        b'\'' => '\'',
                        b'\\' => '\\',
                        b'"' => '"',
                        other => other as char,
                    };
                    s.push(ch);
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\'' {
                    closed = true;
                    i += 1;
                    break;
                }
                s.push(bytes[i] as char);
                i += 1;
            }
            if !closed {
                return Err(LexError::UnterminatedString { pos: start });
            }
            out.push(Token::StringLit(s));
            continue;
        }

        // Numeric literal.
        if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                // Stop a number at the second `.` so `1.2.3` parses
                // as `1.2` then `.` (we don't have decimal chains).
                if bytes[i] == b'.'
                    && (i + 1 >= bytes.len() || !bytes[i + 1].is_ascii_digit())
                {
                    break;
                }
                i += 1;
            }
            let text = std::str::from_utf8(&bytes[start..i])
                .map_err(|_| LexError::InvalidNumber {
                    pos: start,
                    text: String::from_utf8_lossy(&bytes[start..i]).into_owned(),
                })?
                .to_string();
            out.push(Token::NumberLit(text));
            continue;
        }

        // Identifier / keyword.
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            let ident = std::str::from_utf8(&bytes[start..i])
                .map_err(|_| LexError::UnexpectedChar {
                    ch: bytes[start] as char,
                    pos: start,
                })?;
            let tok = match ident {
                "and" => Token::And,
                "or" => Token::Or,
                "not" => Token::Not,
                "true" => Token::Bool(true),
                "false" => Token::Bool(false),
                other => Token::Ident(other.to_string()),
            };
            out.push(tok);
            continue;
        }

        return Err(LexError::UnexpectedChar {
            ch: b as char,
            pos: i,
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenises_simple_path() {
        let toks = lex("Patient.name.family").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Ident("Patient".into()),
                Token::Dot,
                Token::Ident("name".into()),
                Token::Dot,
                Token::Ident("family".into()),
            ]
        );
    }

    #[test]
    fn tokenises_indexed_path() {
        let toks = lex("name[0].family").unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Ident("name".into()),
                Token::LBracket,
                Token::NumberLit("0".into()),
                Token::RBracket,
                Token::Dot,
                Token::Ident("family".into()),
            ]
        );
    }

    #[test]
    fn tokenises_where_clause() {
        let toks = lex("name.where(use = 'official').family").unwrap();
        assert!(matches!(toks[0], Token::Ident(ref s) if s == "name"));
        assert!(matches!(toks[2], Token::Ident(ref s) if s == "where"));
        assert_eq!(toks[3], Token::LParen);
        assert!(matches!(toks[4], Token::Ident(ref s) if s == "use"));
        assert_eq!(toks[5], Token::Eq);
        assert!(matches!(toks[6], Token::StringLit(ref s) if s == "official"));
    }

    #[test]
    fn keywords_become_their_tokens() {
        let toks = lex("a and b or not c").unwrap();
        assert_eq!(toks[1], Token::And);
        assert_eq!(toks[3], Token::Or);
        assert_eq!(toks[4], Token::Not);
    }

    #[test]
    fn comparison_operators() {
        let toks = lex(">= <= != < > =").unwrap();
        assert_eq!(
            toks,
            vec![Token::Ge, Token::Le, Token::Neq, Token::Lt, Token::Gt, Token::Eq,]
        );
    }

    #[test]
    fn unterminated_string_errors() {
        let err = lex("name = 'unterm").unwrap_err();
        assert!(matches!(err, LexError::UnterminatedString { .. }));
    }

    #[test]
    fn string_escape_sequences() {
        let toks = lex(r"'O\'Reilly'").unwrap();
        assert_eq!(toks, vec![Token::StringLit("O'Reilly".into())]);
    }

    #[test]
    fn decimal_number_lit() {
        let toks = lex("72.5").unwrap();
        assert_eq!(toks, vec![Token::NumberLit("72.5".into())]);
    }
}
