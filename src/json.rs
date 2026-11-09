//! Minimal JSON parser (enough for JSON-RPC responses).
//!
//! Numbers are kept as their source text so amounts never go through a float.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The textual form of a number, or the content of a string.
    pub fn as_num_str(&self) -> Option<&str> {
        match self {
            Value::Number(s) | Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

pub fn parse(s: &str) -> Result<Value, String> {
    let mut p = Parser { b: s.as_bytes(), pos: 0, depth: 0 };
    let v = p.value()?;
    p.ws();
    if p.pos != p.b.len() {
        return Err(p.err("trailing data"));
    }
    Ok(v)
}

/// Escapes a string as a JSON string literal.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &str) -> String {
        format!("JSON: {msg} at byte {}", self.pos)
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        self.ws();
        if self.b.get(self.pos) == Some(&c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", c as char)))
        }
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.b[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        if self.depth > 128 {
            return Err(self.err("nesting too deep"));
        }
        match self.b.get(self.pos) {
            None => Err(self.err("unexpected end")),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                self.pos += 1;
                self.depth += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                } else {
                    loop {
                        items.push(self.value()?);
                        self.ws();
                        match self.b.get(self.pos) {
                            Some(b',') => self.pos += 1,
                            Some(b']') => {
                                self.pos += 1;
                                break;
                            }
                            _ => return Err(self.err("expected ',' or ']'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(Value::Array(items))
            }
            Some(b'{') => {
                self.pos += 1;
                self.depth += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.pos) == Some(&b'}') {
                    self.pos += 1;
                } else {
                    loop {
                        self.ws();
                        if self.b.get(self.pos) != Some(&b'"') {
                            return Err(self.err("expected object key"));
                        }
                        let k = self.string()?;
                        self.eat(b':')?;
                        items.push((k, self.value()?));
                        self.ws();
                        match self.b.get(self.pos) {
                            Some(b',') => self.pos += 1,
                            Some(b'}') => {
                                self.pos += 1;
                                break;
                            }
                            _ => return Err(self.err("expected ',' or '}'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(Value::Object(items))
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.pos;
                while matches!(self.b.get(self.pos), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                    self.pos += 1;
                }
                Ok(Value::Number(String::from_utf8_lossy(&self.b[start..self.pos]).into_owned()))
            }
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let s = self.b.get(self.pos..self.pos + 4).ok_or_else(|| self.err("short \\u escape"))?;
        let v = u32::from_str_radix(std::str::from_utf8(s).unwrap_or("x"), 16).map_err(|_| self.err("bad \\u escape"))?;
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // opening quote
        let mut out = Vec::new();
        loop {
            match self.b.get(self.pos) {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let c = *self.b.get(self.pos).ok_or_else(|| self.err("bad escape"))?;
                    self.pos += 1;
                    let ch = match c {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xd800..0xdc00).contains(&cp) && self.b[self.pos..].starts_with(b"\\u") {
                                self.pos += 2;
                                let lo = self.hex4()?;
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo.wrapping_sub(0xdc00) & 0x3ff);
                            }
                            char::from_u32(cp).unwrap_or('\u{fffd}')
                        }
                        _ => return Err(self.err("bad escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                Some(&c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|_| self.err("invalid UTF-8 in string"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_response() {
        let v = parse(
            r#"{"jsonrpc":"2.0","result":{"assets":[{"asset":"NATIVE","balance":0.00029450,
            "balance_obj":{"v":"29450","e":8,"f":0.0002945},"txo":null}]},"id":1, "s":"a\"é😀"}"#,
        )
        .unwrap();
        let a = &v.get("result").unwrap().get("assets").unwrap().as_array().unwrap()[0];
        assert_eq!(a.get("balance").unwrap().as_num_str(), Some("0.00029450"));
        assert_eq!(a.get("balance_obj").unwrap().get("v").unwrap().as_str(), Some("29450"));
        assert!(a.get("txo").unwrap().is_null());
        assert_eq!(v.get("s").unwrap().as_str(), Some("a\"é😀"));
        assert_eq!(parse("[]").unwrap(), Value::Array(vec![]));
        assert!(parse("[1,]").is_err());
        assert!(parse("{} x").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a\"b\\\n"), r#""a\"b\\\n""#);
    }
}
