//! Tiny blocking HTTP/1.1 client: plain TCP or TLS (purecrypto), with
//! `http(s)_proxy` / `no_proxy` support. One request per connection.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use purecrypto::tls::{Config, Connection, HandshakeStatus, ProtocolVersion, RootCertStore};

const CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Gentoo, Arch, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // macOS, BSDs
];

pub struct Url {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

impl Url {
    pub fn parse(url: &str) -> Result<Url, String> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("unsupported URL {url:?} (need http:// or https://)"));
        };
        let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(r) = authority.strip_prefix('[') {
            let (h, after) = r.split_once(']').ok_or_else(|| format!("bad IPv6 host in {url:?}"))?;
            (h, after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(p) => p.parse().map_err(|_| format!("bad port in {url:?}"))?,
            None if tls => 443,
            None => 80,
        };
        if host.is_empty() {
            return Err(format!("no host in {url:?}"));
        }
        Ok(Url { tls, host: host.to_string(), port, path: path.to_string() })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    fn host_header(&self) -> String {
        match (self.tls, self.port) {
            (true, 443) | (false, 80) => self.host.clone(),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

fn env_var(names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| std::env::var(n).ok()).filter(|v| !v.is_empty())
}

/// The proxy to use for `url`, from the usual environment variables.
fn proxy_for(url: &Url) -> Option<Url> {
    let no_proxy = env_var(&["no_proxy", "NO_PROXY"]).unwrap_or_default();
    let host = url.host.to_ascii_lowercase();
    for pat in no_proxy.split(',').map(|p| p.trim().trim_start_matches('.').to_ascii_lowercase()) {
        if pat == "*" || (!pat.is_empty() && (host == pat || host.ends_with(&format!(".{pat}")))) {
            return None;
        }
    }
    let p = if url.tls {
        env_var(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"])
    } else {
        env_var(&["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"])
    }?;
    let p = if p.contains("://") { p } else { format!("http://{p}") };
    Url::parse(&p).ok().filter(|u| !u.tls)
}

fn io_err(what: &str, e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => format!("{what}: timed out"),
        _ => format!("{what}: {e}"),
    }
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addrs = (host, port).to_socket_addrs().map_err(|e| format!("resolving {host}: {e}"))?;
    let mut last = format!("no address for {host}");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
                return Ok(s);
            }
            Err(e) => last = io_err(&format!("connecting to {host}:{port}"), e),
        }
    }
    Err(last)
}

fn tls_config(host: &str) -> Result<Config, String> {
    static ROOTS: OnceLock<Result<RootCertStore, String>> = OnceLock::new();
    let roots = ROOTS.get_or_init(load_roots).as_ref().map_err(Clone::clone)?;
    Ok(Config::builder()
        .rng(Arc::new(purecrypto::rng::OsRng))
        .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
        .roots(roots.clone_store())
        .server_name(host)
        .verify_certificates(true)
        .alpn(vec![b"http/1.1".to_vec()])
        .build())
}

/// System CA bundle (`SSL_CERT_FILE` overrides the default locations).
fn load_roots() -> Result<RootCertStore, String> {
    let candidates: Vec<String> = match std::env::var("SSL_CERT_FILE") {
        Ok(f) if !f.is_empty() => vec![f],
        _ => CA_BUNDLES.iter().map(|s| s.to_string()).collect(),
    };
    for path in &candidates {
        let Ok(pem) = std::fs::read_to_string(path) else { continue };
        let mut store = RootCertStore::new();
        const END: &str = "-----END CERTIFICATE-----";
        let mut rest = pem.as_str();
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let Some(end) = rest[start..].find(END) else { break };
            let block = &rest[start..start + end + END.len()];
            let _ = store.add_pem(block);
            rest = &rest[start + end + END.len()..];
        }
        if !store.is_empty() {
            return Ok(store);
        }
    }
    Err(format!("no CA certificates found (tried {}; set SSL_CERT_FILE)", candidates.join(", ")))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<Connection>, TcpStream),
}

impl Stream {
    fn open(url: &Url, timeout: Duration) -> Result<(Stream, bool), String> {
        let proxy = proxy_for(url);
        let mut sock = match &proxy {
            Some(p) => connect(&p.host, p.port, timeout)?,
            None => connect(&url.host, url.port, timeout)?,
        };
        if !url.tls {
            return Ok((Stream::Plain(sock), proxy.is_some()));
        }
        if let Some(p) = &proxy {
            let target = format!("{}:{}", url.host, url.port);
            write!(sock, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
                .map_err(|e| format!("proxy write: {e}"))?;
            // Read the reply byte by byte so no tunnelled data is consumed.
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match sock.read(&mut b) {
                    Ok(1) => head.push(b[0]),
                    Ok(_) => return Err(format!("proxy {}:{} closed the connection", p.host, p.port)),
                    Err(e) => return Err(io_err("proxy read", e)),
                }
                if head.len() > 16384 {
                    return Err("proxy reply too long".into());
                }
            }
            let status = String::from_utf8_lossy(&head);
            let line = status.lines().next().unwrap_or("");
            if line.split_whitespace().nth(1) != Some("200") {
                return Err(format!("proxy refused CONNECT to {target}: {line}"));
            }
        }
        let cfg = tls_config(&url.host)?;
        let mut conn = Connection::client(&cfg).map_err(|e| format!("TLS setup: {e:?}"))?;
        let mut buf = [0u8; 16384];
        loop {
            let out = conn.pop().unwrap_or_default();
            if !out.is_empty() {
                sock.write_all(&out).map_err(|e| io_err("socket write", e))?;
            }
            match conn.handshake() {
                Ok(HandshakeStatus::Complete) => break,
                Ok(HandshakeStatus::WantWrite) => continue,
                Ok(HandshakeStatus::WantRead) => {
                    let n = sock.read(&mut buf).map_err(|e| io_err("socket read", e))?;
                    if n == 0 {
                        return Err(format!("{} closed the connection during the TLS handshake", url.host));
                    }
                    conn.feed(&buf[..n]).map_err(|e| format!("TLS handshake with {}: {e:?}", url.host))?;
                }
                Err(e) => {
                    let out = conn.pop().unwrap_or_default();
                    let _ = sock.write_all(&out);
                    return Err(format!("TLS handshake with {}: {e:?}", url.host));
                }
            }
        }
        Ok((Stream::Tls(Box::new(conn), sock), false))
    }

    fn send(&mut self, data: &[u8]) -> Result<(), String> {
        match self {
            Stream::Plain(s) => s.write_all(data).map_err(|e| io_err("socket write", e)),
            Stream::Tls(c, s) => {
                c.send(data).map_err(|e| format!("TLS send: {e:?}"))?;
                let out = c.pop().map_err(|e| format!("TLS: {e:?}"))?;
                s.write_all(&out).map_err(|e| io_err("socket write", e))
            }
        }
    }

    /// Reads until the response is complete or the peer closes.
    fn read_response(&mut self) -> Result<Vec<u8>, String> {
        let mut resp = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            if response_complete(&resp) {
                return Ok(resp);
            }
            match self {
                Stream::Plain(s) => match s.read(&mut buf) {
                    Ok(0) => return Ok(resp),
                    Ok(n) => resp.extend_from_slice(&buf[..n]),
                    Err(e) => return Err(io_err("socket read", e)),
                },
                Stream::Tls(c, s) => {
                    let pre = c.recv().unwrap_or_default();
                    if !pre.is_empty() {
                        resp.extend_from_slice(&pre);
                        continue;
                    }
                    if c.received_close_notify() {
                        return Ok(resp);
                    }
                    match s.read(&mut buf) {
                        Ok(0) => {
                            // EOF without close_notify: only fine if the
                            // response framing says we have everything.
                            return if response_complete(&resp) {
                                Ok(resp)
                            } else {
                                Err("connection closed before the response was complete".into())
                            };
                        }
                        Ok(n) => {
                            c.feed(&buf[..n]).map_err(|e| format!("TLS: {e:?}"))?;
                            if let Ok(out) = c.pop()
                                && !out.is_empty()
                            {
                                let _ = s.write_all(&out);
                            }
                        }
                        Err(e) => return Err(io_err("socket read", e)),
                    }
                }
            }
        }
    }

    fn close(mut self) {
        if let Stream::Tls(c, s) = &mut self
            && c.close().is_ok()
            && let Ok(out) = c.pop()
        {
            let _ = s.write_all(&out);
        }
    }
}

struct Head {
    status: u16,
    body_start: usize,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_head(resp: &[u8]) -> Option<Head> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = String::from_utf8_lossy(&resp[..end]);
    let mut lines = text.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut head = Head { status, body_start: end + 4, content_length: None, chunked: false };
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            head.content_length = v.parse().ok();
        } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            head.chunked = true;
        }
    }
    Some(head)
}

fn response_complete(resp: &[u8]) -> bool {
    let Some(h) = parse_head(resp) else { return false };
    let body = &resp[h.body_start..];
    if h.chunked {
        dechunk(body).is_some()
    } else if let Some(n) = h.content_length {
        body.len() >= n
    } else {
        false
    }
}

/// Decodes a complete chunked body; `None` if it is not complete yet.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size_txt = std::str::from_utf8(&b[..eol]).ok()?;
        let size = usize::from_str_radix(size_txt.split(';').next()?.trim(), 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            // Trailers end with an empty line.
            return (b.starts_with(b"\r\n") || b.windows(4).any(|w| w == b"\r\n\r\n")).then_some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

/// POSTs a JSON body and returns the response body (2xx only).
pub fn post_json(url: &str, body: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let u = Url::parse(url)?;
    let (mut stream, via_proxy) = Stream::open(&u, timeout)?;
    let target = if via_proxy { url.to_string() } else { u.path.clone() };
    let req = format!(
        "POST {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: btcwallet/{}\r\nAccept: application/json\r\n\
         Accept-Encoding: identity\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        u.host_header(),
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    stream.send(req.as_bytes())?;
    let resp = stream.read_response()?;
    stream.close();
    let h = parse_head(&resp).ok_or("malformed HTTP response")?;
    let raw = &resp[h.body_start..];
    let body = if h.chunked {
        dechunk(raw).ok_or("truncated chunked response")?
    } else {
        raw[..h.content_length.unwrap_or(raw.len()).min(raw.len())].to_vec()
    };
    if !(200..300).contains(&h.status) {
        let snippet: String = String::from_utf8_lossy(&body).chars().take(200).collect();
        return Err(format!("HTTP {}: {}", h.status, snippet.trim()));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://rpc.modchain.net/chain/bitcoin/rpc").unwrap();
        assert!(u.tls);
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("rpc.modchain.net", 443, "/chain/bitcoin/rpc"));
        let u = Url::parse("http://user:pw@127.0.0.1:3456").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("127.0.0.1", 3456, "/"));
        let u = Url::parse("http://[::1]:8080/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 8080));
    }

    #[test]
    fn chunked() {
        assert_eq!(dechunk(b"4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n").unwrap(), b"Wikipedia");
        assert!(dechunk(b"4\r\nWiki\r\n5\r\nped").is_none());
        assert!(response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"));
    }
}
