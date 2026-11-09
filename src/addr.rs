//! Network parameters and address encoding (via `outscript`).

use outscript::hash::hash160;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub name: &'static str,
    pub p2pkh: u8,
    pub p2sh: u8,
    pub hrp: Option<&'static str>,
}

pub const NETWORKS: &[Network] = &[
    Network { name: "bitcoin", p2pkh: 0x00, p2sh: 0x05, hrp: Some("bc") },
    Network { name: "testnet", p2pkh: 0x6f, p2sh: 0xc4, hrp: Some("tb") },
    Network { name: "regtest", p2pkh: 0x6f, p2sh: 0xc4, hrp: Some("bcrt") },
    Network { name: "litecoin", p2pkh: 0x30, p2sh: 0x32, hrp: Some("ltc") },
    Network { name: "dogecoin", p2pkh: 0x1e, p2sh: 0x16, hrp: None },
    Network { name: "namecoin", p2pkh: 0x34, p2sh: 0x0d, hrp: Some("nc") },
];

impl Network {
    pub fn by_name(name: &str) -> Option<Network> {
        NETWORKS.iter().copied().find(|n| n.name.eq_ignore_ascii_case(name))
    }

    /// Guesses the network an address string belongs to.
    pub fn detect(addr: &str) -> Option<Network> {
        let lower = addr.to_ascii_lowercase();
        // Longest hrp first so "bcrt1" isn't taken for "bc1".
        let mut by_hrp: Vec<_> = NETWORKS.iter().filter(|n| n.hrp.is_some()).collect();
        by_hrp.sort_by_key(|n| std::cmp::Reverse(n.hrp.unwrap().len()));
        if let Some(n) = by_hrp.into_iter().find(|n| lower.starts_with(&format!("{}1", n.hrp.unwrap()))) {
            return Some(*n);
        }
        let mut buf = [0u8; 64];
        let len = outscript::base58::decode_to_slice(addr, &mut buf).ok()?;
        if len != 25 {
            return None;
        }
        let v = buf[0];
        NETWORKS.iter().copied().find(|n| n.p2pkh == v || n.p2sh == v)
    }

    pub fn base58(&self, version: u8, payload: &[u8]) -> String {
        let mut out = [0u8; 64];
        let n = outscript::encode_base58_addr_to_slice(version, payload, &mut out).expect("buffer large enough");
        String::from_utf8_lossy(&out[..n]).into_owned()
    }

    pub fn p2pkh(&self, h: &[u8; 20]) -> String {
        self.base58(self.p2pkh, h)
    }

    pub fn p2sh(&self, h: &[u8; 20]) -> String {
        self.base58(self.p2sh, h)
    }

    pub fn segwit(&self, version: u8, program: &[u8]) -> Option<String> {
        let mut out = [0u8; 100];
        let n = outscript::bech32::segwit_addr_encode_to_slice(self.hrp?, version, program, &mut out).ok()?;
        Some(String::from_utf8_lossy(&out[..n]).into_owned())
    }

    /// Address(es) a public key can receive on: P2PKH always, plus
    /// P2WPKH and P2SH-P2WPKH for compressed keys.
    pub fn pubkey_addresses(&self, pubkey: &[u8]) -> PubkeyAddrs {
        let h = hash160(pubkey);
        let compressed = pubkey.len() == 33;
        let (p2wpkh, p2sh_p2wpkh) = if compressed {
            let mut redeem = [0u8; 22];
            redeem[1] = 0x14;
            redeem[2..].copy_from_slice(&h);
            (self.segwit(0, &h), self.hrp.map(|_| self.p2sh(&hash160(&redeem))))
        } else {
            (None, None)
        };
        PubkeyAddrs { p2pkh: self.p2pkh(&h), p2wpkh, p2sh_p2wpkh }
    }

    /// Decodes a standard output script to an address.
    pub fn script_address(&self, s: &[u8]) -> Option<String> {
        match s {
            [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => Some(self.p2pkh(h.try_into().ok()?)),
            [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => Some(self.p2sh(h.try_into().ok()?)),
            [0x00, 0x14, h @ ..] if h.len() == 20 => self.segwit(0, h),
            [0x00, 0x20, h @ ..] if h.len() == 32 => self.segwit(0, h),
            [0x51, 0x20, h @ ..] if h.len() == 32 => self.segwit(1, h),
            [n, pk @ .., 0xac] if (*n == 33 || *n == 65) && pk.len() == *n as usize => {
                Some(self.p2pkh(&hash160(pk)))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PubkeyAddrs {
    pub p2pkh: String,
    pub p2wpkh: Option<String>,
    pub p2sh_p2wpkh: Option<String>,
}

impl PubkeyAddrs {
    pub fn all(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.p2pkh.as_str())
            .chain(self.p2sh_p2wpkh.as_deref())
            .chain(self.p2wpkh.as_deref())
    }
}

pub fn valid_pubkey(pk: &[u8]) -> bool {
    matches!((pk.len(), pk.first()), (33, Some(2 | 3)) | (65, Some(4 | 6 | 7)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const G_COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn generator_addresses() {
        let btc = Network::by_name("bitcoin").unwrap();
        let a = btc.pubkey_addresses(&unhex(G_COMPRESSED));
        assert_eq!(a.p2pkh, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(a.p2wpkh.as_deref(), Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert_eq!(a.p2sh_p2wpkh.as_deref(), Some("3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"));
    }

    #[test]
    fn detect() {
        assert_eq!(Network::detect("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap().name, "bitcoin");
        assert_eq!(Network::detect("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap().name, "regtest");
        assert_eq!(Network::detect("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap().name, "testnet");
    }
}
