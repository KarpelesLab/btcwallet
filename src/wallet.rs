//! Decoding of legacy (Berkeley DB) bitcoin wallet records.

use std::collections::{BTreeMap, HashMap};

use outscript::hash::hash160;

use crate::bdb::Record;
use crate::util::{RResult, Reader, hex_rev};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// `key`: unencrypted private key.
    Plain,
    /// `wkey`: very old unencrypted wallet key.
    WalletKey,
    /// `ckey`: private key encrypted with the master key.
    Crypted,
}

#[derive(Debug, Clone, Default)]
pub struct KeyMeta {
    pub version: i32,
    pub create_time: i64,
    pub hd_path: Option<String>,
    pub hd_seed_id: Option<[u8; 20]>,
    pub fingerprint: Option<[u8; 4]>,
}

#[derive(Debug, Clone)]
pub struct Key {
    pub pubkey: Vec<u8>,
    pub kind: KeyKind,
    pub meta: Option<KeyMeta>,
    /// Key pool index, if the key is (still) in the pool.
    pub pool: Option<PoolRef>,
}

#[derive(Debug, Clone, Copy)]
pub struct PoolRef {
    pub index: i64,
    pub internal: bool,
}

#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub index: i64,
    pub time: i64,
    pub pubkey: Vec<u8>,
    pub internal: bool,
    pub pre_split: bool,
}

#[derive(Debug, Clone)]
pub struct MasterKey {
    pub id: u32,
    pub crypted_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub method: u32,
    pub iterations: u32,
}

#[derive(Debug, Clone)]
pub struct HdChain {
    pub version: i32,
    pub external_counter: u32,
    pub internal_counter: Option<u32>,
    pub seed_id: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct Descriptor {
    pub id: [u8; 32],
    pub descriptor: String,
    pub create_time: u64,
    pub next_index: i32,
    pub range: (i32, i32),
}

#[derive(Debug, Default)]
pub struct Wallet {
    pub version: Option<i32>,
    pub min_version: Option<i32>,
    pub flags: Option<u64>,
    pub keys: BTreeMap<Vec<u8>, Key>,
    pub master_keys: Vec<MasterKey>,
    pub pool: Vec<PoolEntry>,
    pub hd_chain: Option<HdChain>,
    pub default_key: Option<Vec<u8>>,
    /// address -> label
    pub names: BTreeMap<String, String>,
    /// address -> purpose ("receive", "send", ...)
    pub purposes: BTreeMap<String, String>,
    pub txids: Vec<[u8; 32]>,
    pub best_block: Option<(bool, Vec<[u8; 32]>)>,
    /// hash160 -> redeem script
    pub scripts: Vec<([u8; 20], Vec<u8>)>,
    pub watch_only: Vec<Vec<u8>>,
    /// account name -> pubkey
    pub accounts: Vec<(String, Vec<u8>)>,
    pub account_entries: usize,
    pub order_pos_next: Option<i64>,
    pub descriptors: Vec<Descriptor>,
    pub active_spk: Vec<(bool, u8, [u8; 32])>,
    pub type_counts: BTreeMap<String, usize>,
    pub errors: Vec<String>,
}

/// Wallet feature levels (CWallet::WalletFeature).
pub fn feature_name(v: i32) -> &'static str {
    match v {
        ..10500 => "pre-0.3.24",
        10500..40000 => "base",
        40000..60000 => "wallet encryption",
        60000..130000 => "compressed pubkeys",
        130000..139900 => "HD",
        139900..159900 => "HD split (internal chain)",
        159900..169900 => "no default key",
        _ => "pre-split keypool",
    }
}

pub fn record_type(key: &[u8]) -> Option<String> {
    let mut r = Reader::new(key);
    let t = r.bytes().ok()?;
    std::str::from_utf8(t).ok().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())).map(str::to_owned)
}

impl Wallet {
    pub fn from_records(records: &[Record]) -> Wallet {
        let mut w = Wallet::default();
        let mut metas: HashMap<Vec<u8>, KeyMeta> = HashMap::new();
        for (k, v) in records {
            let Some(typ) = record_type(k) else {
                *w.type_counts.entry("<unparseable>".into()).or_default() += 1;
                continue;
            };
            *w.type_counts.entry(typ.clone()).or_default() += 1;
            let mut kr = Reader::new(k);
            kr.bytes().unwrap();
            let mut vr = Reader::new(v);
            if let Err(e) = w.decode(&typ, &mut kr, &mut vr, &mut metas) {
                w.errors.push(format!("{typ} record: {e}"));
            }
        }
        for (pk, m) in metas {
            if let Some(k) = w.keys.get_mut(&pk) {
                k.meta = Some(m);
            }
        }
        for p in &w.pool {
            if let Some(k) = w.keys.get_mut(&p.pubkey) {
                k.pool = Some(PoolRef { index: p.index, internal: p.internal });
            }
        }
        w.pool.sort_by_key(|p| p.index);
        w
    }

    fn add_key(&mut self, pubkey: &[u8], kind: KeyKind) {
        self.keys.insert(pubkey.to_vec(), Key { pubkey: pubkey.to_vec(), kind, meta: None, pool: None });
    }

    fn decode(
        &mut self,
        typ: &str,
        k: &mut Reader<'_>,
        v: &mut Reader<'_>,
        metas: &mut HashMap<Vec<u8>, KeyMeta>,
    ) -> RResult<()> {
        match typ {
            "version" => self.version = Some(v.i32()?),
            "minversion" => self.min_version = Some(v.i32()?),
            "flags" => self.flags = Some(v.u64()?),
            "orderposnext" => self.order_pos_next = Some(v.i64()?),
            "key" => self.add_key(k.bytes()?, KeyKind::Plain),
            "wkey" => self.add_key(k.bytes()?, KeyKind::WalletKey),
            "ckey" => self.add_key(k.bytes()?, KeyKind::Crypted),
            "keymeta" => {
                let pk = k.bytes()?.to_vec();
                let mut m = KeyMeta { version: v.i32()?, create_time: v.i64()?, ..Default::default() };
                if m.version >= 10 && !v.is_empty() {
                    m.hd_path = Some(v.string()?);
                    m.hd_seed_id = Some(v.array()?);
                }
                if m.version >= 12 && !v.is_empty() {
                    m.fingerprint = Some(v.array()?);
                    let n = v.compact()?;
                    let path: Vec<u32> = (0..n).map(|_| v.u32()).collect::<RResult<_>>()?;
                    let has_origin = v.bool().unwrap_or(false);
                    if m.hd_path.as_deref().unwrap_or("").is_empty() && has_origin {
                        m.hd_path = Some(format_path(&path));
                    }
                }
                metas.insert(pk, m);
            }
            "mkey" => {
                let id = k.u32()?;
                self.master_keys.push(MasterKey {
                    id,
                    crypted_key: v.bytes()?.to_vec(),
                    salt: v.bytes()?.to_vec(),
                    method: v.u32()?,
                    iterations: v.u32()?,
                });
            }
            "pool" => {
                let index = k.i64()?;
                let _client_version = v.i32()?;
                let time = v.i64()?;
                let pubkey = v.bytes()?.to_vec();
                let internal = v.bool().unwrap_or(false);
                let pre_split = v.bool().unwrap_or(false);
                self.pool.push(PoolEntry { index, time, pubkey, internal, pre_split });
            }
            "hdchain" => {
                let version = v.i32()?;
                let external_counter = v.u32()?;
                let seed_id = v.array()?;
                let internal_counter = if version >= 2 { Some(v.u32()?) } else { None };
                self.hd_chain = Some(HdChain { version, external_counter, internal_counter, seed_id });
            }
            "defaultkey" => self.default_key = Some(v.bytes()?.to_vec()),
            "name" => {
                let addr = k.string()?;
                self.names.insert(addr, v.string()?);
            }
            "purpose" => {
                let addr = k.string()?;
                self.purposes.insert(addr, v.string()?);
            }
            "tx" => self.txids.push(k.array()?),
            "bestblock" | "bestblock_nomerkle" => {
                let _version = v.i32()?;
                let n = v.compact()?;
                let hashes: Vec<[u8; 32]> = (0..n).map(|_| v.array()).collect::<RResult<_>>()?;
                let nomerkle = typ == "bestblock_nomerkle";
                // Prefer whichever locator actually has hashes.
                if !hashes.is_empty() || self.best_block.is_none() {
                    self.best_block = Some((nomerkle, hashes));
                }
            }
            "cscript" => {
                let h = k.array()?;
                self.scripts.push((h, v.bytes()?.to_vec()));
            }
            "watchs" => self.watch_only.push(k.bytes()?.to_vec()),
            "acc" => {
                let name = k.string()?;
                let _version = v.i32()?;
                self.accounts.push((name, v.bytes()?.to_vec()));
            }
            "acentry" => self.account_entries += 1,
            "walletdescriptor" => {
                let id = k.array()?;
                let descriptor = v.string()?;
                let create_time = v.u64()?;
                let next_index = v.i32()?;
                let range = (v.i32()?, v.i32()?);
                self.descriptors.push(Descriptor { id, descriptor, create_time, next_index, range });
            }
            "activeexternalspk" | "activeinternalspk" => {
                let t = k.u8()?;
                self.active_spk.push((typ == "activeinternalspk", t, v.array()?));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn encrypted(&self) -> bool {
        !self.master_keys.is_empty() || self.keys.values().any(|k| k.kind == KeyKind::Crypted)
    }

    /// The key whose hash160 matches the HD seed id, if present.
    pub fn hd_seed_key(&self) -> Option<&Key> {
        let id = self.hd_chain.as_ref()?.seed_id;
        self.keys.values().find(|k| hash160(&k.pubkey) == id)
    }

    /// Keys sorted by creation time (unknown first), then pool index.
    pub fn sorted_keys(&self) -> Vec<&Key> {
        let mut v: Vec<&Key> = self.keys.values().collect();
        v.sort_by_key(|k| (k.meta.as_ref().map_or(0, |m| m.create_time), k.pool.map_or(i64::MIN, |p| p.index)));
        v
    }

    pub fn best_block_hash(&self) -> Option<String> {
        self.best_block.as_ref().and_then(|(_, h)| h.first()).map(|h| hex_rev(h))
    }
}

fn format_path(path: &[u32]) -> String {
    let mut s = String::from("m");
    for &p in path {
        if p & 0x8000_0000 != 0 {
            s += &format!("/{}'", p & 0x7fff_ffff);
        } else {
            s += &format!("/{p}");
        }
    }
    s
}
