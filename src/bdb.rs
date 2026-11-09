//! Minimal read-only parser for Berkeley DB 4.x btree files.
//!
//! Only what is needed to read a bitcoin `wallet.dat` is supported: btree
//! databases (optionally inside a master database holding named
//! sub-databases), leaf/internal pages and overflow chains. Hash, queue and
//! recno databases, encrypted environments and off-page duplicates are not.

use std::collections::HashSet;
use std::fmt;

const BTREE_MAGIC: u32 = 0x0005_3162;
const HASH_MAGIC: u32 = 0x0006_1561;

/// Size of the generic page header (`PAGE` in db_page.h).
const PAGE_HEADER: usize = 26;

// Page types.
const P_IBTREE: u8 = 3;
const P_LBTREE: u8 = 5;
const P_OVERFLOW: u8 = 7;
const P_BTREEMETA: u8 = 9;

// Item types (low 7 bits); 0x80 is the "deleted" flag.
const B_KEYDATA: u8 = 1;
const B_DUPLICATE: u8 = 2;
const B_OVERFLOW: u8 = 3;
const B_DELETE: u8 = 0x80;

const MAX_DEPTH: usize = 64;

#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

macro_rules! bail {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

pub type Result<T> = std::result::Result<T, Error>;
pub type Record = (Vec<u8>, Vec<u8>);

/// Information from a btree metadata page.
#[derive(Debug, Clone)]
pub struct Meta {
    pub pgno: u32,
    pub version: u32,
    pub page_size: u32,
    pub root: u32,
}

/// One logical database found in the file.
#[derive(Debug)]
pub struct Database {
    /// Sub-database name, or `None` when the file holds a single unnamed db.
    pub name: Option<String>,
    pub meta: Meta,
    pub records: Vec<Record>,
}

pub struct BdbFile {
    data: Vec<u8>,
    big_endian: bool,
    pub meta: Meta,
    /// Non-fatal oddities met while reading.
    pub warnings: Vec<String>,
}

enum Item<'a> {
    Data(&'a [u8]),
    Overflow { pgno: u32, len: u32 },
    Duplicate,
}

impl BdbFile {
    pub fn open(data: Vec<u8>) -> Result<Self> {
        if data.len() < 512 {
            bail!("file too small to be a Berkeley DB file ({} bytes)", data.len());
        }
        let magic_le = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let magic_be = u32::from_be_bytes(data[12..16].try_into().unwrap());
        let big_endian = match (magic_le, magic_be) {
            (BTREE_MAGIC, _) => false,
            (_, BTREE_MAGIC) => true,
            (HASH_MAGIC, _) | (_, HASH_MAGIC) => bail!("this is a BDB hash database, not a btree"),
            _ => bail!("not a Berkeley DB btree file (magic {magic_le:#010x})"),
        };
        let mut f = BdbFile {
            data,
            big_endian,
            meta: Meta {
                pgno: 0,
                version: 0,
                page_size: 0,
                root: 0,
            },
            warnings: Vec::new(),
        };
        let page_size = f.u32_at(&f.data, 20)?;
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            bail!("invalid page size {page_size}");
        }
        if f.data[24] != 0 {
            bail!("database is encrypted at the Berkeley DB level (not supported)");
        }
        f.meta.page_size = page_size;
        f.meta = f.read_meta(0)?;
        if !f.data.len().is_multiple_of(page_size as usize) {
            f.warnings.push(format!(
                "file size {} is not a multiple of the page size {page_size}",
                f.data.len()
            ));
        }
        Ok(f)
    }

    pub fn big_endian(&self) -> bool {
        self.big_endian
    }

    pub fn page_size(&self) -> usize {
        self.meta.page_size as usize
    }

    pub fn page_count(&self) -> usize {
        self.data.len() / self.page_size()
    }

    fn u16_at(&self, b: &[u8], off: usize) -> Result<u16> {
        let s: [u8; 2] = b
            .get(off..off + 2)
            .ok_or_else(|| Error(format!("read past end of page at offset {off}")))?
            .try_into()
            .unwrap();
        Ok(if self.big_endian { u16::from_be_bytes(s) } else { u16::from_le_bytes(s) })
    }

    fn u32_at(&self, b: &[u8], off: usize) -> Result<u32> {
        let s: [u8; 4] = b
            .get(off..off + 4)
            .ok_or_else(|| Error(format!("read past end of page at offset {off}")))?
            .try_into()
            .unwrap();
        Ok(if self.big_endian { u32::from_be_bytes(s) } else { u32::from_le_bytes(s) })
    }

    fn page(&self, pgno: u32) -> Result<&[u8]> {
        let ps = self.page_size();
        let start = pgno as usize * ps;
        match self.data.get(start..start + ps) {
            Some(p) => Ok(p),
            None => bail!("page {pgno} is beyond the end of the file"),
        }
    }

    fn read_meta(&self, pgno: u32) -> Result<Meta> {
        let p = self.page(pgno)?;
        if self.u32_at(p, 12)? != BTREE_MAGIC {
            bail!("page {pgno} is not a btree metadata page (bad magic)");
        }
        if p[25] != P_BTREEMETA {
            bail!("page {pgno} has type {} instead of btree metadata", p[25]);
        }
        Ok(Meta {
            pgno,
            version: self.u32_at(p, 16)?,
            page_size: self.u32_at(p, 20)?,
            root: self.u32_at(p, 88)?,
        })
    }

    /// Returns the item at index `idx` of a btree page.
    fn item<'a>(&self, p: &'a [u8], idx: usize) -> Result<(u8, Item<'a>)> {
        let off = self.u16_at(p, PAGE_HEADER + 2 * idx)? as usize;
        if off < PAGE_HEADER || off + 3 > p.len() {
            bail!("item offset {off} out of range");
        }
        let typ = p[off + 2];
        let item = match typ & !B_DELETE {
            B_KEYDATA => {
                let len = self.u16_at(p, off)? as usize;
                match p.get(off + 3..off + 3 + len) {
                    Some(d) => Item::Data(d),
                    None => bail!("item at offset {off} overruns its page"),
                }
            }
            B_OVERFLOW => Item::Overflow { pgno: self.u32_at(p, off + 4)?, len: self.u32_at(p, off + 8)? },
            B_DUPLICATE => Item::Duplicate,
            t => bail!("unknown item type {t}"),
        };
        Ok((typ, item))
    }

    fn read_overflow(&self, mut pgno: u32, len: u32) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len as usize);
        let mut seen = HashSet::new();
        while out.len() < len as usize {
            if pgno == 0 {
                bail!("overflow chain ended early ({} of {len} bytes)", out.len());
            }
            if !seen.insert(pgno) {
                bail!("loop in overflow chain at page {pgno}");
            }
            let p = self.page(pgno)?;
            if p[25] != P_OVERFLOW {
                bail!("page {pgno} in overflow chain has type {}", p[25]);
            }
            let n = self.u16_at(p, 22)? as usize;
            match p.get(PAGE_HEADER..PAGE_HEADER + n) {
                Some(d) => out.extend_from_slice(d),
                None => bail!("overflow page {pgno} claims {n} bytes"),
            }
            pgno = self.u32_at(p, 16)?;
        }
        out.truncate(len as usize);
        Ok(out)
    }

    fn resolve(&self, item: Item<'_>) -> Result<Option<Vec<u8>>> {
        match item {
            Item::Data(d) => Ok(Some(d.to_vec())),
            Item::Overflow { pgno, len } => self.read_overflow(pgno, len).map(Some),
            Item::Duplicate => Ok(None),
        }
    }

    /// Reads all key/value pairs from one leaf page.
    fn leaf_records(&mut self, pgno: u32, out: &mut Vec<Record>) -> Result<()> {
        let p = self.page(pgno)?;
        let entries = self.u16_at(p, 20)? as usize;
        let mut pending = Vec::new();
        let mut warn = Vec::new();
        if !entries.is_multiple_of(2) {
            warn.push(format!("leaf page {pgno} has an odd number of entries"));
        }
        for i in (0..entries & !1).step_by(2) {
            let (kt, k) = self.item(p, i)?;
            let (vt, v) = self.item(p, i + 1)?;
            if (kt | vt) & B_DELETE != 0 {
                continue;
            }
            match self.resolve(k).and_then(|k| Ok((k, self.resolve(v)?))) {
                Ok((Some(k), Some(v))) => pending.push((k, v)),
                Ok(_) => warn.push(format!("skipped off-page duplicate on page {pgno}")),
                Err(e) => warn.push(format!("skipped unreadable record on page {pgno}: {e}")),
            }
        }
        out.extend(pending);
        self.warnings.extend(warn);
        Ok(())
    }

    fn walk(&mut self, pgno: u32, depth: usize, seen: &mut HashSet<u32>, out: &mut Vec<Record>) -> Result<()> {
        if depth > MAX_DEPTH {
            bail!("btree deeper than {MAX_DEPTH} levels");
        }
        if !seen.insert(pgno) {
            bail!("loop in btree at page {pgno}");
        }
        let p = self.page(pgno)?;
        match p[25] {
            P_LBTREE => self.leaf_records(pgno, out),
            P_IBTREE => {
                let entries = self.u16_at(p, 20)? as usize;
                let mut children = Vec::with_capacity(entries);
                for i in 0..entries {
                    let off = self.u16_at(p, PAGE_HEADER + 2 * i)? as usize;
                    children.push(self.u32_at(p, off + 4)?);
                }
                for c in children {
                    self.walk(c, depth + 1, seen, out)?;
                }
                Ok(())
            }
            t => bail!("unexpected page type {t} at page {pgno} while walking btree"),
        }
    }

    /// Reads every record of the btree whose metadata page is `meta`.
    pub fn read_tree(&mut self, meta: &Meta) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        self.walk(meta.root, 0, &mut HashSet::new(), &mut out)?;
        Ok(out)
    }

    /// Lists the logical databases stored in the file.
    ///
    /// If the root database is a master database (all its values are page
    /// numbers of btree metadata pages) each named sub-database is returned,
    /// otherwise the root database itself is.
    pub fn databases(&mut self) -> Result<Vec<Database>> {
        let root_meta = self.meta.clone();
        let root = self.read_tree(&root_meta)?;
        let mut subs = Vec::new();
        for (k, v) in &root {
            match self.subdb_meta(v) {
                Some(meta) => subs.push((String::from_utf8_lossy(k).into_owned(), meta)),
                None => {
                    subs.clear();
                    break;
                }
            }
        }
        if subs.is_empty() {
            return Ok(vec![Database { name: None, meta: root_meta, records: root }]);
        }
        let mut dbs = Vec::new();
        for (name, meta) in subs {
            let records = self.read_tree(&meta)?;
            dbs.push(Database { name: Some(name), meta, records });
        }
        Ok(dbs)
    }

    /// Master database values are sub-db meta page numbers, stored big-endian.
    fn subdb_meta(&self, v: &[u8]) -> Option<Meta> {
        let b: [u8; 4] = v.try_into().ok()?;
        [u32::from_be_bytes(b), u32::from_le_bytes(b)]
            .into_iter()
            .filter(|&pg| pg != 0)
            .find_map(|pg| self.read_meta(pg).ok())
    }

    /// Recovery mode: collects records from every leaf page in the file,
    /// ignoring the btree structure (finds data in damaged files, and may
    /// also return stale records from freed pages).
    pub fn salvage(&mut self) -> Vec<Record> {
        let mut out = Vec::new();
        for pg in 1..self.page_count() as u32 {
            let Ok(p) = self.page(pg) else { break };
            if p[25] != P_LBTREE || self.u32_at(p, 8).ok() != Some(pg) {
                continue;
            }
            let mut recs = Vec::new();
            if let Err(e) = self.leaf_records(pg, &mut recs) {
                self.warnings.push(format!("salvage: page {pg}: {e}"));
            }
            // Drop master-database entries (sub-db name -> meta page).
            recs.retain(|(_, v)| self.subdb_meta(v).is_none());
            out.extend(recs);
        }
        out
    }
}
