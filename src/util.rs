//! Small helpers: bitcoin serialization reader, hex and time formatting.

use std::fmt::Write;

/// Cursor over bitcoin-serialized data.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

pub type RResult<T> = Result<T, String>;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, n: usize) -> RResult<&'a [u8]> {
        if n > self.remaining() {
            return Err(format!("need {n} bytes, only {} left", self.remaining()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> RResult<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn u8(&mut self) -> RResult<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> RResult<bool> {
        Ok(self.u8()? != 0)
    }

    pub fn u32(&mut self) -> RResult<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn i32(&mut self) -> RResult<i32> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> RResult<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn i64(&mut self) -> RResult<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub fn compact(&mut self) -> RResult<u64> {
        Ok(match self.u8()? {
            n @ 0..=252 => n as u64,
            253 => u16::from_le_bytes(self.array()?) as u64,
            254 => self.u32()? as u64,
            255 => self.u64()?,
        })
    }

    /// Length-prefixed byte vector.
    pub fn bytes(&mut self) -> RResult<&'a [u8]> {
        let n = self.compact()?;
        if n > self.remaining() as u64 {
            return Err(format!("vector of {n} bytes, only {} left", self.remaining()));
        }
        self.take(n as usize)
    }

    /// Length-prefixed string (lossy UTF-8).
    pub fn string(&mut self) -> RResult<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Hex of a hash displayed the bitcoin way (byte-reversed), e.g. txids.
pub fn hex_rev(b: &[u8]) -> String {
    let mut v = b.to_vec();
    v.reverse();
    hex(&v)
}

/// Formats a unix timestamp as `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn fmt_time(t: i64) -> String {
    if t <= 0 {
        return "-".into();
    }
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time() {
        assert_eq!(fmt_time(1231006505), "2009-01-03 18:15:05");
        assert_eq!(fmt_time(951782400), "2000-02-29 00:00:00");
    }

    #[test]
    fn compact() {
        let mut r = Reader::new(&[0xfd, 0x34, 0x12, 0x05]);
        assert_eq!(r.compact().unwrap(), 0x1234);
        assert_eq!(r.compact().unwrap(), 5);
        assert!(r.is_empty());
    }
}
