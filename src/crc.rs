use super::bundle::*;

/******************************
 *
 * CRC
 *
 ******************************/

pub type CrcRawType = u8;

use crc::{CRC_16_IBM_SDLC, CRC_32_ISCSI, Crc, Table};

// slice-by-16 lookup tables are several times faster than the default byte-wise table
pub const X25: Crc<u16, Table<16>> = Crc::<u16, Table<16>>::new(&CRC_16_IBM_SDLC);
pub const CASTAGNOLI: Crc<u32, Table<16>> = Crc::<u32, Table<16>>::new(&CRC_32_ISCSI);

#[derive(Debug, Clone, PartialEq, Default)]
pub enum CrcValue {
    #[default]
    CrcNo,
    Crc16Empty,
    Crc32Empty,
    Crc16([u8; 2]),
    Crc32([u8; 4]),
    Unknown(CrcRawType),
}

impl CrcValue {
    pub fn has_crc(&self) -> bool {
        // TODO: handle unknown
        *self != CrcValue::CrcNo
    }
    pub fn to_code(&self) -> CrcRawType {
        match self {
            CrcValue::CrcNo => CRC_NO,
            CrcValue::Crc16(_) => CRC_16,
            CrcValue::Crc16Empty => CRC_16,
            CrcValue::Crc32(_) => CRC_32,
            CrcValue::Crc32Empty => CRC_32,
            CrcValue::Unknown(code) => *code,
        }
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            CrcValue::Unknown(_) => None,
            CrcValue::CrcNo => None,
            CrcValue::Crc16(buf) => Some(buf),
            CrcValue::Crc16Empty => Some(&CRC16_EMPTY),
            CrcValue::Crc32(buf) => Some(buf),
            CrcValue::Crc32Empty => Some(&CRC32_EMPTY),
        }
    }
}
pub(crate) const CRC16_EMPTY: [u8; 2] = [0; 2];
pub(crate) const CRC32_EMPTY: [u8; 4] = [0; 4];

pub const CRC_NO: CrcRawType = 0;
pub const CRC_16: CrcRawType = 1;
pub const CRC_32: CrcRawType = 2;

pub trait CRCFuncations {
    fn to_string(self) -> String;
}
impl CRCFuncations for CrcRawType {
    fn to_string(self) -> String {
        match self {
            CRC_NO => String::from("no"),
            CRC_16 => String::from("16"),
            CRC_32 => String::from("32"),
            _ => String::from("unknown"),
        }
    }
}

pub trait CrcBlock: Block + Clone {
    /// Convert block struct to a serializable enum
    fn has_crc(&self) -> bool {
        self.crc_value().has_crc()
    }
    /// Recalculate crc value
    fn update_crc(&mut self) {
        let new_crc = calculate_crc(self);
        self.set_crc(new_crc);
    }
    /// Check if crc value is valid
    fn check_crc(&self) -> bool {
        check_crc(self)
    }
    /// Reset crc field to an empty value
    fn reset_crc(&mut self) {
        if self.has_crc() {
            match self.crc_value() {
                CrcValue::Crc16(_) => self.set_crc(CrcValue::Crc16Empty),
                CrcValue::Crc32(_) => self.set_crc(CrcValue::Crc32Empty),
                _ => {}
            }
        }
    }
    /// Returns raw crc checksum
    fn crc(&self) -> Option<&[u8]> {
        self.crc_value().bytes()
    }
    /// Set crc type
    /// CRC_NO, CRC_16, CRC_32
    fn set_crc_type(&mut self, crc_value: CrcRawType) {
        if crc_value == CRC_NO {
            self.set_crc(CrcValue::CrcNo);
        } else if crc_value == CRC_16 {
            self.set_crc(CrcValue::Crc16Empty);
        } else if crc_value == CRC_32 {
            self.set_crc(CrcValue::Crc32Empty);
        } else {
            self.set_crc(CrcValue::Unknown(crc_value));
        }
    }
    /// Return the crc type code
    fn crc_type(&self) -> CrcRawType {
        self.crc_value().to_code()
    }
    fn crc_value(&self) -> &CrcValue;
    fn set_crc(&mut self, crc: CrcValue);
}

/// Feeds the encoding of a block into a crc digest, replacing the trailing crc value
/// of `n` bytes by zeros. This is the crc input without cloning the block or buffering
/// its encoding, as the crc value is always the last element of a block and of fixed size.
struct CrcWriter<F: FnMut(&[u8])> {
    update: F,
    n: usize,
    tail: [u8; 4],
    tail_len: usize,
}

impl<F: FnMut(&[u8])> CrcWriter<F> {
    fn new(n: usize, update: F) -> Self {
        CrcWriter {
            update,
            n,
            tail: [0; 4],
            tail_len: 0,
        }
    }
    /// Feed zeros in place of the held back crc value
    fn finish(mut self) {
        (self.update)(&[0; 4][..self.n]);
    }
}

impl<F: FnMut(&[u8])> std::io::Write for CrcWriter<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let total = self.tail_len + buf.len();
        if total <= self.n {
            self.tail[self.tail_len..total].copy_from_slice(buf);
            self.tail_len = total;
            return Ok(buf.len());
        }
        // pass on everything but the last n bytes
        let emit = total - self.n;
        let from_tail = emit.min(self.tail_len);
        let from_buf = emit - from_tail;
        (self.update)(&self.tail[..from_tail]);
        (self.update)(&buf[..from_buf]);

        let mut tail = [0; 4];
        let kept = self.tail_len - from_tail;
        tail[..kept].copy_from_slice(&self.tail[from_tail..self.tail_len]);
        tail[kept..self.n].copy_from_slice(&buf[from_buf..]);
        self.tail = tail;
        self.tail_len = self.n;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn calculate_crc<T: CrcBlock + Block>(blck: &T) -> CrcValue {
    match blck.crc_type() {
        CRC_NO => CrcValue::CrcNo,
        CRC_16 => {
            let mut digest = X25.digest();
            let mut writer = CrcWriter::new(2, |data| digest.update(data));
            blck.write_cbor(&mut writer)
                .expect("Error encoding block for crc calculation");
            writer.finish();
            CrcValue::Crc16(digest.finalize().to_be_bytes())
        }
        CRC_32 => {
            let mut digest = CASTAGNOLI.digest();
            let mut writer = CrcWriter::new(4, |data| digest.update(data));
            blck.write_cbor(&mut writer)
                .expect("Error encoding block for crc calculation");
            writer.finish();
            CrcValue::Crc32(digest.finalize().to_be_bytes())
        }
        _ => {
            // unknown crc types cannot be calculated, keep the value as is
            blck.crc_value().clone()
        }
    }
}
pub fn check_crc<T: CrcBlock + Block>(blck: &T) -> bool {
    match blck.crc_value() {
        CrcValue::CrcNo => true,
        // unknown crc types cannot be verified
        CrcValue::Unknown(_) => false,
        _ => calculate_crc(blck).bytes() == blck.crc(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn crc_writer_tests() {
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        for n in [2, 4] {
            let mut expected = data.clone();
            let len = expected.len();
            expected[len - n..].fill(0);
            let expected = CASTAGNOLI.checksum(&expected);

            // all chunk sizes, including writes shorter than the held back tail
            for chunk in [1, 2, 3, 4, 5, 7, 64, 999, 1000] {
                let mut digest = CASTAGNOLI.digest();
                let mut writer = CrcWriter::new(n, |d| digest.update(d));
                for part in data.chunks(chunk) {
                    writer.write_all(part).unwrap();
                }
                writer.finish();
                assert_eq!(digest.finalize(), expected, "n {} chunk {}", n, chunk);
            }
        }
    }
}
