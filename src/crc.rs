use super::bundle::*;

/******************************
 *
 * CRC
 *
 ******************************/

pub type CrcRawType = u8;

use crc::{Crc, CRC_16_IBM_SDLC, CRC_32_ISCSI};

pub const X25: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_SDLC);
pub const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

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
    fn check_crc(&mut self) -> bool {
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

pub fn calculate_crc<T: CrcBlock + Block>(blck: &mut T) -> CrcValue {
    match blck.crc_type() {
        CRC_NO => CrcValue::CrcNo,
        CRC_16 => {
            let crc_bak = blck.crc_value().clone(); // Backup original crc
            blck.reset_crc(); // set empty crc
            let data = blck.to_cbor(); // TODO: optimize this encoding away
                                       // also tried crc16 crate, not a bit faster
            let chksm = X25.checksum(&data);
            let output_crc = chksm.to_be_bytes();
            blck.set_crc(crc_bak); // restore orginal crc
            CrcValue::Crc16(output_crc)
        }
        CRC_32 => {
            let crc_bak = blck.crc_value().clone(); // Backup original crc
            blck.reset_crc(); // set empty crc
            let data = blck.to_cbor(); // TODO: optimize this encoding away
                                       // also tried crc32fast, was not significantly faster
            let chksm = CASTAGNOLI.checksum(&data);
            let output_crc = chksm.to_be_bytes();
            blck.set_crc(crc_bak); // restore orginal crc
            CrcValue::Crc32(output_crc)
        }
        _ => {
            panic!("Unknown crc type");
        }
    }
}
pub fn check_crc<T: CrcBlock + Block>(blck: &mut T) -> bool {
    if !blck.has_crc() {
        return !blck.has_crc();
    }
    calculate_crc(blck).bytes() == blck.crc()
}
