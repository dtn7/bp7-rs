use crate::error::{Error, ErrorList};
use bitflags::bitflags;

/******************************
 *
 * Block Control Flags
 *
 ******************************/

pub type BlockControlFlagsType = u8;

bitflags! {
    pub struct BlockControlFlags: BlockControlFlagsType {
        /// This block must be replicated in every fragment.
        const BLOCK_REPLICATE = 0x01;

        /// Transmit status report if block can't be processed.
        const BLOCK_STATUS_REPORT = 0x02;

        /// Deleted bundle if block can't be processed.
        const BLOCK_DELETE_BUNDLE = 0x04;

        /// Discard block if it can't be processed.
        const BLOCK_REMOVE = 0x10;

        const BLOCK_CFRESERVED_FIELDS = 0xF0;
    }
}

pub trait BlockValidation {
    fn flags(&self) -> BlockControlFlags;

    fn validate(&self) -> Result<(), Error>
    where
        Self: Sized,
    {
        if self
            .flags()
            .contains(BlockControlFlags::BLOCK_CFRESERVED_FIELDS)
        {
            Err(Error::BlockControlFlagsError(
                "Given flag contains reserved bits".to_string(),
            ))
        } else {
            Ok(())
        }
    }
    fn contains(&self, flags: BlockControlFlags) -> bool
    where
        Self: Sized,
    {
        self.flags().contains(flags)
    }
    fn set(&mut self, flags: BlockControlFlags);
}
impl BlockValidation for BlockControlFlagsType {
    fn flags(&self) -> BlockControlFlags {
        BlockControlFlags::from_bits_truncate(*self)
    }
    fn set(&mut self, flags: BlockControlFlags)
    where
        Self: Sized,
    {
        *self = flags.bits();
    }
}
/******************************
 *
 * Bundle Control Flags
 *
 ******************************/

pub type BundleControlFlagsType = u64;

bitflags! {
    #[derive(Default)]
    pub struct BundleControlFlags: BundleControlFlagsType {

/// Request reporting of bundle deletion.
    const BUNDLE_STATUS_REQUEST_DELETION = 0x040000;

/// Request reporting of bundle delivery.
    const BUNDLE_STATUS_REQUEST_DELIVERY = 0x020000;

/// Request reporting of bundle forwarding.
    const BUNDLE_STATUS_REQUEST_FORWARD = 0x010000;

/// Request reporting of bundle reception.
    const BUNDLE_STATUS_REQUEST_RECEPTION = 0x004000;

/// Status time requested in reports.
    const BUNDLE_REQUEST_STATUS_TIME = 0x000040;

/// Acknowledgment by application is requested.
    const BUNDLE_REQUEST_USER_APPLICATION_ACK = 0x000020;

/// Bundle must not be fragmented.
    const BUNDLE_MUST_NOT_FRAGMENTED = 0x000004;

/// ADU is an administrative record.
    const BUNDLE_ADMINISTRATIVE_RECORD_PAYLOAD = 0x000002;

/// The bundle is a fragment.
    const BUNDLE_IS_FRAGMENT = 0x000001;

    const BUNDLE_CFRESERVED_FIELDS = 0xE218;
    }
}

pub trait BundleValidation {
    fn flags(&self) -> BundleControlFlags;
    fn contains(&self, flags: BundleControlFlags) -> bool
    where
        Self: Sized,
    {
        self.flags().contains(flags)
    }
    fn set(&mut self, flags: BundleControlFlags);
    fn validate(&self) -> Result<(), ErrorList>
    where
        Self: Sized,
    {
        let mut errors: ErrorList = Vec::new();
        let flags = self.flags();
        if flags.contains(BundleControlFlags::BUNDLE_CFRESERVED_FIELDS) {
            errors.push(Error::BundleControlFlagsError(
                "Given flag contains reserved bits".to_string(),
            ));
        }

        let admin_rec_check = !flags
            .contains(BundleControlFlags::BUNDLE_ADMINISTRATIVE_RECORD_PAYLOAD)
            || (!flags.contains(BundleControlFlags::BUNDLE_STATUS_REQUEST_RECEPTION)
                && !flags.contains(BundleControlFlags::BUNDLE_STATUS_REQUEST_FORWARD)
                && !flags.contains(BundleControlFlags::BUNDLE_STATUS_REQUEST_DELIVERY)
                && !flags.contains(BundleControlFlags::BUNDLE_STATUS_REQUEST_DELETION));
        if !admin_rec_check {
            errors.push(Error::BundleControlFlagsError(
                "\"payload is administrative record => no status report request flags\" failed"
                    .to_string(),
            ))
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }
}

impl BundleValidation for BundleControlFlagsType {
    fn flags(&self) -> BundleControlFlags {
        BundleControlFlags::from_bits_truncate(*self)
    }
    fn set(&mut self, flags: BundleControlFlags)
    where
        Self: Sized,
    {
        *self = flags.bits();
    }
}
