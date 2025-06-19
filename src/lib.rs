#![no_std]

use pinocchio::{
    program_error::ProgramError, pubkey::Pubkey, sysvars::instructions::IntrospectedInstruction,
};

// Secp256r1SigVerify1111111111111111111111111
pub const SECP256R1_PROGRAM_ID: Pubkey = [
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5, 0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56, 0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
];
pub const SECP256R1_SIGNATURE_LENGTH: usize = 64;
pub const SECP256R1_COMPRESSED_PUBKEY_LENGTH: usize = 33;

pub type Secp256r1Pubkey = [u8; SECP256R1_COMPRESSED_PUBKEY_LENGTH];
pub type Secp256r1Signature = [u8; SECP256R1_SIGNATURE_LENGTH];

pub struct Secp256r1Instruction<'a> {
    header: Secp256r1InstructionHeader,
    offsets: &'a [Secp256r1SignatureOffsets],
    data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for Secp256r1Instruction<'a> {
    type Error = ProgramError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        // We can skip this check, as it's done by the Secp256r1 Program
        #[cfg(not(feature = "perf"))]
        if data.len() < 2 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let header: Secp256r1InstructionHeader = unsafe { core::mem::transmute([data[0]]) };

        #[cfg(not(feature = "perf"))]
        if data.len()
            < 2 + (header.num_signatures as usize
                * core::mem::size_of::<Secp256r1SignatureOffsets>())
        {
            return Err(ProgramError::InvalidInstructionData);
        }

        let offsets = unsafe {
            core::slice::from_raw_parts::<Secp256r1SignatureOffsets>(
                data.as_ptr().add(2) as *const Secp256r1SignatureOffsets,
                header.num_signatures as usize,
            )
        };

        Ok(Secp256r1Instruction {
            header,
            offsets,
            data,
        })
    }
}

impl<'a> TryFrom<&'a IntrospectedInstruction<'a>> for Secp256r1Instruction<'a> {
    type Error = ProgramError;

    fn try_from(ix: &'a IntrospectedInstruction<'a>) -> Result<Self, Self::Error> {
        if SECP256R1_PROGRAM_ID.ne(ix.get_program_id()) {
            return Err(ProgramError::IncorrectProgramId);
        }
        Self::try_from(ix.get_instruction_data())
    }
}

#[repr(C, packed)]
pub struct Secp256r1InstructionHeader {
    pub num_signatures: u8,
}

#[repr(C, packed)]
pub struct Secp256r1SignatureOffsets {
    pub signature_offset: u16,
    pub signature_instruction_index: u16,
    pub public_key_offset: u16,
    pub public_key_instruction_index: u16,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u16,
}

impl<'a> Secp256r1Instruction<'a> {
    /// Get the number of signatures in this instruction
    #[inline(always)]
    pub fn num_signatures(&self) -> u8 {
        self.header.num_signatures
    }

    /// Get the signer (public key) at the specified index
    #[inline(always)]
    pub fn get_signer(&self, index: usize) -> Result<&Secp256r1Pubkey, ProgramError> {
        if index >= self.header.num_signatures as usize {
            return Err(ProgramError::InvalidArgument);
        }

        unsafe { self.get_signer_unchecked(index) }
    }

    /// Get the signature at the specified index
    #[inline(always)]
    pub fn get_signature(&self, index: usize) -> Result<&Secp256r1Signature, ProgramError> {
        if index >= self.header.num_signatures as usize {
            return Err(ProgramError::InvalidArgument);
        }

        unsafe { self.get_signature_unchecked(index) }
    }

    /// Get the message data at the specified index
    #[inline(always)]
    pub fn get_message_data(&self, index: usize) -> Result<&[u8], ProgramError> {
        if index >= self.header.num_signatures as usize {
            return Err(ProgramError::InvalidArgument);
        }

        unsafe { self.get_message_data_unchecked(index) }
    }

    /// Unsafe version - get signer without bounds checking
    ///
    /// # Safety
    ///
    /// The caller must ensure that `index < self.num_signatures()`
    #[inline(always)]
    pub unsafe fn get_signer_unchecked(
        &self,
        index: usize,
    ) -> Result<&Secp256r1Pubkey, ProgramError> {
        let offset = &self.offsets[index];

        // Only support local instruction data for now
        if offset.public_key_instruction_index != u16::MAX {
            return Err(ProgramError::InvalidInstructionData);
        }

        offset.get_signer(self.data)
    }

    /// Unsafe version - get signature without bounds checking
    ///
    /// # Safety
    ///
    /// The caller must ensure that `index < self.num_signatures()`
    #[inline(always)]
    pub unsafe fn get_signature_unchecked(
        &self,
        index: usize,
    ) -> Result<&Secp256r1Signature, ProgramError> {
        let offset = &self.offsets[index];

        // Only support local instruction data for now
        if offset.signature_instruction_index != u16::MAX {
            return Err(ProgramError::InvalidInstructionData);
        }

        offset.get_signature(self.data)
    }

    /// Unsafe version - get message data without bounds checking
    ///
    /// # Safety
    ///
    /// The caller must ensure that `index < self.num_signatures()`
    #[inline(always)]
    pub unsafe fn get_message_data_unchecked(&self, index: usize) -> Result<&[u8], ProgramError> {
        let offset = &self.offsets[index];

        // Only support local instruction data for now
        if offset.message_instruction_index != u16::MAX {
            return Err(ProgramError::InvalidInstructionData);
        }

        offset.get_message_data(self.data)
    }
}

impl Secp256r1SignatureOffsets {
    /// Get the public key from local instruction data
    #[inline(always)]
    pub fn get_signer(&self, data: &[u8]) -> Result<&Secp256r1Pubkey, ProgramError> {
        let start = self.public_key_offset as usize;
        let end = start + SECP256R1_COMPRESSED_PUBKEY_LENGTH;

        if end > data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let slice = &data[start..end];
        Ok(unsafe { &*(slice.as_ptr() as *const Secp256r1Pubkey) })
    }

    /// Get the signature from local instruction data
    #[inline(always)]
    pub fn get_signature(&self, data: &[u8]) -> Result<&Secp256r1Signature, ProgramError> {
        let start = self.signature_offset as usize;
        let end = start + SECP256R1_SIGNATURE_LENGTH;

        if end > data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let slice = &data[start..end];
        Ok(unsafe { &*(slice.as_ptr() as *const Secp256r1Signature) })
    }

    /// Get the message data from local instruction data
    #[inline(always)]
    pub fn get_message_data<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], ProgramError> {
        let start = self.message_data_offset as usize;
        let end = start + self.message_data_size as usize;

        if end > data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(&data[start..end])
    }

    /// Get the public key from local instruction data without bounds checking
    ///
    /// # Safety
    ///
    /// The caller must ensure that the offset and length are within bounds of the data
    #[inline(always)]
    pub unsafe fn get_signer_unchecked(&self, data: &[u8]) -> &Secp256r1Pubkey {
        let start = self.public_key_offset as usize;
        let slice = &data[start..start + SECP256R1_COMPRESSED_PUBKEY_LENGTH];
        unsafe { &*(slice.as_ptr() as *const Secp256r1Pubkey) }
    }

    /// Get the signature from local instruction data without bounds checking
    ///
    /// # Safety
    ///
    /// The caller must ensure that the offset and length are within bounds of the data
    #[inline(always)]
    pub unsafe fn get_signature_unchecked(&self, data: &[u8]) -> &Secp256r1Signature {
        let start = self.signature_offset as usize;
        let slice = &data[start..start + SECP256R1_SIGNATURE_LENGTH];
        unsafe { &*(slice.as_ptr() as *const Secp256r1Signature) }
    }

    /// Get the message data from local instruction data without bounds checking
    ///
    /// # Safety
    ///
    /// The caller must ensure that the offset and length are within bounds of the data
    #[inline(always)]
    pub unsafe fn get_message_data_unchecked<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let start = self.message_data_offset as usize;
        let end = start + self.message_data_size as usize;
        &data[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const TEST_DATA: [u8; 309] = [
        // Header
        0x01, 0x00, // Num signatures
        // Offsets
        0x31, 0x00, // Offset to signature (49 bytes)
        0xff, 0xff, // Current IX (u16::MAX)
        0x10, 0x00, // Offset to pubkey (16 bytes)
        0xff, 0xff, // Current IX (u16::MAX)
        0x71, 0x00, // Offset to message data (113)
        0xc4, 0x00, // Message data size (196 bytes)
        0xff, 0xff, // Current IX (u16::MAX)
        // Odd compressed pubkey
        0x03, 0x2e, 0x9c, 0xc2, 0x5f, 0xeb, 0xa1, 0x9f, 0x5c, 0xc1, 0x14, 0xf6, 0xed, 0xdd, 0x26,
        0xa7, 0x2b, 0x85, 0x54, 0x0a, 0x8b, 0xbd, 0x8f, 0xf0, 0x27, 0x8e, 0x20, 0x7b, 0xa8, 0xf1,
        0x75, 0xd0, 0xf4, // Signature
        0x9c, 0xa7, 0xc8, 0xb9, 0xc3, 0xc7, 0x16, 0x0a, 0x56, 0xb9, 0x1e, 0x38, 0xd8, 0x39, 0x9f,
        0xb6, 0x12, 0x54, 0x2e, 0xb4, 0x63, 0xac, 0xa5, 0x85, 0x5e, 0xfb, 0xda, 0xa4, 0x5c, 0xc3,
        0x4e, 0x31, 0x5c, 0x2b, 0x7d, 0x4d, 0x24, 0x32, 0x47, 0xfb, 0xdc, 0x4a, 0x1c, 0x26, 0xd7,
        0xbe, 0x31, 0xc0, 0xcf, 0x57, 0xdb, 0xe7, 0xad, 0x27, 0xeb, 0xe2, 0x96, 0x1f, 0x2f, 0xb1,
        0xf8, 0x5d, 0x89, 0xe0, // Message data
        0x3e, 0x96, 0x6b, 0x97, 0xe5, 0xaa, 0xb7, 0xe3, 0x85, 0x7c, 0x1a, 0x72, 0xcb, 0x64, 0xab,
        0x68, 0xdd, 0x66, 0xec, 0xb4, 0xf4, 0x19, 0x93, 0x91, 0xc0, 0x60, 0x3b, 0xfb, 0xab, 0xa3,
        0x62, 0x43, 0x45, 0x00, 0x00, 0x00, 0x00, 0xb5, 0x39, 0x76, 0x66, 0x48, 0x85, 0xaa, 0x6b,
        0xce, 0xbf, 0xe5, 0x22, 0x62, 0xa4, 0x39, 0xa2, 0x00, 0x20, 0x58, 0xe3, 0xf5, 0x0a, 0x39,
        0xfe, 0x01, 0x25, 0xca, 0xec, 0x5b, 0x4c, 0x91, 0x79, 0xaf, 0xd9, 0x39, 0x2b, 0x62, 0xcb,
        0xc1, 0x2f, 0xbe, 0x82, 0x01, 0xd6, 0x91, 0x49, 0x7f, 0xba, 0x9d, 0x31, 0xa5, 0x01, 0x02,
        0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x2e, 0x9c, 0xc2, 0x5f, 0xeb, 0xa1, 0x9f, 0x5c,
        0xc1, 0x14, 0xf6, 0xed, 0xdd, 0x26, 0xa7, 0x2b, 0x85, 0x54, 0x0a, 0x8b, 0xbd, 0x8f, 0xf0,
        0x27, 0x8e, 0x20, 0x7b, 0xa8, 0xf1, 0x75, 0xd0, 0xf4, 0x22, 0x58, 0x20, 0x9c, 0x73, 0x0d,
        0x51, 0x6c, 0xf4, 0xba, 0x70, 0xa6, 0x6c, 0x36, 0x71, 0xeb, 0x99, 0x36, 0xd4, 0x3f, 0xe3,
        0x52, 0x78, 0x46, 0xaa, 0x73, 0x27, 0x54, 0x5b, 0x94, 0x10, 0xe4, 0x3d, 0xd1, 0xbd, 0x0e,
        0xf8, 0xaf, 0xa5, 0xef, 0xb5, 0x28, 0x2e, 0xac, 0xb0, 0xdd, 0x6c, 0x51, 0x8b, 0x2b, 0xeb,
        0xa0, 0xe6, 0x70, 0x6c, 0xbf, 0xbb, 0xde, 0x79, 0x03, 0x12, 0x5f, 0x66, 0x6c, 0x38, 0xda,
        0xad,
    ];

    #[test]
    fn test_parse_instruction() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();
        assert_eq!(secp_ix.num_signatures(), 1);
    }

    #[test]
    fn test_get_signer() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();

        // Test getting signer from local instruction
        let signer = secp_ix.get_signer(0).unwrap();

        // Verify the first byte is 0x03 (odd compressed pubkey)
        assert_eq!(signer[0], 0x03);

        // Verify the rest of the pubkey matches
        let expected_pubkey = &TEST_DATA[16..49]; // pubkey starts at offset 16
        assert_eq!(&signer[..], expected_pubkey);
    }

    #[test]
    fn test_get_signature() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();

        // Test getting signature from local instruction
        let signature = secp_ix.get_signature(0).unwrap();

        // Verify signature matches expected data
        let expected_signature = &TEST_DATA[49..113]; // signature starts at offset 49
        assert_eq!(&signature[..], expected_signature);
        assert_eq!(signature.len(), SECP256R1_SIGNATURE_LENGTH);
    }

    #[test]
    fn test_get_message_data() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();

        // Test getting message data from local instruction
        let message_data = secp_ix.get_message_data(0).unwrap();

        // Verify message data matches expected data
        let expected_message_data = &TEST_DATA[113..309]; // message data starts at offset 113
        assert_eq!(message_data, expected_message_data);
        assert_eq!(message_data.len(), 196); // 0xC4 from test data
    }

    #[test]
    fn test_unsafe_methods() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();

        // Test unsafe methods - should work the same as safe methods for valid indices
        unsafe {
            let signer = secp_ix.get_signer_unchecked(0).unwrap();
            let signature = secp_ix.get_signature_unchecked(0).unwrap();
            let message_data = secp_ix.get_message_data_unchecked(0).unwrap();

            assert_eq!(signer[0], 0x03);
            assert_eq!(signature.len(), SECP256R1_SIGNATURE_LENGTH);
            assert_eq!(message_data.len(), 196);
        }
    }

    #[test]
    fn test_bounds_checking() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();

        // Test that out of bounds access returns error
        assert!(secp_ix.get_signer(1).is_err()); // Only 1 signature (index 0)
        assert!(secp_ix.get_signature(1).is_err());
        assert!(secp_ix.get_message_data(1).is_err());
    }

    #[test]
    fn test_invalid_instruction_data() {
        // Test with too short data
        let short_data = [0x01];
        assert!(Secp256r1Instruction::try_from(&short_data[..]).is_err());

        // Test with inconsistent header
        let bad_header = [0x02, 0x00]; // Claims 2 signatures but no offset data
        assert!(Secp256r1Instruction::try_from(&bad_header[..]).is_err());
    }

    #[test]
    fn test_offset_methods_directly() {
        let secp_ix = Secp256r1Instruction::try_from(&TEST_DATA[..]).unwrap();
        let offset = &secp_ix.offsets[0];

        // Test offset methods directly
        let signer = offset.get_signer(secp_ix.data).unwrap();
        let signature = offset.get_signature(secp_ix.data).unwrap();
        let message_data = offset.get_message_data(secp_ix.data).unwrap();

        assert_eq!(signer[0], 0x03);
        assert_eq!(signature.len(), SECP256R1_SIGNATURE_LENGTH);
        assert_eq!(message_data.len(), 196);

        // Test unsafe versions
        unsafe {
            let signer = offset.get_signer_unchecked(secp_ix.data);
            let signature = offset.get_signature_unchecked(secp_ix.data);
            let message_data = offset.get_message_data_unchecked(secp_ix.data);

            assert_eq!(signer[0], 0x03);
            assert_eq!(signature.len(), SECP256R1_SIGNATURE_LENGTH);
            assert_eq!(message_data.len(), 196);
        }
    }
}
