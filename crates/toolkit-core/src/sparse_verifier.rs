use crate::error::{FlashrustError, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const SPARSE_HEADER_MAGIC: u32 = 0xED26_FF3A;
pub const SPARSE_HEADER_SIZE: u16 = 28;
pub const SPARSE_CHUNK_HEADER_MIN_SIZE: u16 = 12;

pub const CHUNK_TYPE_RAW: u16 = 0xCAC1;
pub const CHUNK_TYPE_FILL: u16 = 0xCAC2;
pub const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
pub const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

pub const AVB_VBMETA_MAGIC: &[u8; 4] = b"AVB0";
pub const AVB_VBMETA_HEADER_SIZE: usize = 256;
pub const AVB_FLAG_HASHTREE_DISABLED: u32 = 1 << 0;
pub const AVB_FLAG_VERIFICATION_DISABLED: u32 = 1 << 1;

/// Compile-time generated 256-entry IEEE 802.3 CRC32 lookup table (polynomial 0xEDB88320).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Zero-allocation streaming IEEE 802.3 CRC32 hasher.
#[derive(Debug, Clone, Copy)]
pub struct Crc32Hasher {
    state: u32,
}

impl Default for Crc32Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32Hasher {
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.state;
        for &b in bytes {
            let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[idx];
        }
        self.state = crc;
    }

    pub fn update_zeros(&mut self, mut len: u64) {
        const ZERO_BUF: [u8; 4096] = [0u8; 4096];
        while len > 0 {
            let step = (len.min(ZERO_BUF.len() as u64)) as usize;
            self.update(&ZERO_BUF[..step]);
            len -= step as u64;
        }
    }

    pub const fn finalize(self) -> u32 {
        !self.state
    }
}

/// FIPS 180-4 SHA-256 round constants.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Zero-allocation streaming FIPS 180-4 SHA-256 state machine.
#[derive(Debug, Clone)]
pub struct Sha256Hasher {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if input.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
            self.buffer[self.buffer_len..64].copy_from_slice(&input[..needed]);
            Self::compress_block(&mut self.state, &self.buffer);
            self.buffer_len = 0;
            input = &input[needed..];
        }

        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            Self::compress_block(&mut self.state, &block);
            input = &input[64..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    pub fn finalize_hex(mut self) -> String {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for b in &mut self.buffer[self.buffer_len..64] {
                *b = 0;
            }
            Self::compress_block(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }

        for b in &mut self.buffer[self.buffer_len..56] {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress_block(&mut self.state, &self.buffer);

        let mut out = String::with_capacity(64);
        for word in self.state {
            for byte in word.to_be_bytes() {
                out.push_str(&format!("{:02x}", byte));
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_hdr_sz: u16,
    pub chunk_hdr_sz: u16,
    pub blk_sz: u32,
    pub total_blks: u32,
    pub total_chunks: u32,
    pub image_checksum: u32,
}

impl SparseHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SPARSE_HEADER_SIZE as usize {
            return Err(FlashrustError::BufferTooSmall {
                expected: SPARSE_HEADER_SIZE as usize,
                actual: bytes.len(),
            });
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != SPARSE_HEADER_MAGIC {
            return Err(FlashrustError::StorageValidationError(format!(
                "Invalid Android Sparse magic: expected 0x{:08X}, got 0x{:08X}",
                SPARSE_HEADER_MAGIC, magic
            )));
        }
        let major_version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let minor_version = u16::from_le_bytes([bytes[6], bytes[7]]);
        let file_hdr_sz = u16::from_le_bytes([bytes[8], bytes[9]]);
        let chunk_hdr_sz = u16::from_le_bytes([bytes[10], bytes[11]]);
        let blk_sz = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let total_blks = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let total_chunks = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let image_checksum = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);

        if major_version != 1 {
            return Err(FlashrustError::StorageValidationError(format!(
                "Unsupported sparse major version: {}",
                major_version
            )));
        }
        if file_hdr_sz < SPARSE_HEADER_SIZE || chunk_hdr_sz < SPARSE_CHUNK_HEADER_MIN_SIZE {
            return Err(FlashrustError::StorageValidationError(
                "Malformed sparse header sizes".into(),
            ));
        }
        if blk_sz == 0 || !blk_sz.is_multiple_of(4) {
            return Err(FlashrustError::StorageValidationError(format!(
                "Invalid sparse block size: {}",
                blk_sz
            )));
        }

        Ok(Self {
            magic,
            major_version,
            minor_version,
            file_hdr_sz,
            chunk_hdr_sz,
            blk_sz,
            total_blks,
            total_chunks,
            image_checksum,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageChecksumResult {
    pub is_sparse: bool,
    pub logical_size_bytes: u64,
    pub payload_bytes_read: u64,
    pub total_chunks: u32,
    pub crc32: u32,
    pub sha256: String,
}

pub struct SparseImageVerifier;

impl SparseImageVerifier {
    /// Verify an Android sparse image or raw partition image from an in-memory slice.
    pub fn verify_bytes(data: &[u8]) -> Result<ImageChecksumResult> {
        if data.len() >= 4 {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if magic == SPARSE_HEADER_MAGIC {
                return Self::verify_sparse_bytes(data);
            }
        }
        let mut crc = Crc32Hasher::new();
        let mut sha = Sha256Hasher::new();
        crc.update(data);
        sha.update(data);
        Ok(ImageChecksumResult {
            is_sparse: false,
            logical_size_bytes: data.len() as u64,
            payload_bytes_read: data.len() as u64,
            total_chunks: 1,
            crc32: crc.finalize(),
            sha256: sha.finalize_hex(),
        })
    }

    /// Stream-verify a file on disk without loading multi-gigabyte raw images into RAM.
    pub fn verify_file(path: &Path) -> Result<ImageChecksumResult> {
        let mut file = File::open(path).map_err(|e| FlashrustError::IoError(e.to_string()))?;
        let mut prefix = [0u8; 28];
        let read_n = file
            .read(&mut prefix)
            .map_err(|e| FlashrustError::IoError(e.to_string()))?;

        if read_n >= 4 {
            let magic = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
            if magic == SPARSE_HEADER_MAGIC {
                let bytes =
                    std::fs::read(path).map_err(|e| FlashrustError::IoError(e.to_string()))?;
                return Self::verify_sparse_bytes(&bytes);
            }
        }

        // Stream raw file in 64 KiB windows
        let mut file = File::open(path).map_err(|e| FlashrustError::IoError(e.to_string()))?;
        let mut buf = [0u8; 64 * 1024];
        let mut crc = Crc32Hasher::new();
        let mut sha = Sha256Hasher::new();
        let mut total = 0u64;

        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| FlashrustError::IoError(e.to_string()))?;
            if n == 0 {
                break;
            }
            crc.update(&buf[..n]);
            sha.update(&buf[..n]);
            total += n as u64;
        }

        Ok(ImageChecksumResult {
            is_sparse: false,
            logical_size_bytes: total,
            payload_bytes_read: total,
            total_chunks: 1,
            crc32: crc.finalize(),
            sha256: sha.finalize_hex(),
        })
    }

    fn verify_sparse_bytes(data: &[u8]) -> Result<ImageChecksumResult> {
        let header = SparseHeader::parse(data)?;
        let mut cursor = header.file_hdr_sz as usize;
        if cursor > data.len() {
            return Err(FlashrustError::BufferTooSmall {
                expected: cursor,
                actual: data.len(),
            });
        }

        let mut crc = Crc32Hasher::new();
        let mut sha = Sha256Hasher::new();
        let mut logical_blocks_seen = 0u64;
        let mut payload_bytes_read = 0u64;
        let chunk_hdr_sz = header.chunk_hdr_sz as usize;

        for _chunk_idx in 0..header.total_chunks {
            if cursor + chunk_hdr_sz > data.len() {
                return Err(FlashrustError::BufferTooSmall {
                    expected: cursor + chunk_hdr_sz,
                    actual: data.len(),
                });
            }

            let chunk_type = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
            let chunk_sz_blks = u32::from_le_bytes([
                data[cursor + 4],
                data[cursor + 5],
                data[cursor + 6],
                data[cursor + 7],
            ]);
            let total_sz = u32::from_le_bytes([
                data[cursor + 8],
                data[cursor + 9],
                data[cursor + 10],
                data[cursor + 11],
            ]) as usize;

            if total_sz < chunk_hdr_sz || cursor + total_sz > data.len() {
                return Err(FlashrustError::StorageValidationError(
                    "Sparse chunk exceeds image bounds or has invalid total_sz".into(),
                ));
            }

            let payload_start = cursor + chunk_hdr_sz;
            let payload_len = total_sz - chunk_hdr_sz;
            let payload = &data[payload_start..payload_start + payload_len];
            let logical_bytes = (chunk_sz_blks as u64) * (header.blk_sz as u64);

            match chunk_type {
                CHUNK_TYPE_RAW => {
                    if (payload_len as u64) != logical_bytes {
                        return Err(FlashrustError::StorageValidationError(format!(
                            "SPARSE_RAW payload length ({}) != logical block bytes ({})",
                            payload_len, logical_bytes
                        )));
                    }
                    crc.update(payload);
                    sha.update(payload);
                    payload_bytes_read += payload_len as u64;
                    logical_blocks_seen += chunk_sz_blks as u64;
                }
                CHUNK_TYPE_FILL => {
                    if payload_len != 4 {
                        return Err(FlashrustError::StorageValidationError(
                            "SPARSE_FILL chunk must carry exactly 4 fill bytes".into(),
                        ));
                    }
                    let fill_word = [payload[0], payload[1], payload[2], payload[3]];
                    let mut fill_block = [0u8; 4096];
                    for slot in fill_block.as_chunks_mut::<4>().0 {
                        slot.copy_from_slice(&fill_word);
                    }
                    let mut rem = logical_bytes;
                    while rem > 0 {
                        let step = (rem.min(fill_block.len() as u64)) as usize;
                        crc.update(&fill_block[..step]);
                        sha.update(&fill_block[..step]);
                        rem -= step as u64;
                    }
                    logical_blocks_seen += chunk_sz_blks as u64;
                }
                CHUNK_TYPE_DONT_CARE => {
                    if payload_len != 0 {
                        return Err(FlashrustError::StorageValidationError(
                            "SPARSE_DONT_CARE chunk must have 0 payload bytes".into(),
                        ));
                    }
                    crc.update_zeros(logical_bytes);
                    logical_blocks_seen += chunk_sz_blks as u64;
                }
                CHUNK_TYPE_CRC32 => {
                    if payload_len != 4 {
                        return Err(FlashrustError::StorageValidationError(
                            "SPARSE_CRC32 chunk must carry a 4-byte checksum".into(),
                        ));
                    }
                    let expected_chunk_crc =
                        u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let current_crc = crc.finalize();
                    if current_crc != expected_chunk_crc {
                        return Err(FlashrustError::StorageValidationError(format!(
                            "Sparse CRC32 chunk mismatch: expected 0x{:08X}, got 0x{:08X}",
                            expected_chunk_crc, current_crc
                        )));
                    }
                }
                other => {
                    return Err(FlashrustError::StorageValidationError(format!(
                        "Unknown Android Sparse chunk type: 0x{:04X}",
                        other
                    )));
                }
            }

            cursor += total_sz;
        }

        if logical_blocks_seen != header.total_blks as u64 {
            return Err(FlashrustError::StorageValidationError(format!(
                "Sparse total blocks mismatch: header declares {}, chunks sum to {}",
                header.total_blks, logical_blocks_seen
            )));
        }

        let final_crc = crc.finalize();
        if header.image_checksum != 0 && final_crc != header.image_checksum {
            return Err(FlashrustError::StorageValidationError(format!(
                "Sparse header checksum mismatch: expected 0x{:08X}, got 0x{:08X}",
                header.image_checksum, final_crc
            )));
        }

        Ok(ImageChecksumResult {
            is_sparse: true,
            logical_size_bytes: logical_blocks_seen * (header.blk_sz as u64),
            payload_bytes_read,
            total_chunks: header.total_chunks,
            crc32: final_crc,
            sha256: sha.finalize_hex(),
        })
    }
}

/// Android Verified Boot (`vbmeta.img`) metadata summary and flag editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VbmetaSummary {
    pub major_version: u32,
    pub minor_version: u32,
    pub algorithm_type: u32,
    pub rollback_index: u64,
    pub flags: u32,
    pub hashtree_disabled: bool,
    pub verification_disabled: bool,
    pub release_string: String,
}

pub struct VbmetaTools;

impl VbmetaTools {
    /// Inspect an Android Verified Boot `vbmeta.img` header.
    pub fn inspect_vbmeta(bytes: &[u8]) -> Result<VbmetaSummary> {
        if bytes.len() < AVB_VBMETA_HEADER_SIZE {
            return Err(FlashrustError::BufferTooSmall {
                expected: AVB_VBMETA_HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        if &bytes[0..4] != AVB_VBMETA_MAGIC {
            return Err(FlashrustError::StorageValidationError(
                "Invalid AVB vbmeta magic (expected 'AVB0')".into(),
            ));
        }

        let major_version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let minor_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let algorithm_type = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        let rollback_index = u64::from_be_bytes([
            bytes[112], bytes[113], bytes[114], bytes[115], bytes[116], bytes[117], bytes[118],
            bytes[119],
        ]);
        let flags = u32::from_be_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]);

        let release_slice = &bytes[128..176];
        let nul_pos = release_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(release_slice.len());
        let release_string = String::from_utf8_lossy(&release_slice[..nul_pos]).into_owned();

        Ok(VbmetaSummary {
            major_version,
            minor_version,
            algorithm_type,
            rollback_index,
            flags,
            hashtree_disabled: (flags & AVB_FLAG_HASHTREE_DISABLED) != 0,
            verification_disabled: (flags & AVB_FLAG_VERIFICATION_DISABLED) != 0,
            release_string,
        })
    }

    /// Patch `vbmeta.img` in-memory to disable dm-verity and AVB verification when flashing
    /// custom KernelSU / Magisk boot images.
    pub fn patch_disable_verity(bytes: &[u8]) -> Result<(Vec<u8>, VbmetaSummary)> {
        let _ = Self::inspect_vbmeta(bytes)?;
        let mut patched = bytes.to_vec();
        let current_flags =
            u32::from_be_bytes([patched[120], patched[121], patched[122], patched[123]]);
        let new_flags = current_flags | AVB_FLAG_HASHTREE_DISABLED | AVB_FLAG_VERIFICATION_DISABLED;
        patched[120..124].copy_from_slice(&new_flags.to_be_bytes());
        let summary = Self::inspect_vbmeta(&patched)?;
        Ok((patched, summary))
    }
}
