use crate::error::{FlashrustError, Result};
use crate::sparse_verifier::Sha256Hasher;
use crate::zig_bridge::ZigEngine;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const ODIN_HANDSHAKE_REQUEST: &[u8; 4] = b"ODIN";
pub const LOKE_HANDSHAKE_RESPONSE: &[u8; 4] = b"LOKE";
pub const LOKE_CONTROL_PACKET_SIZE: usize = 1024;
pub const PIT_MAGIC_LE: u32 = 0x1234_9876;
pub const AOSP_FRP_HEADER_MARKER: u32 = 0x1990_1873;

/// Primary Odin / Heimdall (Loke) control request opcodes.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LokeRequestType {
    BeginSession = 0x64,    // 100
    PitFileTransfer = 0x65, // 101
    FileTransfer = 0x66,    // 102
    EndSession = 0x67,      // 103
}

/// Samsung Odin 4-slot / 5-slot firmware package roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OdinSlotRole {
    Bl,      // Bootloader (sboot.bin, param.bin, up_param.bin, tz.img)
    Ap, // Application Processor / PDA (boot.img, init_boot.img, recovery.img, super.img, vbmeta.img)
    Cp, // Core Processor / Modem (modem.bin, modem_debug.bin)
    Csc, // Consumer Software Customization - Full Wipe + PIT repartition (cache.img, optics.img, prism.img, *.pit)
    HomeCsc, // Preserves userdata (no factory reset)
}

impl OdinSlotRole {
    pub const ALL: [OdinSlotRole; 5] = [
        OdinSlotRole::Bl,
        OdinSlotRole::Ap,
        OdinSlotRole::Cp,
        OdinSlotRole::Csc,
        OdinSlotRole::HomeCsc,
    ];

    pub fn code(&self) -> &'static str {
        match self {
            OdinSlotRole::Bl => "BL",
            OdinSlotRole::Ap => "AP",
            OdinSlotRole::Cp => "CP",
            OdinSlotRole::Csc => "CSC",
            OdinSlotRole::HomeCsc => "HOME_CSC",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            OdinSlotRole::Bl => "BL (Bootloader / sboot / tz / param)",
            OdinSlotRole::Ap => "AP (System / super / boot / init_boot / vbmeta)",
            OdinSlotRole::Cp => "CP (Modem / Baseband / Radio)",
            OdinSlotRole::Csc => "CSC (Region / PIT / Factory Reset)",
            OdinSlotRole::HomeCsc => "HOME_CSC (Region / Keep Userdata)",
        }
    }
}

/// Samsung Download Mode FRP (Factory Reset Protection) lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrpLockState {
    Off, // FRP LOCK: OFF (Custom binaries allowed if OEM Unlock is ON)
    On, // FRP LOCK: ON  (Bootloader blocks unsigned/custom binaries; only official signed Samsung TARs accepted)
}

impl FrpLockState {
    pub fn label(&self) -> &'static str {
        match self {
            FrpLockState::Off => "FRP LOCK: OFF (Unlocked / Authorized)",
            FrpLockState::On => "FRP LOCK: ON (Enforced - Samsung Signed Only)",
        }
    }
}

/// Samsung Knox Guard (KG) / RMM state reported in Download Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KgLockState {
    Completed, // Standard unlocked/normal state
    Checking,  // Initial network verification pending
    Prenormal, // Blocks custom boot/recovery even if FRP is OFF until 168h uptime + network check
    Locked,    // Enterprise / carrier KG lock active
}

impl KgLockState {
    pub const ALL: [KgLockState; 4] = [
        KgLockState::Completed,
        KgLockState::Checking,
        KgLockState::Prenormal,
        KgLockState::Locked,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            KgLockState::Completed => "KG STATE: Completed / Normal",
            KgLockState::Checking => "KG STATE: Checking",
            KgLockState::Prenormal => "KG STATE: Prenormal (Custom Binaries Restricted)",
            KgLockState::Locked => "KG STATE: Locked (Enterprise Enforced)",
        }
    }
}

/// Parsed entry from a Samsung PIT (Partition Information Table) binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitPartitionEntry {
    pub identifier: u32,
    pub block_offset: u32,
    pub block_count: u32,
    pub partition_name: String,
    pub flash_filename: String,
}

/// Complete parsed Samsung PIT table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PitTable {
    pub gang_name: String,
    pub project_name: String,
    pub entries: Vec<PitPartitionEntry>,
}

impl PitTable {
    /// Parse a binary `.pit` buffer using the Zig bare-metal PIT parser.
    pub fn parse_bytes(data: &[u8]) -> Result<Self> {
        let (count, gang_name, project_name) = ZigEngine::parse_pit_header_raw(data)?;
        let mut entries = Vec::with_capacity(count as usize);
        for idx in 0..(count as usize) {
            let (identifier, block_offset, block_count, partition_name, flash_filename) =
                ZigEngine::parse_pit_entry_raw(data, idx)?;
            entries.push(PitPartitionEntry {
                identifier,
                block_offset,
                block_count,
                partition_name,
                flash_filename,
            });
        }
        Ok(Self {
            gang_name,
            project_name,
            entries,
        })
    }

    /// Find the PIT partition entry matching a TAR member filename (e.g. `boot.img.lz4` -> `boot.img`).
    pub fn find_by_filename(&self, tar_member_name: &str) -> Option<&PitPartitionEntry> {
        let normalized = tar_member_name
            .strip_suffix(".lz4")
            .unwrap_or(tar_member_name);
        self.entries.iter().find(|e| {
            e.flash_filename.eq_ignore_ascii_case(normalized)
                || e.flash_filename.eq_ignore_ascii_case(tar_member_name)
                || e.partition_name
                    .eq_ignore_ascii_case(normalized.strip_suffix(".img").unwrap_or(normalized))
        })
    }

    /// Synthesize a binary `.pit` image for a standard Samsung Galaxy UFS/eMMC layout.
    pub fn build_standard_galaxy_pit_bytes() -> Vec<u8> {
        let specs: &[(u32, &str, &str, u32, u32)] = &[
            (1, "BL", "sboot.bin", 0, 8192),
            (2, "PARAM", "param.bin", 8192, 4096),
            (3, "EFS", "efs.img", 12288, 10240),
            (4, "FRP", "persistent.img", 22528, 512),
            (5, "BOOT", "boot.img", 23040, 32768),
            (6, "INIT_BOOT", "init_boot.img", 55808, 4096),
            (7, "RECOVERY", "recovery.img", 59904, 40960),
            (8, "VBMETA", "vbmeta.img", 100864, 256),
            (9, "RADIO", "modem.bin", 101120, 65536),
            (10, "SUPER", "super.img", 166656, 2097152),
            (11, "PRISM", "prism.img", 2263808, 262144),
            (12, "OPTICS", "optics.img", 2525952, 32768),
            (13, "USERDATA", "userdata.img", 2558720, 8388608),
        ];

        let mut buf = Vec::with_capacity(28 + specs.len() * 132);
        buf.extend_from_slice(&PIT_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&(specs.len() as u32).to_le_bytes());

        let mut gang = [0u8; 8];
        gang[..7].copy_from_slice(b"COM_TAR");
        let mut proj = [0u8; 8];
        proj[..6].copy_from_slice(b"GALAXY");
        buf.extend_from_slice(&gang);
        buf.extend_from_slice(&proj);
        buf.extend_from_slice(&0u32.to_le_bytes());

        for &(id, part_name, flash_file, blk_off, blk_cnt) in specs {
            let mut entry = [0u8; 132];
            entry[0..4].copy_from_slice(&0u32.to_le_bytes()); // binary_type = AP
            entry[4..8].copy_from_slice(&2u32.to_le_bytes()); // device_type = MMC/UFS
            entry[8..12].copy_from_slice(&id.to_le_bytes());
            entry[12..16].copy_from_slice(&1u32.to_le_bytes()); // attributes
            entry[16..20].copy_from_slice(&1u32.to_le_bytes()); // update_attributes
            entry[20..24].copy_from_slice(&blk_off.to_le_bytes());
            entry[24..28].copy_from_slice(&blk_cnt.to_le_bytes());
            entry[36..36 + part_name.len().min(31)]
                .copy_from_slice(&part_name.as_bytes()[..part_name.len().min(31)]);
            entry[68..68 + flash_file.len().min(31)]
                .copy_from_slice(&flash_file.as_bytes()[..flash_file.len().min(31)]);
            buf.extend_from_slice(&entry);
        }

        buf
    }
}

/// Entry inside a Samsung `.tar` or `.tar.md5` firmware archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OdinTarEntry {
    pub filename: String,
    pub size_bytes: u64,
    pub data_offset: u64,
    pub is_lz4_compressed: bool,
    pub mapped_partition: Option<String>,
}

/// Summary of an inspected `.tar` or `.tar.md5` package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OdinTarManifest {
    pub archive_path: String,
    pub has_md5_trailer: bool,
    pub trailing_md5_expected: Option<String>,
    pub trailing_md5_computed: Option<String>,
    pub md5_matches: Option<bool>,
    pub total_payload_bytes: u64,
    pub entries: Vec<OdinTarEntry>,
}

/// Samsung Odin / Loke protocol packet & archive engine.
pub struct OdinProtocolEngine;

impl OdinProtocolEngine {
    fn find_md5_trailer(bytes: &[u8], minimum_offset: usize) -> Option<(usize, String)> {
        if bytes.len() < 32 || minimum_offset >= bytes.len() {
            return None;
        }
        for start in (minimum_offset..=bytes.len() - 32).rev() {
            let candidate = &bytes[start..start + 32];
            if !candidate.iter().all(u8::is_ascii_hexdigit) {
                continue;
            }
            let boundary_before = start == 0
                || bytes[start - 1] == 0
                || bytes[start - 1] == b'\n'
                || bytes[start - 1] == b'\r';
            let boundary_after =
                start + 32 == bytes.len() || bytes[start + 32].is_ascii_whitespace();
            if boundary_before && boundary_after {
                return Some((
                    start,
                    String::from_utf8_lossy(candidate).to_ascii_lowercase(),
                ));
            }
        }
        None
    }

    /// Build a 1024-byte Loke control packet for USB Bulk OUT transmission.
    pub fn build_control_packet(
        request: LokeRequestType,
        subcommand: u32,
        param1: u32,
        param2: u32,
    ) -> [u8; LOKE_CONTROL_PACKET_SIZE] {
        let mut pkt = [0u8; LOKE_CONTROL_PACKET_SIZE];
        pkt[0..4].copy_from_slice(&(request as u32).to_le_bytes());
        pkt[4..8].copy_from_slice(&subcommand.to_le_bytes());
        pkt[8..12].copy_from_slice(&param1.to_le_bytes());
        pkt[12..16].copy_from_slice(&param2.to_le_bytes());
        pkt
    }

    /// Inspect a POSIX USTAR `.tar` or `.tar.md5` firmware archive from an in-memory buffer.
    pub fn parse_tar_bytes(
        archive_name: &str,
        bytes: &[u8],
        pit: Option<&PitTable>,
    ) -> Result<OdinTarManifest> {
        let mut cursor = 0usize;
        let mut entries = Vec::new();
        let mut total_payload_bytes = 0u64;

        while cursor + 512 <= bytes.len() {
            let block = &bytes[cursor..cursor + 512];
            // Check for all-zero end-of-archive block
            if block.iter().all(|&b| b == 0) {
                break;
            }

            // USTAR magic check at offset 257..262 ("ustar") or standard octal size at 124..136
            let name_end = block[0..100].iter().position(|&b| b == 0).unwrap_or(100);
            let filename = String::from_utf8_lossy(&block[0..name_end])
                .trim()
                .to_string();
            if filename.is_empty() {
                break;
            }

            let size_octal = String::from_utf8_lossy(&block[124..136])
                .trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace())
                .to_string();
            let size_bytes = u64::from_str_radix(&size_octal, 8).map_err(|_| {
                FlashrustError::StorageValidationError(format!(
                    "Invalid USTAR octal size '{}' in TAR header for '{}'",
                    size_octal, filename
                ))
            })?;

            let data_offset = (cursor + 512) as u64;
            let padded_size = size_bytes.div_ceil(512) * 512;
            let next_cursor = (data_offset + padded_size) as usize;
            if next_cursor > bytes.len() {
                return Err(FlashrustError::BufferTooSmall {
                    expected: next_cursor,
                    actual: bytes.len(),
                });
            }

            let mapped_partition = pit
                .and_then(|p| p.find_by_filename(&filename))
                .map(|e| e.partition_name.clone())
                .or_else(|| Self::infer_standard_partition(&filename));

            total_payload_bytes += size_bytes;
            entries.push(OdinTarEntry {
                is_lz4_compressed: filename.ends_with(".lz4"),
                filename,
                size_bytes,
                data_offset,
                mapped_partition,
            });

            cursor = next_cursor;
        }

        let trailer = Self::find_md5_trailer(bytes, cursor);
        let has_md5_trailer = trailer.is_some();
        let trailing_md5_expected = trailer.as_ref().map(|(_, digest)| digest.clone());
        let trailing_md5_computed = trailer
            .as_ref()
            .map(|(offset, _)| format!("{:x}", md5::compute(&bytes[..*offset])));
        let md5_matches = trailing_md5_expected
            .as_ref()
            .zip(trailing_md5_computed.as_ref())
            .map(|(expected, computed)| expected == computed);

        Ok(OdinTarManifest {
            archive_path: archive_name.to_string(),
            has_md5_trailer,
            trailing_md5_expected,
            trailing_md5_computed,
            md5_matches,
            total_payload_bytes,
            entries,
        })
    }

    /// Stream-inspect a `.tar` or `.tar.md5` file on disk without reading multi-gigabyte `super.img` payloads into RAM!
    pub fn inspect_tar_file(path: &Path, pit: Option<&PitTable>) -> Result<OdinTarManifest> {
        let mut file = File::open(path).map_err(|e| FlashrustError::IoError(e.to_string()))?;
        let file_len = file
            .metadata()
            .map_err(|e| FlashrustError::IoError(e.to_string()))?
            .len();

        let mut cursor = 0u64;
        let mut header = [0u8; 512];
        let mut entries = Vec::new();
        let mut total_payload_bytes = 0u64;

        while cursor + 512 <= file_len {
            file.seek(SeekFrom::Start(cursor))
                .map_err(|e| FlashrustError::IoError(e.to_string()))?;
            file.read_exact(&mut header)
                .map_err(|e| FlashrustError::IoError(e.to_string()))?;

            if header.iter().all(|&b| b == 0) {
                break;
            }

            let name_end = header[0..100].iter().position(|&b| b == 0).unwrap_or(100);
            let filename = String::from_utf8_lossy(&header[0..name_end])
                .trim()
                .to_string();
            if filename.is_empty() {
                break;
            }

            let size_octal = String::from_utf8_lossy(&header[124..136])
                .trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace())
                .to_string();
            let Ok(size_bytes) = u64::from_str_radix(&size_octal, 8) else {
                break;
            };

            let data_offset = cursor + 512;
            let padded_size = size_bytes.div_ceil(512) * 512;
            let next_cursor = data_offset + padded_size;
            if next_cursor > file_len {
                return Err(FlashrustError::BufferTooSmall {
                    expected: next_cursor as usize,
                    actual: file_len as usize,
                });
            }

            let mapped_partition = pit
                .and_then(|p| p.find_by_filename(&filename))
                .map(|e| e.partition_name.clone())
                .or_else(|| Self::infer_standard_partition(&filename));

            total_payload_bytes += size_bytes;
            entries.push(OdinTarEntry {
                is_lz4_compressed: filename.ends_with(".lz4"),
                filename,
                size_bytes,
                data_offset,
                mapped_partition,
            });

            cursor = next_cursor;
        }

        // Check the tail for an appended Odin MD5 line and verify the archive bytes before it.
        let mut trailer_offset = None;
        let mut trailing_md5_expected = None;
        if file_len >= 32 {
            let tail_len = file_len.min(512) as usize;
            let mut tail_buf = vec![0u8; tail_len];
            let tail_start = file_len - tail_len as u64;
            file.seek(SeekFrom::Start(tail_start))
                .map_err(|e| FlashrustError::IoError(e.to_string()))?;
            file.read_exact(&mut tail_buf)
                .map_err(|e| FlashrustError::IoError(e.to_string()))?;
            let minimum = cursor.saturating_sub(tail_start) as usize;
            if let Some((local_offset, expected)) = Self::find_md5_trailer(&tail_buf, minimum) {
                trailer_offset = Some(tail_start + local_offset as u64);
                trailing_md5_expected = Some(expected);
            }
        }

        let trailing_md5_computed = if let Some(limit) = trailer_offset {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| FlashrustError::IoError(e.to_string()))?;
            let mut context = md5::Context::new();
            let mut remaining = limit;
            let mut chunk = [0u8; 64 * 1024];
            while remaining > 0 {
                let requested = remaining.min(chunk.len() as u64) as usize;
                file.read_exact(&mut chunk[..requested])
                    .map_err(|e| FlashrustError::IoError(e.to_string()))?;
                context.consume(&chunk[..requested]);
                remaining -= requested as u64;
            }
            Some(format!("{:x}", context.finalize()))
        } else {
            None
        };
        let md5_matches = trailing_md5_expected
            .as_ref()
            .zip(trailing_md5_computed.as_ref())
            .map(|(expected, computed)| expected == computed);

        Ok(OdinTarManifest {
            archive_path: path.to_string_lossy().to_string(),
            has_md5_trailer: trailing_md5_expected.is_some(),
            trailing_md5_expected,
            trailing_md5_computed,
            md5_matches,
            total_payload_bytes,
            entries,
        })
    }

    pub fn infer_standard_partition(filename: &str) -> Option<String> {
        let base = filename.strip_suffix(".lz4").unwrap_or(filename);
        let lower = base.to_ascii_lowercase();
        if lower == "boot.img" {
            Some("BOOT".into())
        } else if lower == "init_boot.img" {
            Some("INIT_BOOT".into())
        } else if lower == "vendor_boot.img" {
            Some("VENDOR_BOOT".into())
        } else if lower == "recovery.img" {
            Some("RECOVERY".into())
        } else if lower == "vbmeta.img" {
            Some("VBMETA".into())
        } else if lower == "super.img" {
            Some("SUPER".into())
        } else if lower == "sboot.bin" {
            Some("BL".into())
        } else if lower == "param.bin" || lower == "up_param.bin" {
            Some("PARAM".into())
        } else if lower == "modem.bin" {
            Some("RADIO".into())
        } else if lower == "prism.img" {
            Some("PRISM".into())
        } else if lower == "optics.img" {
            Some("OPTICS".into())
        } else if lower == "userdata.img" {
            Some("USERDATA".into())
        } else if lower == "persistent.img" || lower == "frp.img" {
            Some("FRP".into())
        } else if lower.ends_with(".pit") {
            Some("PIT (Repartition)".into())
        } else {
            None
        }
    }
}

/// Detailed inspection of an Android `frp` / `persistent` partition image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrpPartitionReport {
    pub partition_size_bytes: usize,
    pub header_marker: u32,
    pub marker_valid: bool,
    pub credential_data_size: u32,
    pub has_enrolled_credentials: bool,
    pub oem_unlock_enabled: bool,
    pub stored_sha256_hex: String,
    pub computed_sha256_hex: String,
    pub digest_matches: bool,
}

pub struct FrpPartitionInspector;

impl FrpPartitionInspector {
    /// Inspect an Android `frp` / `persistent` partition image and verify its AOSP SHA-256 digest.
    pub fn inspect_bytes(data: &[u8]) -> Result<FrpPartitionReport> {
        if data.len() < 40 {
            return Err(FlashrustError::BufferTooSmall {
                expected: 40,
                actual: data.len(),
            });
        }
        let (header_marker, marker_valid, credential_data_size, oem_unlock_enabled, has_creds) =
            ZigEngine::inspect_frp_partition_raw(data)?;

        let mut stored_sha256_hex = String::with_capacity(64);
        for &b in &data[0..32] {
            stored_sha256_hex.push_str(&format!("{:02x}", b));
        }

        // AOSP PersistentDataBlockService hashes bytes[32..data.len() - 1]
        let mut sha = Sha256Hasher::new();
        sha.update(&data[32..data.len() - 1]);
        let computed_sha256_hex = sha.finalize_hex();
        let digest_matches = marker_valid && (stored_sha256_hex == computed_sha256_hex);

        Ok(FrpPartitionReport {
            partition_size_bytes: data.len(),
            header_marker,
            marker_valid,
            credential_data_size,
            has_enrolled_credentials: has_creds,
            oem_unlock_enabled,
            stored_sha256_hex,
            computed_sha256_hex,
            digest_matches,
        })
    }

    /// Generate a clean AOSP `persistent` / `frp` partition image for authorized developer provisioning.
    /// Sets `BLOCK_HEADER_MARKER = 0x19901873`, `total_data_size = 0`, sets the `oem_unlock_enabled`
    /// byte at `size - 1`, and writes the matching SHA-256 digest into `bytes[0..32]`.
    pub fn build_developer_frp_image(
        partition_size_bytes: usize,
        oem_unlock_enabled: bool,
    ) -> Result<Vec<u8>> {
        if partition_size_bytes < 1040 {
            return Err(FlashrustError::BufferTooSmall {
                expected: 1040,
                actual: partition_size_bytes,
            });
        }

        let mut buf = vec![0u8; partition_size_bytes];
        buf[32..36].copy_from_slice(&AOSP_FRP_HEADER_MARKER.to_be_bytes());
        buf[36..40].copy_from_slice(&0u32.to_be_bytes());
        buf[partition_size_bytes - 1] = if oem_unlock_enabled { 1 } else { 0 };

        let mut sha = Sha256Hasher::new();
        sha.update(&buf[32..partition_size_bytes - 1]);
        let hex = sha.finalize_hex();

        for i in 0..32 {
            if let Ok(byte) = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                buf[i] = byte;
            }
        }

        Ok(buf)
    }
}

/// Preflight compatibility assessment for Samsung Download Mode + FRP/KG states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamsungPreflightReport {
    pub can_flash_stock_signed: bool,
    pub can_flash_custom_patched: bool,
    pub current_payload_allowed: bool,
    pub status_headline: String,
    pub findings: Vec<String>,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SamsungOdinConfig {
    pub bl_tar: Option<PathBuf>,
    pub ap_tar: Option<PathBuf>,
    pub cp_tar: Option<PathBuf>,
    pub csc_tar: Option<PathBuf>,
    pub pit_file: Option<PathBuf>,
    pub frp_partition_file: Option<PathBuf>,
    pub frp_lock_state: FrpLockState,
    pub kg_lock_state: KgLockState,
    pub oem_unlock_enabled: bool,
    pub nand_erase_all: bool,
    pub repartition: bool,
}

impl Default for SamsungOdinConfig {
    fn default() -> Self {
        Self {
            bl_tar: None,
            ap_tar: None,
            cp_tar: None,
            csc_tar: None,
            pit_file: None,
            frp_partition_file: None,
            frp_lock_state: FrpLockState::On,
            kg_lock_state: KgLockState::Completed,
            oem_unlock_enabled: false,
            nand_erase_all: false,
            repartition: false,
        }
    }
}

impl SamsungOdinConfig {
    /// Evaluate whether the configured Samsung Odin flash session will pass bootloader verification.
    pub fn evaluate_preflight(&self, has_custom_patch_or_su: bool) -> SamsungPreflightReport {
        let can_flash_stock_signed = self.kg_lock_state != KgLockState::Locked;
        let can_flash_custom_patched = self.frp_lock_state == FrpLockState::Off
            && self.oem_unlock_enabled
            && self.kg_lock_state == KgLockState::Completed;

        let current_payload_allowed = if has_custom_patch_or_su {
            can_flash_custom_patched
        } else {
            can_flash_stock_signed
        };

        let mut findings = Vec::new();
        let mut recommended_actions = Vec::new();

        match self.frp_lock_state {
            FrpLockState::On => {
                findings.push(
                    "Bootloader reports FRP LOCK: ON — Samsung Loke strictly enforces RSA-2048/4096 signature verification on all flashed partitions.".into(),
                );
                if has_custom_patch_or_su {
                    findings.push(
                        "CRITICAL: Auto SU Injection / Custom Boot Kitchen patches modify boot.img/vbmeta.img digests and WILL be rejected with 'Custom Binary (BOOT) Blocked by FRP Lock'.".into(),
                    );
                    recommended_actions.push(
                        "Disable 'Auto SU Binary Injection' and flash official Samsung-signed stock BL + AP + CP + CSC .tar.md5 packages first.".into(),
                    );
                    recommended_actions.push(
                        "On authorized developer devices, boot into Android -> Settings -> Developer Options -> Enable 'OEM Unlocking' (sets persistent[size-1] = 0x01) so Download Mode reports FRP LOCK: OFF.".into(),
                    );
                } else {
                    findings.push(
                        "Official Samsung-signed stock firmware (BL / AP / CP / CSC .tar.md5) is permitted even while FRP LOCK: ON.".into(),
                    );
                    recommended_actions.push(
                        "Select matching official BL, AP, CP, and CSC .tar.md5 archives (same or higher SW REV bit/binary counter) to flash cleanly over Loke Download Mode.".into(),
                    );
                }
            }
            FrpLockState::Off => {
                findings.push(
                    "Bootloader reports FRP LOCK: OFF — Unsigned or custom-patched partitions are permitted if OEM Unlock is active and KG State is Completed.".into(),
                );
            }
        }

        if self.kg_lock_state == KgLockState::Prenormal {
            findings.push(
                "KG STATE: Prenormal — Knox Guard restricts custom binaries even when FRP LOCK is OFF.".into(),
            );
            recommended_actions.push(
                "Flash stock official firmware, connect to Wi-Fi in Android, and verify 'OEM Unlocking' appears in Developer Options to transition KG STATE -> Completed.".into(),
            );
        } else if self.kg_lock_state == KgLockState::Locked {
            findings
                .push("KG STATE: Locked — Device is managed by Knox Guard enterprise lock.".into());
        }

        let status_headline = if current_payload_allowed {
            if has_custom_patch_or_su {
                "PREFLIGHT PASS: Custom Patched / Rooted Firmware Permitted (FRP OFF + OEM Unlocked)".into()
            } else {
                "PREFLIGHT PASS: Official Stock Signed Firmware Ready for Loke Download Mode (FRP Compatible)".into()
            }
        } else {
            "PREFLIGHT BLOCKED: Custom Binary Blocked by FRP / KG Lock (Switch to Stock Signed TAR or Enable OEM Unlock)".into()
        };

        SamsungPreflightReport {
            can_flash_stock_signed,
            can_flash_custom_patched,
            current_payload_allowed,
            status_headline,
            findings,
            recommended_actions,
        }
    }

    /// Generate the equivalent CLI command preview for the configured Odin session.
    pub fn to_command_string(&self, auto_reboot: bool) -> String {
        let mut parts = vec!["flashrust".to_string(), "samsung-flash".to_string()];
        if let Some(ref bl) = self.bl_tar {
            parts.push(format!("--bl \"{}\"", bl.display()));
        }
        if let Some(ref ap) = self.ap_tar {
            parts.push(format!("--ap \"{}\"", ap.display()));
        }
        if let Some(ref cp) = self.cp_tar {
            parts.push(format!("--cp \"{}\"", cp.display()));
        }
        if let Some(ref csc) = self.csc_tar {
            parts.push(format!("--csc \"{}\"", csc.display()));
        }
        if let Some(ref pit) = self.pit_file {
            parts.push(format!("--pit \"{}\"", pit.display()));
        }
        parts.push(format!(
            "--frp-lock {}",
            if self.frp_lock_state == FrpLockState::Off {
                "off"
            } else {
                "on"
            }
        ));
        parts.push(format!(
            "--kg-state {}",
            match self.kg_lock_state {
                KgLockState::Completed => "completed",
                KgLockState::Checking => "checking",
                KgLockState::Prenormal => "prenormal",
                KgLockState::Locked => "locked",
            }
        ));
        if self.oem_unlock_enabled {
            parts.push("--oem-unlock".to_string());
        }
        if !auto_reboot {
            parts.push("--no-reboot".to_string());
        }
        parts.join(" ")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamsungDetectedSubMode {
    RealLokeDownload,   // Responded with "LOKE" to "ODIN" handshake
    FakeOrAtModemMode, // Responded with "OK" / "+DEVCONINFO" to AT commands (Factory / Fake Download / Modem mode)
    UnresponsiveOrBusy, // Port opened, no immediate AT or LOKE reply (may be waiting on Warning Screen: press Volume Up)
    NoSerialPortFound,  // No /dev/cu.usbmodem* or /dev/ttyACM* node found
}

impl SamsungDetectedSubMode {
    pub fn label(&self) -> &'static str {
        match self {
            SamsungDetectedSubMode::RealLokeDownload => {
                "Real Odin / Loke Download Mode (LOKE Verified)"
            }
            SamsungDetectedSubMode::FakeOrAtModemMode => "Fake Download / Factory AT Modem Mode",
            SamsungDetectedSubMode::UnresponsiveOrBusy => "Waiting on Warning Screen / Silent Port",
            SamsungDetectedSubMode::NoSerialPortFound => "No /dev/cu.usbmodem* Port Detected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamsungDevConInfo {
    pub model: String,            // e.g. "SM-S266V"
    pub firmware_version: String, // e.g. "S266VUDSACZH3"
    pub sw_rev_bit: String,       // e.g. "D" (Binary Bit / Revision)
    pub carrier_prd: String,      // e.g. "TFV" (TracFone / Verizon)
    pub serial_number: String,    // e.g. "R5CY744N4KP"
    pub imei: String,             // e.g. "350567321636692"
    pub usb_composition: String,  // e.g. "AT,MTP"
    pub lock_status: String,      // e.g. "NONE"
    pub unique_number: String,    // e.g. "CE062596E82511D60F7E"
}

impl SamsungDevConInfo {
    pub fn parse(raw: &str) -> Option<Self> {
        let tag = "+DEVCONINFO:";
        let pos = raw.find(tag)?;
        let content = &raw[pos + tag.len()..];
        let end_pos = content
            .find("#OK#")
            .or_else(|| content.find('\r'))
            .or_else(|| content.find('\n'))
            .unwrap_or(content.len());
        let fields_str = &content[..end_pos];

        let extract_field = |key: &str| -> String {
            fields_str
                .split(';')
                .map(str::trim)
                .find_map(|field| {
                    let value = field.strip_prefix(key)?.strip_prefix('(')?;
                    Some(value.strip_suffix(')')?.trim().to_string())
                })
                .unwrap_or_default()
        };

        let model = extract_field("MN");
        let fw = extract_field("VER");
        let prd = extract_field("PRD");
        let sn = extract_field("SN");
        let imei = extract_field("IMEI");
        let lock = extract_field("LOCK");
        let con = extract_field("CON");
        let un = extract_field("UN");

        if model.is_empty() && fw.is_empty() {
            return None;
        }

        // Parse Binary Bit from Firmware string (e.g. "S266VUDSACZH3" -> Bit D)
        let bit = if fw.len() >= 9 {
            let chars: Vec<char> = fw.chars().collect();
            let idx = chars.len().saturating_sub(8);
            chars
                .get(idx)
                .map(|c| c.to_string())
                .unwrap_or_else(|| "Unknown".into())
        } else {
            "Unknown".into()
        };

        Some(Self {
            model,
            firmware_version: fw,
            sw_rev_bit: bit,
            carrier_prd: prd,
            serial_number: sn,
            imei,
            usb_composition: con,
            lock_status: lock,
            unique_number: un,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamsungModeProbeReport {
    pub serial_port: Option<String>,
    pub detected_submode: SamsungDetectedSubMode,
    pub raw_response: String,
    pub devconinfo: Option<String>,
    pub parsed_telemetry: Option<SamsungDevConInfo>,
    pub summary: String,
}

impl OdinProtocolEngine {
    /// Discover attached `/dev/cu.usbmodem*` (macOS) or `/dev/ttyACM*` (Linux) CDC-ACM ports.
    pub fn discover_samsung_modem_ports() -> Vec<PathBuf> {
        let mut ports = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("cu.usbmodem") || name.starts_with("ttyACM") {
                    ports.push(entry.path());
                }
            }
        }
        ports.sort();
        ports
    }

    #[cfg(unix)]
    fn open_nonblocking_serial(path: &Path) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK (0x0004 on macOS, 0x0800 on Linux) | O_NOCTTY (0x20000 on macOS, 0x0100 on Linux)
        #[cfg(target_os = "macos")]
        const FLAGS: i32 = 0x0004 | 0x0002_0000;
        #[cfg(not(target_os = "macos"))]
        const FLAGS: i32 = 0x0800 | 0x0100;

        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FLAGS)
            .open(path)
    }

    #[cfg(not(unix))]
    fn open_nonblocking_serial(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
    }

    fn write_and_read_window(file: &mut File, payload: &[u8], wait_ms: u64) -> Vec<u8> {
        use std::io::Write;
        let _ = file.write_all(payload);
        let _ = file.flush();

        let start = std::time::Instant::now();
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        while start.elapsed() < std::time::Duration::from_millis(wait_ms) {
            match file.read(&mut buf) {
                Ok(n) if n > 0 => {
                    out.extend_from_slice(&buf[..n]);
                }
                _ => {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
            }
        }
        out
    }

    /// Probe the attached Samsung USB CDC-ACM port (`/dev/cu.usbmodem*`) to determine if the phone
    /// is in **Real Loke Download Mode** (`ODIN` -> `LOKE`), **Fake Download / Factory / AT Modem Mode** (`AT` -> `OK`),
    /// or sitting at the initial Download Mode Warning Screen waiting for `Volume Up`.
    pub fn probe_samsung_download_mode() -> SamsungModeProbeReport {
        Self::probe_samsung_download_mode_on(None)
    }

    pub fn probe_samsung_download_mode_on(port_override: Option<&Path>) -> SamsungModeProbeReport {
        let ports = port_override
            .map(|path| vec![path.to_path_buf()])
            .unwrap_or_else(Self::discover_samsung_modem_ports);
        let Some(port_path) = ports.first() else {
            return SamsungModeProbeReport {
                serial_port: None,
                detected_submode: SamsungDetectedSubMode::NoSerialPortFound,
                raw_response: String::new(),
                devconinfo: None,
                parsed_telemetry: None,
                summary:
                    "No /dev/cu.usbmodem* port found. Ensure the Samsung USB cable is connected."
                        .into(),
            };
        };

        let port_str = port_path.to_string_lossy().to_string();
        let Ok(mut file) = Self::open_nonblocking_serial(port_path) else {
            return SamsungModeProbeReport {
                serial_port: Some(port_str.clone()),
                detected_submode: SamsungDetectedSubMode::UnresponsiveOrBusy,
                raw_response: String::new(),
                devconinfo: None,
                parsed_telemetry: None,
                summary: format!("Port {} is busy or held by another process.", port_str),
            };
        };

        // 1. Probe AT command first (safe in both Fake Download Mode / Factory Mode and ignored by Loke)
        let at_resp = Self::write_and_read_window(&mut file, b"AT\r\n", 180);
        let at_text = String::from_utf8_lossy(&at_resp).trim().to_string();
        if at_text.contains("OK") || at_text.contains("AT") || at_text.contains("ERROR") {
            let info_resp = Self::write_and_read_window(&mut file, b"AT+DEVCONINFO\r\n", 220);
            let info_text = String::from_utf8_lossy(&info_resp).trim().to_string();
            let telemetry = SamsungDevConInfo::parse(&info_text);
            return SamsungModeProbeReport {
                serial_port: Some(port_str.clone()),
                detected_submode: SamsungDetectedSubMode::FakeOrAtModemMode,
                raw_response: format!("{} {}", at_text, info_text).trim().to_string(),
                devconinfo: if info_text.is_empty() {
                    None
                } else {
                    Some(info_text)
                },
                parsed_telemetry: telemetry,
                summary: format!(
                    "DETECTED FAKE DOWNLOAD / AT MODEM MODE on {} (Device replied to AT commands instead of Loke!). Click 'Reboot to Real Download Mode' to send AT+FUS?.",
                    port_str
                ),
            };
        }

        // 2. Probe 4-byte "ODIN" Loke greeting
        let odin_resp = Self::write_and_read_window(&mut file, b"ODIN", 220);
        let odin_text = String::from_utf8_lossy(&odin_resp).trim().to_string();
        if odin_resp.windows(4).any(|w| w == b"LOKE") || odin_text.contains("LOKE") {
            return SamsungModeProbeReport {
                serial_port: Some(port_str.clone()),
                detected_submode: SamsungDetectedSubMode::RealLokeDownload,
                raw_response: odin_text,
                devconinfo: None,
                parsed_telemetry: None,
                summary: format!(
                    "VERIFIED REAL LOKE DOWNLOAD MODE on {}! Device replied 'LOKE' to 'ODIN' handshake.",
                    port_str
                ),
            };
        }

        SamsungModeProbeReport {
            serial_port: Some(port_str.clone()),
            detected_submode: SamsungDetectedSubMode::UnresponsiveOrBusy,
            raw_response: odin_text,
            devconinfo: None,
            parsed_telemetry: None,
            summary: format!(
                "Port {} opened, but no 'LOKE' reply yet. If the phone screen shows 'Warning!!' or 'Fake Download Mode', click 'Reboot to Real Download Mode' or press Volume Up.",
                port_str
            ),
        }
    }

    /// Force-transition a connected Samsung device into **Real Odin / Loke Download Mode** using:
    /// 1. Samsung USB Modem `AT+FUS?\r\n` (Firmware Update Service Download Mode trigger) over `/dev/cu.usbmodem*`
    /// 2. `adb reboot download`, then `adb reboot edl` (if ADB daemon is active)
    /// 3. `fastboot reboot download`, `fastboot reboot bootloader`, then `fastboot oem download` (if Fastboot/lk mode is active)
    pub fn reboot_to_download_mode() -> Vec<String> {
        Self::reboot_to_download_mode_on(None)
    }

    pub fn reboot_to_download_mode_on(port_override: Option<&Path>) -> Vec<String> {
        let mut logs = Vec::new();

        // Method 1: USB CDC-ACM Serial Port (`AT+FUS?\r\n` Samsung Suds/Kies Download Mode trigger)
        let ports = port_override
            .map(|path| vec![path.to_path_buf()])
            .unwrap_or_else(Self::discover_samsung_modem_ports);
        if ports.is_empty() {
            logs.push("[SERIAL] No /dev/cu.usbmodem* CDC-ACM port currently mounted".into());
        } else {
            for port in &ports {
                let port_str = port.to_string_lossy().to_string();
                match Self::open_nonblocking_serial(port) {
                    Ok(mut file) => {
                        logs.push(format!(
                            "[SERIAL] Opened Samsung USB port {} — sending AT+FUN=1,1 and AT+FUS? (Download Mode trigger)...",
                            port_str
                        ));
                        let _ = Self::write_and_read_window(&mut file, b"AT+FUN=1,1\r\n", 120);
                        let resp = Self::write_and_read_window(&mut file, b"AT+FUS?\r\n", 250);
                        let resp_str = String::from_utf8_lossy(&resp).trim().to_string();
                        if !resp_str.is_empty() {
                            logs.push(format!(
                                "[SERIAL] Device response on {}: {}",
                                port_str, resp_str
                            ));
                        } else {
                            logs.push(format!(
                                "[SERIAL] Dispatched AT+FUS? to {} (device re-enumerating USB bus if in Factory/Modem mode)",
                                port_str
                            ));
                        }
                    }
                    Err(e) => {
                        logs.push(format!("[SERIAL] Could not open {}: {}", port_str, e));
                    }
                }
            }
        }

        // Method 2: Try `adb reboot download`, then `adb reboot edl`.
        if let Ok(out) = std::process::Command::new("adb")
            .args(["reboot", "download"])
            .output()
        {
            if out.status.success() {
                logs.push("[ADB] Issued `adb reboot download` -> SUCCESS".into());
            } else {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if !err.is_empty() {
                    logs.push(format!("[ADB] `adb reboot download`: {}", err));
                }
            }
        } else {
            // `adb reboot edl` (Emergency Download Mode) — some Samsung devices
            // reboot straight into EDL/download mode via this path.
            if let Ok(out) = std::process::Command::new("adb")
                .args(["reboot", "edl"])
                .output()
            {
                if out.status.success() {
                    logs.push("[ADB] Issued `adb reboot edl` -> SUCCESS".into());
                } else {
                    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    if !err.is_empty() {
                        logs.push(format!("[ADB] `adb reboot edl`: {}", err));
                    }
                }
            }
        }

        // Method 3: Try `fastboot reboot download`, `fastboot reboot bootloader`,
        // then `fastboot oem download`. Each attempt is bounded by a timeout so
        // a missing fastboot device cannot hang.
        if Self::run_fastboot_with_timeout(&["reboot", "download"], 5) {
            logs.push("[FASTBOOT] Issued `fastboot reboot download` -> SUCCESS".into());
        } else if Self::run_fastboot_with_timeout(&["reboot", "bootloader"], 5) {
            logs.push("[FASTBOOT] Issued `fastboot reboot bootloader` -> SUCCESS".into());
        } else if Self::run_fastboot_with_timeout(&["oem", "download"], 5) {
            logs.push("[FASTBOOT] Issued `fastboot oem download` -> SUCCESS".into());
        }

        logs
    }

    /// Run a `fastboot` subcommand with a hard timeout (in seconds).
    /// Returns `true` if the command exited successfully before the deadline,
    /// `false` if it failed, timed out, or `fastboot` is not on PATH.
    fn run_fastboot_with_timeout(args: &[&str], timeout_secs: u64) -> bool {
        let mut child = match std::process::Command::new("fastboot")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        let started = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) => {
                    if started.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(_) => return false,
            }
        }
    }

    /// Send Loke `ODIN` -> `LOKE` handshake + `BeginSession (0x64)` + `EndSession (0x67, sub=0x01)`
    /// to cleanly reboot a Samsung device that is currently in Real Loke Download Mode.
    pub fn loke_reboot_device() -> Vec<String> {
        let mut logs = Vec::new();
        let ports = Self::discover_samsung_modem_ports();
        if ports.is_empty() {
            logs.push("[LOKE-REBOOT] No /dev/cu.usbmodem* port found.".into());
            return logs;
        }

        for port in &ports {
            let port_str = port.to_string_lossy().to_string();
            match Self::open_nonblocking_serial(port) {
                Ok(mut file) => {
                    let hs = Self::write_and_read_window(&mut file, b"ODIN", 180);
                    let hs_str = String::from_utf8_lossy(&hs).trim().to_string();
                    logs.push(format!(
                        "[LOKE-REBOOT] Sent 'ODIN' handshake on {} -> reply: '{}'",
                        port_str,
                        if hs_str.is_empty() {
                            "(session already active)"
                        } else {
                            &hs_str
                        }
                    ));
                    // BeginSession (0x64, sub=0x00)
                    let begin_pkt =
                        Self::build_control_packet(LokeRequestType::BeginSession, 0x00, 0, 0);
                    let _ = Self::write_and_read_window(&mut file, &begin_pkt, 120);
                    // EndSession (0x67, sub=0x01 = Reboot target)
                    let reboot_pkt =
                        Self::build_control_packet(LokeRequestType::EndSession, 0x01, 0, 0);
                    let _ = Self::write_and_read_window(&mut file, &reboot_pkt, 150);
                    logs.push(format!(
                        "[LOKE-REBOOT] Dispatched Loke EndSession+Reboot packet (opcode 0x67, sub 0x01) on {}",
                        port_str
                    ));
                }
                Err(e) => {
                    logs.push(format!("[LOKE-REBOOT] Failed to open {}: {}", port_str, e));
                }
            }
        }
        logs
    }
}
