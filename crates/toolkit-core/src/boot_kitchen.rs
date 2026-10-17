use crate::error::{FlashrustError, Result};
use crate::zig_bridge::{BootHeaderVersion, ZigEngine};
use base64::Engine as _;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use lz4_flex::frame::{FrameDecoder, FrameEncoder, FrameInfo};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const NEWC_MAGIC: &[u8; 6] = b"070701";
const NEWC_CRC_MAGIC: &[u8; 6] = b"070702";
const GZIP_MAGIC: &[u8; 2] = &[0x1f, 0x8b];
const LZ4_FRAME_MAGIC: &[u8; 4] = &[0x04, 0x22, 0x4d, 0x18];
const LZ4_LEGACY_MAGIC: &[u8; 4] = &[0x02, 0x21, 0x4c, 0x18];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitHijackTarget {
    KernelSU,
    Magisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RamdiskCompression {
    RawCpio,
    Gzip,
    Lz4Frame,
    Lz4Legacy,
}

impl RamdiskCompression {
    pub fn label(self) -> &'static str {
        match self {
            Self::RawCpio => "raw newc CPIO",
            Self::Gzip => "gzip",
            Self::Lz4Frame => "LZ4 frame",
            Self::Lz4Legacy => "legacy LZ4 frame",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchOperation {
    InitHijack(InitHijackTarget),
    SelinuxPolicy,
    AdbPreauthorization,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BootPatchRequest<'a> {
    pub init_payload: Option<&'a [u8]>,
    pub init_target: Option<InitHijackTarget>,
    pub selinux_policy: Option<&'a [u8]>,
    pub adb_public_key: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchSummary {
    pub header_version: String,
    pub original_ramdisk_size: usize,
    pub patched_ramdisk_size: usize,
    pub ramdisk_compression: RamdiskCompression,
    pub operations: Vec<PatchOperation>,
    pub preserved_suffix_bytes: usize,
}

pub struct BootKitchen;

impl BootKitchen {
    /// Compatibility wrapper for the original init-hijack API.
    pub fn patch_boot_image(
        boot_img_bytes: &[u8],
        init_payload: &[u8],
        target: InitHijackTarget,
        selinux_policy: Option<&[u8]>,
    ) -> Result<(Vec<u8>, PatchSummary)> {
        Self::patch_boot_image_with_options(
            boot_img_bytes,
            BootPatchRequest {
                init_payload: Some(init_payload),
                init_target: Some(target),
                selinux_policy,
                adb_public_key: None,
            },
        )
    }

    /// Compatibility wrapper for ADB-only patching.
    pub fn patch_boot_image_adb_preauth(
        boot_img_bytes: &[u8],
        adb_pubkey: &[u8],
    ) -> Result<(Vec<u8>, PatchSummary)> {
        Self::patch_boot_image_with_options(
            boot_img_bytes,
            BootPatchRequest {
                adb_public_key: Some(adb_pubkey),
                ..BootPatchRequest::default()
            },
        )
    }

    /// Apply every requested ramdisk operation and rebuild the image once.
    pub fn patch_boot_image_with_options(
        boot_img_bytes: &[u8],
        request: BootPatchRequest<'_>,
    ) -> Result<(Vec<u8>, PatchSummary)> {
        if request.init_payload.is_none()
            && request.selinux_policy.is_none()
            && request.adb_public_key.is_none()
        {
            return Err(FlashrustError::StorageValidationError(
                "No boot image patch operation was requested".into(),
            ));
        }
        if request.init_payload.is_some() != request.init_target.is_some() {
            return Err(FlashrustError::StorageValidationError(
                "An init payload and init target must be supplied together".into(),
            ));
        }

        let meta = ZigEngine::parse_boot_image(boot_img_bytes)?;
        if meta.ramdisk_size == 0 {
            return Err(FlashrustError::StorageValidationError(
                "Boot image contains an empty ramdisk segment".into(),
            ));
        }

        let page_size = meta.page_size as usize;
        if page_size == 0 {
            return Err(FlashrustError::StorageValidationError(
                "Boot image declares a zero page size".into(),
            ));
        }

        let ramdisk_start = meta.ramdisk_offset;
        let ramdisk_end = ramdisk_start
            .checked_add(meta.ramdisk_size as usize)
            .ok_or_else(|| {
                FlashrustError::StorageValidationError("Ramdisk range overflowed".into())
            })?;
        let original_aligned_end = ramdisk_start
            .checked_add((meta.ramdisk_size as usize).div_ceil(page_size) * page_size)
            .ok_or_else(|| {
                FlashrustError::StorageValidationError("Aligned ramdisk range overflowed".into())
            })?;

        if ramdisk_end > boot_img_bytes.len() || original_aligned_end > boot_img_bytes.len() {
            return Err(FlashrustError::BufferTooSmall {
                expected: original_aligned_end.max(ramdisk_end),
                actual: boot_img_bytes.len(),
            });
        }

        let (mut cpio, compression) =
            Self::decode_ramdisk(&boot_img_bytes[ramdisk_start..ramdisk_end])?;
        let mut operations = Vec::new();

        if let (Some(payload), Some(target)) = (request.init_payload, request.init_target) {
            cpio = ZigEngine::patch_cpio_init(&cpio, payload)?;
            operations.push(PatchOperation::InitHijack(target));
        }

        if let Some(policy) = request.selinux_policy {
            let _ = ZigEngine::inject_selinux_rules(policy)?;
            operations.push(PatchOperation::SelinuxPolicy);
        }

        if let Some(key) = request.adb_public_key {
            let normalized_key = Self::validate_adb_public_key(key)?;
            cpio = ZigEngine::inject_adb_preauth(&cpio, &normalized_key)?;
            operations.push(PatchOperation::AdbPreauthorization);
        }

        let patched_ramdisk = Self::encode_ramdisk(&cpio, compression)?;
        let patched_ramdisk_size = patched_ramdisk.len();
        let patched_aligned_size = patched_ramdisk_size.div_ceil(page_size) * page_size;
        let preserved_suffix = &boot_img_bytes[original_aligned_end..];

        let output_capacity = ramdisk_start
            .checked_add(patched_aligned_size)
            .and_then(|size| size.checked_add(preserved_suffix.len()))
            .ok_or_else(|| {
                FlashrustError::StorageValidationError("Patched boot image size overflowed".into())
            })?;
        let mut patched_boot = Vec::with_capacity(output_capacity);
        patched_boot.extend_from_slice(&boot_img_bytes[..ramdisk_start]);
        patched_boot.extend_from_slice(&patched_ramdisk);
        patched_boot.resize(ramdisk_start + patched_aligned_size, 0);
        patched_boot.extend_from_slice(preserved_suffix);

        let size_u32 = u32::try_from(patched_ramdisk_size).map_err(|_| {
            FlashrustError::StorageValidationError(
                "Patched ramdisk is too large for the Android boot header".into(),
            )
        })?;
        let size_bytes = size_u32.to_le_bytes();
        match meta.version {
            BootHeaderVersion::V3 | BootHeaderVersion::V4 => {
                patched_boot[12..16].copy_from_slice(&size_bytes);
            }
            _ => patched_boot[16..20].copy_from_slice(&size_bytes),
        }

        let summary = PatchSummary {
            header_version: format!("{:?}", meta.version),
            original_ramdisk_size: meta.ramdisk_size as usize,
            patched_ramdisk_size,
            ramdisk_compression: compression,
            operations,
            preserved_suffix_bytes: preserved_suffix.len(),
        };

        Ok((patched_boot, summary))
    }

    pub fn default_adb_public_key_path() -> Option<std::path::PathBuf> {
        let home = std::env::var_os("HOME")?;
        Some(std::path::PathBuf::from(home).join(".android/adbkey.pub"))
    }

    pub fn read_host_adb_pubkey() -> Option<Vec<u8>> {
        std::fs::read(Self::default_adb_public_key_path()?).ok()
    }

    /// Validate and normalize the one-line Android ADB RSA public-key format.
    pub fn validate_adb_public_key(adb_pubkey: &[u8]) -> Result<Vec<u8>> {
        let text = std::str::from_utf8(adb_pubkey).map_err(|_| {
            FlashrustError::StorageValidationError(
                "ADB public key must be UTF-8 text in Android adbkey.pub format".into(),
            )
        })?;
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
            return Err(FlashrustError::StorageValidationError(
                "ADB public key must contain exactly one non-empty line".into(),
            ));
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let encoded = parts.next().unwrap_or_default();
        let comment = parts
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| {
                FlashrustError::StorageValidationError(
                    "ADB public key contains invalid base64 data".into(),
                )
            })?;
        if decoded.len() != 524 {
            return Err(FlashrustError::StorageValidationError(format!(
                "ADB public key decoded to {} bytes; expected a 524-byte Android RSA key",
                decoded.len()
            )));
        }

        let mut normalized = encoded.as_bytes().to_vec();
        if let Some(comment) = comment {
            normalized.push(b' ');
            normalized.extend_from_slice(comment.as_bytes());
        }
        normalized.push(b'\n');
        Ok(normalized)
    }

    fn decode_ramdisk(input: &[u8]) -> Result<(Vec<u8>, RamdiskCompression)> {
        let (decoded, compression) =
            if input.starts_with(NEWC_MAGIC) || input.starts_with(NEWC_CRC_MAGIC) {
                (input.to_vec(), RamdiskCompression::RawCpio)
            } else if input.starts_with(GZIP_MAGIC) {
                let mut output = Vec::new();
                GzDecoder::new(input)
                    .read_to_end(&mut output)
                    .map_err(|error| {
                        FlashrustError::StorageValidationError(format!(
                            "Failed to decompress gzip ramdisk: {error}"
                        ))
                    })?;
                (output, RamdiskCompression::Gzip)
            } else if input.starts_with(LZ4_FRAME_MAGIC) || input.starts_with(LZ4_LEGACY_MAGIC) {
                let compression = if input.starts_with(LZ4_LEGACY_MAGIC) {
                    RamdiskCompression::Lz4Legacy
                } else {
                    RamdiskCompression::Lz4Frame
                };
                let mut output = Vec::new();
                FrameDecoder::new(input)
                    .read_to_end(&mut output)
                    .map_err(|error| {
                        FlashrustError::StorageValidationError(format!(
                            "Failed to decompress {} ramdisk: {error}",
                            compression.label()
                        ))
                    })?;
                (output, compression)
            } else {
                return Err(FlashrustError::StorageValidationError(
                    "Unsupported ramdisk encoding; expected raw newc CPIO, gzip, or LZ4".into(),
                ));
            };

        if !decoded.starts_with(NEWC_MAGIC) && !decoded.starts_with(NEWC_CRC_MAGIC) {
            return Err(FlashrustError::StorageValidationError(format!(
                "{} ramdisk did not decode to a newc CPIO archive",
                compression.label()
            )));
        }
        Ok((decoded, compression))
    }

    fn encode_ramdisk(input: &[u8], compression: RamdiskCompression) -> Result<Vec<u8>> {
        match compression {
            RamdiskCompression::RawCpio => Ok(input.to_vec()),
            RamdiskCompression::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(input).map_err(Self::compression_error)?;
                encoder.finish().map_err(Self::compression_error)
            }
            RamdiskCompression::Lz4Frame => {
                let info = FrameInfo::new();
                let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
                encoder.write_all(input).map_err(Self::compression_error)?;
                encoder.finish().map_err(|error| {
                    FlashrustError::StorageValidationError(format!(
                        "Failed to compress {} ramdisk: {error}",
                        compression.label()
                    ))
                })
            }
            RamdiskCompression::Lz4Legacy => {
                const LEGACY_BLOCK_SIZE: usize = 8 * 1024 * 1024;
                let mut output = Vec::with_capacity(input.len());
                output.extend_from_slice(LZ4_LEGACY_MAGIC);
                for chunk in input.chunks(LEGACY_BLOCK_SIZE) {
                    let compressed = lz4_flex::block::compress(chunk);
                    let block_size = u32::try_from(compressed.len()).map_err(|_| {
                        FlashrustError::StorageValidationError(
                            "Legacy LZ4 block exceeds the 32-bit frame limit".into(),
                        )
                    })?;
                    output.extend_from_slice(&block_size.to_le_bytes());
                    output.extend_from_slice(&compressed);
                }
                Ok(output)
            }
        }
    }

    fn compression_error(error: std::io::Error) -> FlashrustError {
        FlashrustError::StorageValidationError(format!("Failed to compress ramdisk: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_cpio_entry(archive: &mut Vec<u8>, name: &str, data: &[u8], mode: u32) {
        let namesize = name.len() + 1;
        let header = format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            1,
            mode,
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            0,
            0,
            namesize,
            0
        );
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(name.as_bytes());
        archive.push(0);
        archive.resize(archive.len().div_ceil(4) * 4, 0);
        archive.extend_from_slice(data);
        archive.resize(archive.len().div_ceil(4) * 4, 0);
    }

    fn test_cpio() -> Vec<u8> {
        let mut archive = Vec::new();
        append_cpio_entry(
            &mut archive,
            "prop.default",
            b"ro.debuggable=0\nro.adb.secure=1\nkeep.this=value\n",
            0o100644,
        );
        append_cpio_entry(&mut archive, "adb_keys", b"old-key\n", 0o100600);
        append_cpio_entry(&mut archive, "init", b"#!/bin/sh\n", 0o100755);
        append_cpio_entry(&mut archive, "TRAILER!!!", b"", 0);
        archive
    }

    fn test_adb_key() -> Vec<u8> {
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x5au8; 524]);
        format!("{encoded} flashrust-test@localhost\n").into_bytes()
    }

    fn build_v4_boot(ramdisk: &[u8], suffix: &[u8]) -> Vec<u8> {
        let ramdisk_aligned = ramdisk.len().div_ceil(4096) * 4096;
        let mut image = vec![0u8; 4096 + ramdisk_aligned];
        image[0..8].copy_from_slice(b"ANDROID!");
        image[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        image[40..44].copy_from_slice(&4u32.to_le_bytes());
        image[4096..4096 + ramdisk.len()].copy_from_slice(ramdisk);
        image.extend_from_slice(suffix);
        image
    }

    fn occurrences(haystack: &str, needle: &str) -> usize {
        haystack.match_indices(needle).count()
    }

    #[test]
    fn validates_android_adb_public_key_format() {
        let key = test_adb_key();
        let normalized = BootKitchen::validate_adb_public_key(&key).expect("valid ADB key");
        assert_eq!(normalized, key);
        assert!(BootKitchen::validate_adb_public_key(b"ssh-rsa invalid\n").is_err());
        assert!(BootKitchen::validate_adb_public_key(b"\n").is_err());
    }

    #[test]
    fn adb_cpio_patch_is_idempotent_and_replaces_existing_values() {
        let key = test_adb_key();
        let once = ZigEngine::inject_adb_preauth(&test_cpio(), &key).expect("first patch");
        let twice = ZigEngine::inject_adb_preauth(&once, &key).expect("second patch");
        let text = String::from_utf8_lossy(&twice);

        assert_eq!(occurrences(&text, "adb_keys"), 1);
        assert_eq!(occurrences(&text, "ro.debuggable=1"), 1);
        assert_eq!(occurrences(&text, "ro.adb.secure=0"), 1);
        assert_eq!(occurrences(&text, "persist.sys.usb.config=mtp,adb"), 1);
        assert!(!text.contains("ro.debuggable=0"));
        assert!(!text.contains("ro.adb.secure=1"));
        assert!(text.contains("keep.this=value"));
        assert!(twice.windows(key.len()).any(|window| window == key));
    }

    #[test]
    fn adb_cpio_patch_rejects_missing_trailer() {
        let mut malformed = Vec::new();
        append_cpio_entry(&mut malformed, "init", b"#!/bin/sh\n", 0o100755);
        assert!(ZigEngine::inject_adb_preauth(&malformed, &test_adb_key()).is_err());
    }

    #[test]
    fn patches_supported_ramdisk_encodings_and_preserves_suffix() {
        let suffix = b"BOOT-SIGNATURE-AND-TRAILING-DATA";
        let key = test_adb_key();
        for encoding in [
            RamdiskCompression::RawCpio,
            RamdiskCompression::Gzip,
            RamdiskCompression::Lz4Frame,
            RamdiskCompression::Lz4Legacy,
        ] {
            let ramdisk =
                BootKitchen::encode_ramdisk(&test_cpio(), encoding).expect("encode test ramdisk");
            let boot = build_v4_boot(&ramdisk, suffix);
            let (patched, summary) =
                BootKitchen::patch_boot_image_adb_preauth(&boot, &key).expect("patch boot image");

            assert_eq!(summary.ramdisk_compression, encoding);
            assert_eq!(summary.preserved_suffix_bytes, suffix.len());
            assert_eq!(&patched[patched.len() - suffix.len()..], suffix);
            assert_eq!(
                summary.operations,
                vec![PatchOperation::AdbPreauthorization]
            );

            let size = u32::from_le_bytes(patched[12..16].try_into().unwrap()) as usize;
            let (decoded, detected) =
                BootKitchen::decode_ramdisk(&patched[4096..4096 + size]).expect("decode output");
            assert_eq!(detected, encoding);
            let decoded_text = String::from_utf8_lossy(&decoded);
            assert!(decoded_text.contains("ro.debuggable=1"));
        }
    }
}
