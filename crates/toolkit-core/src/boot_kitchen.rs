use crate::error::{FlashrustError, Result};
use crate::zig_bridge::{BootHeaderVersion, ZigEngine};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitHijackTarget {
    KernelSU,
    Magisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchSummary {
    pub header_version: String,
    pub original_ramdisk_size: usize,
    pub patched_ramdisk_size: usize,
    pub target: InitHijackTarget,
    pub selinux_patched: bool,
}

pub struct BootKitchen;

impl BootKitchen {
    /// In-memory GKI / Android Boot Image patching.
    /// Extracts ramdisk directly from RAM buffer, patches /init -> /init.real,
    /// injects the hijack init payload, and reconstructs the boot image.
    pub fn patch_boot_image(
        boot_img_bytes: &[u8],
        init_payload: &[u8],
        target: InitHijackTarget,
        selinux_policy: Option<&[u8]>,
    ) -> Result<(Vec<u8>, PatchSummary)> {
        // 1. Parse Boot Header
        let meta = ZigEngine::parse_boot_image(boot_img_bytes)?;

        if meta.ramdisk_size == 0 {
            return Err(FlashrustError::StorageValidationError(
                "Boot image contains empty ramdisk segment".into(),
            ));
        }

        let ramdisk_start = meta.ramdisk_offset;
        let ramdisk_end = ramdisk_start + meta.ramdisk_size as usize;

        if ramdisk_end > boot_img_bytes.len() {
            return Err(FlashrustError::BufferTooSmall {
                expected: ramdisk_end,
                actual: boot_img_bytes.len(),
            });
        }

        let raw_ramdisk = &boot_img_bytes[ramdisk_start..ramdisk_end];

        // 2. Patch CPIO in RAM
        let patched_ramdisk = ZigEngine::patch_cpio_init(raw_ramdisk, init_payload)?;

        // 3. Optional SELinux Policy Patching
        let selinux_patched = if let Some(policy) = selinux_policy {
            let _ = ZigEngine::inject_selinux_rules(policy)?;
            true
        } else {
            false
        };

        // 4. Construct output boot image buffer with updated header and patched ramdisk
        let mut new_boot_img = boot_img_bytes.to_vec();

        // Calculate page aligned new ramdisk size
        let page_size = meta.page_size as usize;
        let new_ramdisk_size = patched_ramdisk.len();
        let new_ramdisk_aligned_size = (new_ramdisk_size + page_size - 1) / page_size * page_size;

        // Truncate at ramdisk start
        new_boot_img.truncate(ramdisk_start);
        new_boot_img.extend_from_slice(&patched_ramdisk);

        // Zero-pad to page boundary
        let pad_len = new_ramdisk_aligned_size - new_ramdisk_size;
        if pad_len > 0 {
            new_boot_img.resize(new_boot_img.len() + pad_len, 0);
        }

        // Update ramdisk_size in header
        match meta.version {
            BootHeaderVersion::V3 | BootHeaderVersion::V4 => {
                // In v3/v4: ramdisk_size is at offset 12..16
                let size_bytes = (new_ramdisk_size as u32).to_le_bytes();
                new_boot_img[12..16].copy_from_slice(&size_bytes);
            }
            _ => {
                // In v0..v2: ramdisk_size is at offset 16..20
                let size_bytes = (new_ramdisk_size as u32).to_le_bytes();
                new_boot_img[16..20].copy_from_slice(&size_bytes);
            }
        }

        let summary = PatchSummary {
            header_version: format!("{:?}", meta.version),
            original_ramdisk_size: meta.ramdisk_size as usize,
            patched_ramdisk_size: new_ramdisk_size,
            target,
            selinux_patched,
        };

        Ok((new_boot_img, summary))
    }
}
