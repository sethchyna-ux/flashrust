use crate::error::{FlashrustError, Result};
use serde::{Deserialize, Serialize};

pub const GPT_HEADER_SIZE_BYTES: u64 = 17 * 1024; // 17 kB (LBA 0–33)
pub const MCU_BINARY_OFFSET_KB: u64 = 5120; // 5120 kB (5.12 MB)

pub const PARTITION_TABLE_13GB: &str = "partition-table-13GB.img";
pub const PARTITION_TABLE_DEFAULT: &str = "partition-table.img";

/// Returns the required SPL (Secondary Program Loader) offset in kB.
pub fn get_required_spl_offset_kb(soc_name: &str, is_emmc_boot: bool) -> u64 {
    if is_emmc_boot {
        return 0; // eMMC boot0 hardware partition starts at offset 0
    }
    match soc_name.to_ascii_lowercase().as_str() {
        "imx8mm" | "imx8mq" => 33, // 33 kB offset for 8M Mini / 8M Quad MMC
        "imx8mn" => 32,           // 32 kB offset for 8M Nano MMC
        "imx8mp" | "imx8ulp" | "imx95" | "imx952" => 32, // 32 kB offset for SD
        _ => 32,
    }
}

/// Determines the proper partition table image according to storage card capacity.
pub fn select_partition_table_image(storage_capacity_bytes: u64) -> &'static str {
    const GIB_16: u64 = 16 * 1024 * 1024 * 1024;
    if storage_capacity_bytes <= GIB_16 {
        PARTITION_TABLE_13GB
    } else {
        PARTITION_TABLE_DEFAULT
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLayoutPlan {
    pub soc_name: String,
    pub is_emmc_boot: bool,
    pub spl_offset_kb: u64,
    pub spl_offset_bytes: u64,
    pub gpt_header_bytes: u64,
    pub mcu_firmware_enabled: bool,
    pub mcu_offset_kb: Option<u64>,
    pub storage_capacity_bytes: u64,
    pub partition_table_image: String,
}

pub fn create_storage_layout_plan(
    soc_name: &str,
    is_emmc_boot: bool,
    has_mcu_firmware: bool,
    storage_capacity_bytes: u64,
) -> Result<StorageLayoutPlan> {
    let spl_kb = get_required_spl_offset_kb(soc_name, is_emmc_boot);
    let spl_bytes = spl_kb * 1024;

    // Check boundary overlap with GPT header on non-eMMC
    if !is_emmc_boot && spl_bytes < GPT_HEADER_SIZE_BYTES {
        return Err(FlashrustError::StorageValidationError(format!(
            "SPL offset ({} bytes) collides with Primary GPT header ({} bytes)",
            spl_bytes, GPT_HEADER_SIZE_BYTES
        )));
    }

    let mcu_offset = if has_mcu_firmware {
        Some(MCU_BINARY_OFFSET_KB)
    } else {
        None
    };

    let partition_img = select_partition_table_image(storage_capacity_bytes);

    Ok(StorageLayoutPlan {
        soc_name: soc_name.to_string(),
        is_emmc_boot,
        spl_offset_kb: spl_kb,
        spl_offset_bytes: spl_bytes,
        gpt_header_bytes: GPT_HEADER_SIZE_BYTES,
        mcu_firmware_enabled: has_mcu_firmware,
        mcu_offset_kb: mcu_offset,
        storage_capacity_bytes,
        partition_table_image: partition_img.to_string(),
    })
}
