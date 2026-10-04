use crate::error::{FlashrustError, Result};
use crate::zig_bridge::{Rp2350CoreMode, ZigEngine};
use serde::{Deserialize, Serialize};

pub const RP2350_FLASH_VIRTUAL_BASE: u32 = 0x1000_0000;
pub const RP2350_SUBWINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
pub const RP2350_PAGE_ALIGNMENT: u32 = 4096; // 4 KiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcpBenchmarkProfile {
    pub operation: &'static str,
    pub software_cycles: f64,
    pub dcp_hardware_cycles: f64,
    pub speedup_factor: f64,
}

pub const DCP_PROFILES: &[DcpBenchmarkProfile] = &[
    DcpBenchmarkProfile {
        operation: "f64 Addition (__aeabi_dadd)",
        software_cycles: 150.0,
        dcp_hardware_cycles: 23.8,
        speedup_factor: 6.30,
    },
    DcpBenchmarkProfile {
        operation: "f64 Multiplication (__aeabi_dmul)",
        software_cycles: 117.0,
        dcp_hardware_cycles: 41.0,
        speedup_factor: 2.85,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QspiWindowMapping {
    pub window_index: u32,
    pub virtual_base_address: u32,
    pub physical_flash_offset: u32,
    pub hardware_register_val: u32,
    pub target_mode: Rp2350CoreMode,
}

pub struct Rp2350Manager;

impl Rp2350Manager {
    /// Calculate the hardware QSPI window translation register and virtual address range.
    pub fn configure_qspi_window(
        window_idx: u32,
        physical_offset: u32,
        mode: Rp2350CoreMode,
    ) -> Result<QspiWindowMapping> {
        let (virtual_base, reg_val) = ZigEngine::calculate_qspi_window(window_idx, physical_offset)?;

        Ok(QspiWindowMapping {
            window_index: window_idx,
            virtual_base_address: virtual_base,
            physical_flash_offset: physical_offset,
            hardware_register_val: reg_val,
            target_mode: mode,
        })
    }

    /// Seal an in-memory application binary with the 256-byte RP2350 IMAGE_DEF header.
    pub fn seal_binary(
        binary_data: &mut [u8],
        mode: Rp2350CoreMode,
        entry_point: u32,
    ) -> Result<()> {
        if binary_data.len() < 256 {
            return Err(FlashrustError::BufferTooSmall {
                expected: 256,
                actual: binary_data.len(),
            });
        }
        ZigEngine::seal_rp2350_image_def(&mut binary_data[0..256], mode, entry_point)
    }
}
