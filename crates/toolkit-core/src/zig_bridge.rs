use crate::error::{FlashrustError, Result};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn flashrust_zig_version() -> *const c_char;
    fn flashrust_zig_parse_cpio_header(
        data_ptr: *const u8,
        data_len: usize,
        out_filesize: *mut u64,
        out_namesize: *mut u32,
    ) -> c_int;
    fn flashrust_zig_patch_cpio_init(
        input_ptr: *const u8,
        input_len: usize,
        inject_ptr: *const u8,
        inject_len: usize,
        out_buf_ptr: *mut u8,
        out_buf_cap: usize,
        out_len: *mut usize,
    ) -> c_int;
    fn flashrust_zig_inject_su_binary(
        input_ptr: *const u8,
        input_len: usize,
        su_ptr: *const u8,
        su_len: usize,
        path_ptr: *const u8,
        path_len: usize,
        is_setuid: c_int,
        replace_init: c_int,
        out_buf_ptr: *mut u8,
        out_buf_cap: usize,
        out_len: *mut usize,
    ) -> c_int;
    fn flashrust_zig_parse_boot_image(
        data_ptr: *const u8,
        data_len: usize,
        out_version: *mut u32,
        out_kernel_size: *mut u32,
        out_ramdisk_size: *mut u32,
        out_ramdisk_offset: *mut usize,
        out_page_size: *mut u32,
    ) -> c_int;
    fn flashrust_zig_inject_selinux_rules(
        policy_ptr: *const u8,
        policy_len: usize,
        out_buf_ptr: *mut u8,
        out_buf_cap: usize,
        out_len: *mut usize,
    ) -> c_int;
    fn flashrust_zig_calculate_qspi_window(
        window_idx: u32,
        physical_offset: u32,
        out_virtual_base: *mut u32,
        out_register_val: *mut u32,
    ) -> c_int;
    fn flashrust_zig_verify_rp2350_image_def(
        data_ptr: *const u8,
        data_len: usize,
        out_mode: *mut u32,
    ) -> c_int;
    fn flashrust_zig_seal_rp2350_image_def(
        buf_ptr: *mut u8,
        buf_len: usize,
        mode_val: u32,
        entry_point: u32,
    ) -> c_int;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootHeaderVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootImageMetadata {
    pub version: BootHeaderVersion,
    pub kernel_size: u32,
    pub ramdisk_size: u32,
    pub ramdisk_offset: usize,
    pub page_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Rp2350CoreMode {
    ArmSecure = 0x0,
    ArmNonSecure = 0x1,
    RiscVMachine = 0x2,
}

impl Rp2350CoreMode {
    pub fn from_u32(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::ArmSecure),
            1 => Ok(Self::ArmNonSecure),
            2 => Ok(Self::RiscVMachine),
            other => Err(FlashrustError::ZigEngineError(
                other as i32,
                "Unknown RP2350 Core Mode".into(),
            )),
        }
    }
}

pub struct ZigEngine;

impl ZigEngine {
    /// Retrieve the compile-time version string of the Zig Bare-Metal Engine.
    pub fn version() -> &'static str {
        unsafe {
            let ptr = flashrust_zig_version();
            if ptr.is_null() {
                "unknown"
            } else {
                CStr::from_ptr(ptr).to_str().unwrap_or("invalid-utf8")
            }
        }
    }

    /// Zero-copy CPIO newc header parsing using the Zig engine.
    pub fn parse_cpio_header(data: &[u8]) -> Result<(u64, u32)> {
        let mut filesize: u64 = 0;
        let mut namesize: u32 = 0;

        let ret = unsafe {
            flashrust_zig_parse_cpio_header(
                data.as_ptr(),
                data.len(),
                &mut filesize,
                &mut namesize,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "Failed to parse CPIO newc header".into(),
            ));
        }

        Ok((filesize, namesize))
    }

    /// In-memory AST CPIO patcher:
    /// Renames /init to /init.real and injects an in-memory init executable (KernelSU or Magisk).
    pub fn patch_cpio_init(
        input_cpio: &[u8],
        injected_init_binary: &[u8],
    ) -> Result<Vec<u8>> {
        // Output capacity: original + injected init + headers + alignment padding
        let est_capacity = input_cpio.len() + injected_init_binary.len() + 1024;
        let mut output = vec![0u8; est_capacity];
        let mut written_len: usize = 0;

        let ret = unsafe {
            flashrust_zig_patch_cpio_init(
                input_cpio.as_ptr(),
                input_cpio.len(),
                injected_init_binary.as_ptr(),
                injected_init_binary.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written_len,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "In-memory CPIO init hijack patching failed".into(),
            ));
        }

        output.truncate(written_len);
        Ok(output)
    }

    /// In-memory SU binary injector:
    /// Injects `su_binary` at `target_path` with root:root (0:0),
    /// setuid permissions (0o104755 if `is_setuid` is true, else 0o100755),
    /// and optionally replaces /init -> /init.real if `replace_init` is true.
    pub fn inject_su_binary(
        input_cpio: &[u8],
        su_binary: &[u8],
        target_path: &str,
        is_setuid: bool,
        replace_init: bool,
    ) -> Result<Vec<u8>> {
        let est_capacity = input_cpio.len() + su_binary.len() * 2 + 2048;
        let mut output = vec![0u8; est_capacity];
        let mut written_len: usize = 0;

        let ret = unsafe {
            flashrust_zig_inject_su_binary(
                input_cpio.as_ptr(),
                input_cpio.len(),
                su_binary.as_ptr(),
                su_binary.len(),
                target_path.as_ptr(),
                target_path.len(),
                if is_setuid { 1 } else { 0 },
                if replace_init { 1 } else { 0 },
                output.as_mut_ptr(),
                output.len(),
                &mut written_len,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "In-memory SU binary injection failed".into(),
            ));
        }

        output.truncate(written_len);
        Ok(output)
    }

    /// Parse Android Boot Image Header (v0-v4).
    pub fn parse_boot_image(data: &[u8]) -> Result<BootImageMetadata> {
        let mut ver: u32 = 0;
        let mut kernel_size: u32 = 0;
        let mut ramdisk_size: u32 = 0;
        let mut ramdisk_offset: usize = 0;
        let mut page_size: u32 = 0;

        let ret = unsafe {
            flashrust_zig_parse_boot_image(
                data.as_ptr(),
                data.len(),
                &mut ver,
                &mut kernel_size,
                &mut ramdisk_size,
                &mut ramdisk_offset,
                &mut page_size,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "Failed to parse Android Boot Image Header".into(),
            ));
        }

        let version = match ver {
            1 => BootHeaderVersion::V1,
            2 => BootHeaderVersion::V2,
            3 => BootHeaderVersion::V3,
            4 => BootHeaderVersion::V4,
            _ => BootHeaderVersion::V0,
        };

        Ok(BootImageMetadata {
            version,
            kernel_size,
            ramdisk_size,
            ramdisk_offset,
            page_size,
        })
    }

    /// Inject live KernelSU permissive domain transitions into SELinux policy buffer.
    pub fn inject_selinux_rules(policy_data: &[u8]) -> Result<Vec<u8>> {
        let mut output = vec![0u8; policy_data.len() + 1024];
        let mut written_len: usize = 0;

        let ret = unsafe {
            flashrust_zig_inject_selinux_rules(
                policy_data.as_ptr(),
                policy_data.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut written_len,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "Failed to inject SELinux policy rules".into(),
            ));
        }

        output.truncate(written_len);
        Ok(output)
    }

    /// Calculate RP2350 QSPI window virtual base and hardware register value.
    pub fn calculate_qspi_window(window_idx: u32, physical_offset: u32) -> Result<(u32, u32)> {
        let mut virtual_base: u32 = 0;
        let mut reg_val: u32 = 0;

        let ret = unsafe {
            flashrust_zig_calculate_qspi_window(
                window_idx,
                physical_offset,
                &mut virtual_base,
                &mut reg_val,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                format!(
                    "Invalid RP2350 QSPI window calculation (idx: {}, offset: 0x{:08x})",
                    window_idx, physical_offset
                ),
            ));
        }

        Ok((virtual_base, reg_val))
    }

    /// Verify an RP2350 256-byte IMAGE_DEF block.
    pub fn verify_rp2350_image_def(data: &[u8]) -> Result<Rp2350CoreMode> {
        let mut mode: u32 = 0;
        let ret = unsafe {
            flashrust_zig_verify_rp2350_image_def(data.as_ptr(), data.len(), &mut mode)
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "RP2350 IMAGE_DEF verification failed (invalid magic or mode)".into(),
            ));
        }

        Rp2350CoreMode::from_u32(mode)
    }

    /// Seal an RP2350 256-byte IMAGE_DEF block in-place.
    pub fn seal_rp2350_image_def(
        buffer: &mut [u8],
        mode: Rp2350CoreMode,
        entry_point: u32,
    ) -> Result<()> {
        if buffer.len() < 256 {
            return Err(FlashrustError::BufferTooSmall {
                expected: 256,
                actual: buffer.len(),
            });
        }

        let ret = unsafe {
            flashrust_zig_seal_rp2350_image_def(
                buffer.as_mut_ptr(),
                buffer.len(),
                mode as u32,
                entry_point,
            )
        };

        if ret != 0 {
            return Err(FlashrustError::ZigEngineError(
                ret,
                "Failed to seal RP2350 IMAGE_DEF block".into(),
            ));
        }

        Ok(())
    }
}
