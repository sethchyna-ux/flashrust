use crate::board_presets::BoardPreset;
use crate::error::{FlashrustError, Result};
use crate::usb_monitor::UsbDeviceInfo;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetCpuArch {
    Aarch64,
    ArmV7a,
    X86_64,
    Riscv64,
    Unknown,
}

impl TargetCpuArch {
    pub fn label(&self) -> &'static str {
        match self {
            TargetCpuArch::Aarch64 => "ARM64 (aarch64)",
            TargetCpuArch::ArmV7a => "ARM 32-bit (armv7a)",
            TargetCpuArch::X86_64 => "x86_64 (AMD64)",
            TargetCpuArch::Riscv64 => "RISC-V 64 (riscv64)",
            TargetCpuArch::Unknown => "Unknown Architecture",
        }
    }

    pub fn target_triple(&self) -> &'static str {
        match self {
            TargetCpuArch::Aarch64 => "aarch64-linux-musl",
            TargetCpuArch::ArmV7a => "arm-linux-musleabihf",
            TargetCpuArch::X86_64 => "x86_64-linux-musl",
            TargetCpuArch::Riscv64 => "riscv64-linux-musl",
            TargetCpuArch::Unknown => "aarch64-linux-musl",
        }
    }

    pub fn android_abi(&self) -> &'static str {
        match self {
            TargetCpuArch::Aarch64 => "arm64-v8a",
            TargetCpuArch::ArmV7a => "armeabi-v7a",
            TargetCpuArch::X86_64 => "x86_64",
            TargetCpuArch::Riscv64 => "riscv64",
            TargetCpuArch::Unknown => "arm64-v8a",
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(
            self,
            TargetCpuArch::Aarch64 | TargetCpuArch::X86_64 | TargetCpuArch::Riscv64
        )
    }

    pub fn elf_machine(&self) -> u16 {
        match self {
            TargetCpuArch::Aarch64 => 0x00B7, // EM_AARCH64
            TargetCpuArch::ArmV7a => 0x0028,  // EM_ARM
            TargetCpuArch::X86_64 => 0x003E,  // EM_X86_64
            TargetCpuArch::Riscv64 => 0x00F3, // EM_RISCV
            TargetCpuArch::Unknown => 0x00B7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuBuildRequirements {
    pub target_arch: TargetCpuArch,
    pub target_triple: &'static str,
    pub android_abi: &'static str,
    pub is_64bit: bool,
    pub device_name: String,
    pub linkage: &'static str,
    pub compiler_required: &'static str,
    pub compiler_detected: bool,
    pub compiler_version: Option<String>,
    pub compiler_path: Option<PathBuf>,
    pub ndk_detected: bool,
    pub ndk_path: Option<PathBuf>,
    pub source_ready: bool,
    pub source_name: &'static str,
    pub selinux_context: &'static str,
    pub injection_path: &'static str,
    pub permissions_mode: u32,
    pub estimated_binary_size_kb: u32,
    pub can_build: bool,
    pub notes: Vec<String>,
}

/// Embedded, standalone, zero-dependency static C source for Android/Linux SU binary.
pub const STANDALONE_SU_C_SOURCE: &str = r#"/*
 * flashrust-su: High-performance, standalone SetUID root supervisor
 * Built with musl libc - Zero runtime dynamic linker/Bionic dependencies.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <grp.h>

#define FLASH_SU_VERSION "flashrust-su v1.0.0 (Static MUSL, Zero-Dependency)"

static void setup_selinux_context(const char *ctx) {
    int fd = open("/proc/thread-self/attr/current", O_WRONLY);
    if (fd < 0) {
        fd = open("/proc/self/attr/current", O_WRONLY);
    }
    if (fd >= 0) {
        (void)write(fd, ctx, strlen(ctx));
        close(fd);
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("%s\n", FLASH_SU_VERSION);
            return 0;
        }
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("Usage: su [options] [-] [user [argument...]]\n\n");
            printf("Options:\n");
            printf("  -c, -c <command>    Pass command string directly to root shell\n");
            printf("  -s, --shell <shell> Use specified shell instead of default\n");
            printf("  -v, -V, --version   Display version code and build metadata\n");
            printf("  -h, --help          Display this help message\n");
            return 0;
        }
    }

    /* Elevate privileges to root (UID 0, GID 0) */
    (void)setgroups(0, NULL);
    if (setresgid(0, 0, 0) < 0) {
        perror("su: warning - setresgid(0) failed");
    }
    if (setresuid(0, 0, 0) < 0) {
        perror("su: fatal - setresuid(0) failed");
        return 1;
    }

    /* Transition SELinux domain to root su domain */
    setup_selinux_context("u:r:su:s0");

    /* Populate sanitized root execution environment */
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("HOME", "/root", 0);
    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin:/vendor/xbin:/bin:/usr/bin", 1);

    const char *shell = "/system/bin/sh";
    if (access(shell, X_OK) != 0) {
        shell = "/bin/sh";
    }

    /* Custom shell override */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--shell") == 0) && (i + 1 < argc)) {
            shell = argv[i + 1];
            break;
        }
    }

    /* Command execution (-c <command>) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && (i + 1 < argc)) {
            char *const cmd_args[] = { (char *)shell, "-c", argv[i + 1], NULL };
            execv(shell, cmd_args);
            perror("su: execv failed");
            return 1;
        }
    }

    char *const default_args[] = { (char *)shell, NULL };
    execv(shell, default_args);
    perror("su: execv failed");
    return 1;
}
"#;

pub struct SuDetector;

impl SuDetector {
    /// Detects target architecture and toolchain requirements for the detected device.
    pub fn detect(
        device: Option<&UsbDeviceInfo>,
        preset: Option<&BoardPreset>,
    ) -> SuBuildRequirements {
        let mut target_arch = TargetCpuArch::Aarch64; // Default to modern 64-bit ARM
        let mut dev_label = "Universal ARM64 Target".to_string();
        let mut notes = Vec::new();

        // 1. Identify device from attached USB device
        if let Some(dev) = device {
            let prod = dev.product.as_deref().unwrap_or("USB Device");
            let mfg = dev.manufacturer.as_deref().unwrap_or("");
            dev_label = format!(
                "{} {} [{:04x}:{:04x}]",
                mfg, prod, dev.vendor_id, dev.product_id
            )
            .trim()
            .to_string();

            match (dev.vendor_id, dev.product_id) {
                // Samsung Galaxy Devices
                (0x04E8, _) => {
                    target_arch = TargetCpuArch::Aarch64;
                    notes.push("Detected Samsung Galaxy architecture: ARM64 (arm64-v8a)".into());
                }
                // Motorola Devices
                (0x22B8, _) => {
                    target_arch = TargetCpuArch::Aarch64;
                    notes.push("Detected Motorola architecture: ARM64 (arm64-v8a)".into());
                }
                // Google Pixel
                (0x18D1, _) => {
                    target_arch = TargetCpuArch::Aarch64;
                    notes.push("Detected Google Tensor / Qualcomm Pixel: ARM64 (arm64-v8a)".into());
                }
                // NXP i.MX Series
                (0x1FC9, _) | (0x15A2, _) => {
                    if let Some(p) = preset {
                        if p.soc.starts_with("imx8") || p.soc.starts_with("imx9") {
                            target_arch = TargetCpuArch::Aarch64;
                            notes.push(format!(
                                "Detected NXP {} SoC: 64-bit ARM Cortex-A53/A55",
                                p.soc
                            ));
                        } else {
                            target_arch = TargetCpuArch::ArmV7a;
                            notes.push(format!(
                                "Detected NXP {} SoC: 32-bit ARM Cortex-A7/A9",
                                p.soc
                            ));
                        }
                    } else {
                        target_arch = TargetCpuArch::Aarch64;
                    }
                }
                // Xiaomi / OnePlus / Qualcomm / MediaTek
                (0x2717, _) | (0x22D9, _) | (0x05C6, _) | (0x0E8D, _) => {
                    target_arch = TargetCpuArch::Aarch64;
                    notes.push(
                        "Detected Qualcomm / MediaTek architecture: ARM64 (arm64-v8a)".into(),
                    );
                }
                // Raspberry Pi RP2350
                (0x2E8A, 0x000F) => {
                    target_arch = TargetCpuArch::ArmV7a;
                    notes.push("RP2350 microcontroller target (Microcontroller bare-metal)".into());
                }
                _ => {
                    // Check preset if available
                    if let Some(p) = preset {
                        if p.soc.starts_with("imx6") || p.soc.starts_with("imx7") {
                            target_arch = TargetCpuArch::ArmV7a;
                        } else {
                            target_arch = TargetCpuArch::Aarch64;
                        }
                    }
                }
            }
        } else if let Some(p) = preset {
            dev_label = format!("Board Profile: {}", p.name);
            if p.soc.starts_with("imx6") || p.soc.starts_with("imx7") {
                target_arch = TargetCpuArch::ArmV7a;
                notes.push(format!("Profile {} specifies 32-bit ARM target", p.name));
            } else {
                target_arch = TargetCpuArch::Aarch64;
                notes.push(format!("Profile {} specifies 64-bit ARM target", p.name));
            }
        }

        // 2. Inspect host cross-compilation toolchains
        let (zig_detected, zig_version, zig_path) = Self::detect_zig();
        let (ndk_detected, ndk_path) = Self::detect_ndk();

        if zig_detected {
            notes.push(format!(
                "Compiler: Zig {} available (Universal zero-dependency cross-compilation for {})",
                zig_version.as_deref().unwrap_or(""),
                target_arch.target_triple()
            ));
        } else {
            notes.push("Warning: Zig compiler not detected on system PATH".into());
        }

        if ndk_detected {
            notes.push(format!(
                "Android NDK detected at {}",
                ndk_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ));
        }

        notes.push("C Runtime: musl-libc static (No Bionic dynamic linker / version lock)".into());
        notes.push("Privilege: SetUID root (chmod 04755, uid:0, gid:0)".into());
        notes.push("SELinux: Permissive context transition to 'u:r:su:s0'".into());

        SuBuildRequirements {
            target_arch,
            target_triple: target_arch.target_triple(),
            android_abi: target_arch.android_abi(),
            is_64bit: target_arch.is_64bit(),
            device_name: dev_label,
            linkage: "Static ELF (Zero-Dependency musl)",
            compiler_required: "Zig C/C++ Cross-Compiler (zig cc)",
            compiler_detected: zig_detected,
            compiler_version: zig_version,
            compiler_path: zig_path,
            ndk_detected,
            ndk_path,
            source_ready: true,
            source_name: "Embedded Standalone SU Engine (Hardened POSIX/Android)",
            selinux_context: "u:r:su:s0 (Permissive Domain)",
            injection_path: "system/bin/su",
            permissions_mode: 0o104755,
            estimated_binary_size_kb: 22,
            can_build: zig_detected,
            notes,
        }
    }

    fn detect_zig() -> (bool, Option<String>, Option<PathBuf>) {
        if let Ok(out) = Command::new("zig").arg("version").output()
            && out.status.success()
        {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let path = Command::new("which")
                .arg("zig")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|p| PathBuf::from(p.trim()));
            return (true, Some(ver), path);
        }
        (false, None, None)
    }

    fn detect_ndk() -> (bool, Option<PathBuf>) {
        if let Ok(val) = std::env::var("ANDROID_NDK_HOME") {
            let p = PathBuf::from(val);
            if p.exists() {
                return (true, Some(p));
            }
        }
        if let Ok(val) = std::env::var("ANDROID_HOME") {
            let ndk = PathBuf::from(val).join("ndk");
            if ndk.exists() {
                return (true, Some(ndk));
            }
        }
        (false, None)
    }

    /// Compiles a standalone static SU binary tailored for the detected requirements.
    pub fn build(requirements: &SuBuildRequirements, output_dir: &Path) -> Result<PathBuf> {
        if !requirements.can_build {
            return Err(FlashrustError::StorageValidationError(
                "Cannot build SU binary: Zig cross-compiler is not available on PATH".into(),
            ));
        }

        fs::create_dir_all(output_dir).map_err(|e| FlashrustError::IoError(e.to_string()))?;

        let src_path = output_dir.join("standalone_su.c");
        fs::write(&src_path, STANDALONE_SU_C_SOURCE)
            .map_err(|e| FlashrustError::IoError(format!("Failed to write SU source: {}", e)))?;

        let out_bin = output_dir.join("su");

        // Invoke zig cc to cross-compile static binary
        let output = Command::new("zig")
            .arg("cc")
            .arg("-target")
            .arg(requirements.target_triple)
            .arg("-static")
            .arg("-O2")
            .arg("-s")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-o")
            .arg(&out_bin)
            .arg(&src_path)
            .output()
            .map_err(|e| FlashrustError::IoError(format!("Failed to launch zig cc: {}", e)))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(FlashrustError::StorageValidationError(format!(
                "Zig compilation failed for target {}: {}",
                requirements.target_triple, err_msg
            )));
        }

        // Validate generated binary
        let bin_bytes = fs::read(&out_bin).map_err(|e| {
            FlashrustError::IoError(format!("Failed to read compiled SU binary: {}", e))
        })?;

        if bin_bytes.len() < 52 {
            return Err(FlashrustError::StorageValidationError(
                "Compiled SU binary is corrupt or too small".into(),
            ));
        }

        // Validate ELF magic: \x7F 'E' 'L' 'F'
        if &bin_bytes[0..4] != b"\x7fELF" {
            return Err(FlashrustError::StorageValidationError(
                "Compiled output is not a valid ELF binary".into(),
            ));
        }

        // Validate ELF machine architecture
        let machine = u16::from_le_bytes([bin_bytes[18], bin_bytes[19]]);
        let expected_machine = requirements.target_arch.elf_machine();
        if machine != expected_machine {
            return Err(FlashrustError::StorageValidationError(format!(
                "ELF machine mismatch: expected 0x{:04x}, got 0x{:04x}",
                expected_machine, machine
            )));
        }

        Ok(out_bin)
    }
}
