use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "flashrust")]
#[command(author = "flashrust Core Team")]
#[command(version = "0.1.0")]
#[command(about = "High-performance dual-engine firmware flashing & bootloader engineering toolkit", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

fn parse_hex_or_dec_u32(s: &str) -> Result<u32, String> {
    let clean = s.trim();
    if let Some(stripped) = clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
    {
        u32::from_str_radix(stripped, 16).map_err(|e| format!("Invalid hex integer '{}': {}", s, e))
    } else {
        clean
            .parse::<u32>()
            .map_err(|e| format!("Invalid integer '{}': {}", s, e))
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Display or query hardware board presets
    Presets {
        /// Target SoC or preset name (optional)
        #[arg(short, long)]
        target: Option<String>,
    },

    /// Validate storage offsets and generate partition plan
    Offset {
        /// Target SoC (e.g., imx8mm, imx8mn, imx8mp, imx8ulp, imx95, imx952)
        #[arg(short, long)]
        soc: String,

        /// Flag if target boots from eMMC boot0 partition
        #[arg(long, default_value_t = false)]
        emmc: bool,

        /// Flag if coprocessor MCU binary is enabled (-m)
        #[arg(short = 'm', long, default_value_t = false)]
        mcu: bool,

        /// Storage capacity in gigabytes (e.g., 16, 32, 64)
        #[arg(short = 'c', long, default_value_t = 32)]
        capacity_gb: u64,
    },

    /// Scan and display attached USB devices and operating modes
    Devices,

    /// Calculate RP2350 hardware QSPI translation window registers
    Rp2350Window {
        /// Subwindow index (0 to 3)
        #[arg(short, long, default_value_t = 0)]
        window: u32,

        /// Physical flash offset (must be 4 KiB aligned, e.g. 0x00010000 or 65536)
        #[arg(short, long, value_parser = parse_hex_or_dec_u32)]
        offset: u32,

        /// Target Core Mode: 'arm-secure', 'arm-nonsecure', or 'riscv'
        #[arg(short, long, default_value = "arm-nonsecure")]
        mode: String,
    },

    /// Plan NXP SDP (Serial Download Protocol) upload chunking
    SdpPlan {
        /// Target RAM address (e.g., 0x40000000 for i.MX 8M)
        #[arg(short, long, default_value = "0x40000000", value_parser = parse_hex_or_dec_u32)]
        address: u32,

        /// Payload size in bytes
        #[arg(short, long)]
        size: usize,

        /// Chunk size in bytes (default 512 KiB)
        #[arg(short, long, default_value_t = 524288)]
        chunk_size: usize,
    },

    /// In-memory patch an Android Boot Image or GKI init_boot.img (KernelSU / Magisk init hijack)
    PatchBoot {
        /// Path to input boot/init_boot image
        #[arg(short = 'b', long)]
        image: String,

        /// Optional path to custom init executable payload (e.g. ksuinit or magiskinit). Optional if using --adb-preauth
        #[arg(short = 'p', long)]
        init_payload: Option<String>,

        /// Output path for patched boot image
        #[arg(short = 'o', long)]
        output: String,

        /// Injection target type: 'kernelsu' (default) or 'magisk'
        #[arg(short = 't', long, default_value = "kernelsu")]
        target: String,

        /// Optional path to SELinux policy file to inject permissive su rules
        #[arg(short = 's', long)]
        selinux_policy: Option<String>,

        /// Force early-boot USB debugging & pre-authorize host Mac ADB key (`~/.android/adbkey.pub` + `ro.debuggable=1`, `ro.adb.secure=0`)
        #[arg(long, default_value_t = false)]
        adb_preauth: bool,

        /// Android ADB public key path; defaults to `~/.android/adbkey.pub`
        #[arg(long, requires = "adb_preauth")]
        adb_pubkey: Option<String>,

        /// Confirm that the device bootloader accepts custom boot images
        #[arg(long, default_value_t = false, requires = "adb_preauth")]
        confirm_unlocked: bool,

        /// Permit replacing the input file when output resolves to the same path
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Detect SU binary architecture and compilation requirements for connected/specified target
    DetectSu {
        /// Optional target SoC or preset name
        #[arg(short, long)]
        preset: Option<String>,
    },

    /// Build a standalone static SU binary for the detected or specified target architecture
    BuildSu {
        /// Target architecture override: 'aarch64', 'armv7a', 'x86_64', or 'riscv64'
        #[arg(short, long)]
        arch: Option<String>,

        /// Output directory (default: target/su)
        #[arg(short, long, default_value = "target/su")]
        output: String,
    },

    /// Stream-verify an Android Sparse Image (0xED26FF3A) or raw partition image (CRC32 + SHA-256)
    Verify {
        /// Path to sparse or raw image file
        #[arg(short, long)]
        image: String,
    },

    /// Inspect or patch Android Verified Boot (AVB 2.0) vbmeta.img dm-verity/verification flags
    Vbmeta {
        /// Path to input vbmeta.img
        #[arg(short, long)]
        image: String,

        /// Optional output path to write vbmeta.img with dm-verity & verification disabled (flags |= 0x3)
        #[arg(short, long)]
        disable_verity_output: Option<String>,
    },

    /// Flash Samsung firmware through the bundled real Heimdall USB engine
    SamsungFlash {
        /// Optional BL (Bootloader) .tar / .tar.md5 path
        #[arg(long)]
        bl: Option<String>,

        /// Optional AP (System/Boot) .tar / .tar.md5 path
        #[arg(long)]
        ap: Option<String>,

        /// Optional CP (Modem/Radio) .tar / .tar.md5 path
        #[arg(long)]
        cp: Option<String>,

        /// Optional CSC / HOME_CSC .tar / .tar.md5 path
        #[arg(long)]
        csc: Option<String>,

        /// Optional device-specific .pit file used to validate archive-to-partition mappings
        #[arg(long)]
        pit: Option<String>,

        /// FRP Lock state shown by Download Mode ('on' or 'off')
        #[arg(long, default_value = "on")]
        frp_lock: String,

        /// Knox Guard state: completed, checking, prenormal, or locked
        #[arg(long, default_value = "completed")]
        kg_state: String,

        /// Confirm that Download Mode reports OEM unlock enabled
        #[arg(long, default_value_t = false)]
        oem_unlock: bool,

        /// Whether custom root/BootKitchen patch is active
        #[arg(long, default_value_t = false)]
        custom_binary: bool,

        /// Leave the device in Download Mode after a successful flash
        #[arg(long, default_value_t = false)]
        no_reboot: bool,
    },

    /// Read-only inspection of an AOSP `frp` / `persistent` partition image
    InspectFrp {
        /// Path to `frp.img` / `persistent.img` to inspect
        #[arg(short, long)]
        image: String,
    },

    /// Probe Real vs. Fake Download Mode and reboot Samsung device into real Odin/Loke Download Mode (`AT+FUS?` / `adb reboot download`)
    RebootDownload {
        /// Optional serial port override (e.g. `/dev/cu.usbmodem1121201`)
        #[arg(short, long)]
        port: Option<String>,

        /// Only probe whether the device is in Real Loke Download Mode vs. Fake/Factory AT Mode without sending reboot
        #[arg(long, default_value_t = false)]
        probe_only: bool,
    },

    /// Display dual-engine runtime information (Rust Host + Zig Bare-Metal)
    Engine,

    /// Launch interactive terminal dashboard (TUI)
    Tui,

    /// Launch the native desktop reactive GUI window
    Gui,
}
