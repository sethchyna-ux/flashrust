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
    if let Some(stripped) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
        u32::from_str_radix(stripped, 16).map_err(|e| format!("Invalid hex integer '{}': {}", s, e))
    } else {
        clean.parse::<u32>().map_err(|e| format!("Invalid integer '{}': {}", s, e))
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

        /// Path to custom init executable payload (e.g. ksuinit or magiskinit)
        #[arg(short = 'p', long)]
        init_payload: String,

        /// Output path for patched boot image
        #[arg(short = 'o', long)]
        output: String,

        /// Injection target type: 'kernelsu' (default) or 'magisk'
        #[arg(short = 't', long, default_value = "kernelsu")]
        target: String,

        /// Optional path to SELinux policy file to inject permissive su rules
        #[arg(short = 's', long)]
        selinux_policy: Option<String>,
    },

    /// Display dual-engine runtime information (Rust Host + Zig Bare-Metal)
    Engine,

    /// Launch interactive terminal dashboard (TUI)
    Tui,

    /// Launch the native desktop reactive GUI window
    Gui,
}
