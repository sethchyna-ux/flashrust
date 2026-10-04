use clap::Parser;
use cli::{Cli, Commands};
use toolkit_core::{
    create_storage_layout_plan, find_preset, list_attached_devices, BootKitchen, InitHijackTarget,
    Rp2350CoreMode, Rp2350Manager, SdpCommandPacket, UuuTransport, ZigEngine, PRESETS,
};

mod cli;
mod tui;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Presets { target }) => {
            if let Some(target_str) = target {
                let preset = find_preset(&target_str)?;
                println!("Preset: {}", preset.name);
                println!("  Target SoC:     {}", preset.soc);
                println!("  U-Boot Feature: {}", preset.uboot_feature);
                println!("  DTB Feature:    {}", preset.dtb_feature);
                println!("  MCU Binary:     {}", preset.mcu_binary);
            } else {
                println!("{:<22} {:<10} {:<24} {:<18} {:<10}", "PRESET", "SOC", "U-BOOT (-u)", "DTB (-d)", "MCU (-m)");
                println!("{}", "-".repeat(88));
                for p in PRESETS {
                    println!(
                        "{:<22} {:<10} {:<24} {:<18} {:<10}",
                        p.name, p.soc, p.uboot_feature, p.dtb_feature, p.mcu_binary
                    );
                }
            }
        }
        Some(Commands::Offset {
            soc,
            emmc,
            mcu,
            capacity_gb,
        }) => {
            let capacity_bytes = capacity_gb * 1024 * 1024 * 1024;
            let plan = create_storage_layout_plan(&soc, emmc, mcu, capacity_bytes)?;
            println!("Storage Partition & Offset Plan:");
            println!("  Target SoC:           {}", plan.soc_name);
            println!("  eMMC Boot0 Partition: {}", plan.is_emmc_boot);
            println!("  SPL Offset:           {} kB ({} bytes)", plan.spl_offset_kb, plan.spl_offset_bytes);
            println!("  Primary GPT Header:   {} bytes (LBA 0–33)", plan.gpt_header_bytes);
            if let Some(mcu_offset) = plan.mcu_offset_kb {
                println!("  MCU Coprocessor:      {} kB (5.12 MB)", mcu_offset);
            } else {
                println!("  MCU Coprocessor:      Disabled");
            }
            println!("  Selected Partition:   {}", plan.partition_table_image);
        }
        Some(Commands::Devices) => {
            let devices = list_attached_devices();
            println!("Detected USB Devices ({} found):", devices.len());
            for dev in devices {
                let prod = dev.product.as_deref().unwrap_or("Unknown Device");
                let mfg = dev.manufacturer.as_deref().unwrap_or("Unknown Manufacturer");
                println!(
                    "• [{:04x}:{:04x}] {} - {} (Mode: {:?})",
                    dev.vendor_id, dev.product_id, mfg, prod, dev.operating_mode
                );
            }
        }
        Some(Commands::Rp2350Window {
            window,
            offset,
            mode,
        }) => {
            let core_mode = match mode.to_ascii_lowercase().as_str() {
                "arm-secure" => Rp2350CoreMode::ArmSecure,
                "riscv" => Rp2350CoreMode::RiscVMachine,
                _ => Rp2350CoreMode::ArmNonSecure,
            };

            let mapping = Rp2350Manager::configure_qspi_window(window, offset, core_mode)?;
            println!("RP2350 QSPI Address Window Mapping:");
            println!("  Subwindow Index:        {}", mapping.window_index);
            println!("  Virtual Base Address:   0x{:08x}", mapping.virtual_base_address);
            println!("  Physical Flash Offset:  0x{:08x}", mapping.physical_flash_offset);
            println!("  Hardware Register Val:  0x{:08x} (TRANS_ADDR_{})", mapping.hardware_register_val, window);
            println!("  Target Core Mode:       {:?}", mapping.target_mode);
        }
        Some(Commands::SdpPlan {
            address,
            size,
            chunk_size,
        }) => {
            let cmd = SdpCommandPacket::new_write_file(address, size as u32);
            let chunks = UuuTransport::plan_chunks(size, chunk_size);
            println!("NXP SDP Upload Plan:");
            println!("  Destination Address:    0x{:08x}", address);
            println!("  Total Payload Size:     {} bytes ({:.2} MiB)", size, size as f64 / (1024.0 * 1024.0));
            println!("  Chunk Block Size:       {} bytes", chunk_size);
            println!("  Total Chunks:           {}", chunks.len());
            println!("  SDP Command Header:     {:02x?}", cmd.to_bytes());
        }
        Some(Commands::PatchBoot {
            image,
            init_payload,
            output,
            target,
            selinux_policy,
        }) => {
            let boot_bytes = std::fs::read(&image)?;
            let payload_bytes = std::fs::read(&init_payload)?;
            let hijack_target = match target.to_ascii_lowercase().as_str() {
                "magisk" => InitHijackTarget::Magisk,
                _ => InitHijackTarget::KernelSU,
            };
            let selinux_bytes = if let Some(path) = selinux_policy {
                Some(std::fs::read(path)?)
            } else {
                None
            };

            let (patched_bytes, summary) = BootKitchen::patch_boot_image(
                &boot_bytes,
                &payload_bytes,
                hijack_target,
                selinux_bytes.as_deref(),
            )?;

            std::fs::write(&output, patched_bytes)?;
            println!("Android boot image patched successfully in-memory:");
            println!("  Header Version:        {}", summary.header_version);
            println!("  Target:                {:?}", summary.target);
            println!("  Original Ramdisk Size: {} bytes", summary.original_ramdisk_size);
            println!("  Patched Ramdisk Size:  {} bytes", summary.patched_ramdisk_size);
            println!("  SELinux Permissive Su: {}", summary.selinux_patched);
            println!("  Output Written:        {}", output);
        }
        Some(Commands::Engine) => {
            println!("Project flashrust Dual-Engine Info:");
            println!("  Host Orchestration Engine: Rust v1.85+ (Tokio, Embassy, nusb, clap, ratatui)");
            println!("  Bare-Metal Binary Engine:  Zig {}", ZigEngine::version());
        }
        Some(Commands::Tui) | None => {
            tui::run_tui()?;
        }
    }

    Ok(())
}
