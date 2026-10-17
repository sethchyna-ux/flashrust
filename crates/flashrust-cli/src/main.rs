use clap::Parser;
use cli::{Cli, Commands};
use toolkit_core::{
    BootKitchen, BootPatchRequest, InitHijackTarget, PRESETS, Rp2350CoreMode, Rp2350Manager,
    SdpCommandPacket, UuuTransport, ZigEngine, create_storage_layout_plan, find_preset,
    list_attached_devices,
};

mod cli;
mod tui;

fn resolved_path(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    if path.exists() {
        return std::fs::canonicalize(path);
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Output path has no filename",
        )
    })?;
    Ok(std::fs::canonicalize(parent)?.join(filename))
}

fn paths_resolve_equal(input: &std::path::Path, output: &std::path::Path) -> std::io::Result<bool> {
    Ok(resolved_path(input)? == resolved_path(output)?)
}

fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Output path has no filename",
        )
    })?;
    let mut temporary = None;
    for serial in 0..100u32 {
        let candidate = parent.join(format!(
            ".{}.flashrust-{}-{serial}.tmp",
            filename.to_string_lossy(),
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temporary_path, mut temporary_file) = temporary.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Could not allocate a temporary output file",
        )
    })?;
    let write_result = (|| {
        temporary_file.write_all(bytes)?;
        temporary_file.sync_all()?;
        drop(temporary_file);
        std::fs::rename(&temporary_path, path)
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    write_result
}

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
                println!(
                    "{:<22} {:<10} {:<24} {:<18} {:<10}",
                    "PRESET", "SOC", "U-BOOT (-u)", "DTB (-d)", "MCU (-m)"
                );
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
            println!(
                "  SPL Offset:           {} kB ({} bytes)",
                plan.spl_offset_kb, plan.spl_offset_bytes
            );
            println!(
                "  Primary GPT Header:   {} bytes (LBA 0–33)",
                plan.gpt_header_bytes
            );
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
                let mfg = dev
                    .manufacturer
                    .as_deref()
                    .unwrap_or("Unknown Manufacturer");
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
            println!(
                "  Virtual Base Address:   0x{:08x}",
                mapping.virtual_base_address
            );
            println!(
                "  Physical Flash Offset:  0x{:08x}",
                mapping.physical_flash_offset
            );
            println!(
                "  Hardware Register Val:  0x{:08x} (TRANS_ADDR_{})",
                mapping.hardware_register_val, window
            );
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
            println!(
                "  Total Payload Size:     {} bytes ({:.2} MiB)",
                size,
                size as f64 / (1024.0 * 1024.0)
            );
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
            adb_preauth,
            adb_pubkey,
            confirm_unlocked,
            force,
        }) => {
            if adb_preauth && !confirm_unlocked {
                return Err(
                    "--adb-preauth requires --confirm-unlocked because the output is a custom boot image"
                        .into(),
                );
            }

            let input_path = std::path::Path::new(&image);
            let output_path = std::path::Path::new(&output);
            if !force && paths_resolve_equal(input_path, output_path)? {
                return Err(
                    "Output resolves to the input image; choose another path or pass --force"
                        .into(),
                );
            }

            let boot_bytes = std::fs::read(input_path)?;
            let payload_bytes = init_payload.as_deref().map(std::fs::read).transpose()?;
            let selinux_bytes = selinux_policy.as_deref().map(std::fs::read).transpose()?;
            let adb_key_bytes = if adb_preauth {
                let key_path = adb_pubkey
                    .map(std::path::PathBuf::from)
                    .or_else(BootKitchen::default_adb_public_key_path)
                    .ok_or("Could not determine the host ADB public-key path")?;
                Some(std::fs::read(&key_path).map_err(|error| {
                    format!(
                        "Could not read Android ADB public key at {}: {error}",
                        key_path.display()
                    )
                })?)
            } else {
                None
            };
            let init_target = payload_bytes.as_ref().map(|_| {
                if target.eq_ignore_ascii_case("magisk") {
                    InitHijackTarget::Magisk
                } else {
                    InitHijackTarget::KernelSU
                }
            });

            let (patched_boot, summary) = BootKitchen::patch_boot_image_with_options(
                &boot_bytes,
                BootPatchRequest {
                    init_payload: payload_bytes.as_deref(),
                    init_target,
                    selinux_policy: selinux_bytes.as_deref(),
                    adb_public_key: adb_key_bytes.as_deref(),
                },
            )?;
            write_atomically(output_path, &patched_boot)?;
            println!("Android boot image patched successfully in-memory:");
            println!("  Header Version:        {}", summary.header_version);
            println!(
                "  Original Ramdisk Size: {} bytes",
                summary.original_ramdisk_size
            );
            println!(
                "  Patched Ramdisk Size:  {} bytes",
                summary.patched_ramdisk_size
            );
            println!(
                "  Ramdisk Encoding:      {}",
                summary.ramdisk_compression.label()
            );
            println!("  Applied Operations:    {:?}", summary.operations);
            println!(
                "  Preserved Tail Data:   {} bytes",
                summary.preserved_suffix_bytes
            );
            println!("  Output Written:        {}", output_path.display());
        }
        Some(Commands::DetectSu { preset }) => {
            let preset_ref = preset.as_deref().and_then(|p| find_preset(p).ok());
            let devices = list_attached_devices();
            let primary_dev = devices
                .iter()
                .find(|d| d.operating_mode != toolkit_core::DeviceOperatingMode::Unknown)
                .or_else(|| devices.first());

            let reqs = toolkit_core::SuDetector::detect(primary_dev, preset_ref);

            println!("=======================================================");
            println!("  flashrust Auto SU Target Requirements & Toolchain Inspector");
            println!("=======================================================");
            println!("  Detected Target:       {}", reqs.device_name);
            println!("  Required CPU Arch:     {}", reqs.target_arch.label());
            println!("  Target Triple:         {}", reqs.target_triple);
            println!("  Android ABI:           {}", reqs.android_abi);
            println!("  64-bit Architecture:   {}", reqs.is_64bit);
            println!("  Binary Linkage:        {}", reqs.linkage);
            println!("  Compiler Required:     {}", reqs.compiler_required);
            println!(
                "  Compiler Detected:     {} (version: {})",
                if reqs.compiler_detected {
                    "YES (Ready)"
                } else {
                    "NO (Missing)"
                },
                reqs.compiler_version.as_deref().unwrap_or("none")
            );
            println!(
                "  Android NDK Detected:  {}",
                if reqs.ndk_detected {
                    "YES"
                } else {
                    "NO (Optional)"
                }
            );
            println!("  Source Code:           {}", reqs.source_name);
            println!("  Target Injection Path: {}", reqs.injection_path);
            println!(
                "  Required File Mode:    0o{:o} (SetUID root, uid:0, gid:0)",
                reqs.permissions_mode
            );
            println!("  SELinux Policy:        {}", reqs.selinux_context);
            println!(
                "  Estimated Binary Size: ~{} KB",
                reqs.estimated_binary_size_kb
            );
            println!(
                "  Ready to Auto-Build:   {}",
                if reqs.can_build { "YES" } else { "NO" }
            );
            println!("-------------------------------------------------------");
            println!("  Analysis Notes:");
            for note in &reqs.notes {
                println!("    • {}", note);
            }
            println!("=======================================================");
        }
        Some(Commands::BuildSu { arch, output }) => {
            let devices = list_attached_devices();
            let primary_dev = devices
                .iter()
                .find(|d| d.operating_mode != toolkit_core::DeviceOperatingMode::Unknown)
                .or_else(|| devices.first());

            let mut reqs = toolkit_core::SuDetector::detect(primary_dev, None);
            if let Some(a) = arch {
                match a.to_lowercase().as_str() {
                    "aarch64" | "arm64" => {
                        reqs.target_arch = toolkit_core::TargetCpuArch::Aarch64;
                        reqs.target_triple = "aarch64-linux-musl";
                        reqs.android_abi = "arm64-v8a";
                        reqs.is_64bit = true;
                    }
                    "armv7a" | "arm" | "armeabi-v7a" => {
                        reqs.target_arch = toolkit_core::TargetCpuArch::ArmV7a;
                        reqs.target_triple = "arm-linux-musleabihf";
                        reqs.android_abi = "armeabi-v7a";
                        reqs.is_64bit = false;
                    }
                    "x86_64" | "x64" => {
                        reqs.target_arch = toolkit_core::TargetCpuArch::X86_64;
                        reqs.target_triple = "x86_64-linux-musl";
                        reqs.android_abi = "x86_64";
                        reqs.is_64bit = true;
                    }
                    "riscv64" => {
                        reqs.target_arch = toolkit_core::TargetCpuArch::Riscv64;
                        reqs.target_triple = "riscv64-linux-musl";
                        reqs.android_abi = "riscv64";
                        reqs.is_64bit = true;
                    }
                    other => {
                        eprintln!(
                            "Unknown architecture override '{}'. Supported: aarch64, armv7a, x86_64, riscv64",
                            other
                        );
                        return Ok(());
                    }
                }
            }

            println!(
                "Building static standalone SU binary for target {} ({})...",
                reqs.target_arch.label(),
                reqs.target_triple
            );
            let out_dir = std::path::PathBuf::from(&output).join(reqs.target_triple);
            match toolkit_core::SuDetector::build(&reqs, &out_dir) {
                Ok(path) => {
                    let meta = std::fs::metadata(&path)?;
                    println!("SU binary compiled and verified successfully:");
                    println!("  Output Path:   {}", path.display());
                    println!(
                        "  Binary Size:   {} bytes ({:.1} KB)",
                        meta.len(),
                        meta.len() as f64 / 1024.0
                    );
                    println!(
                        "  Target Arch:   {} ({})",
                        reqs.target_arch.label(),
                        reqs.target_triple
                    );
                    println!(
                        "  Linkage:       Static musl ELF (Zero dynamic runtime dependencies)"
                    );
                    println!(
                        "  Permissions:   chmod 04755 root:root (ready for ramdisk/boot injection)"
                    );
                }
                Err(e) => {
                    eprintln!("Failed to build SU binary: {}", e);
                }
            }
        }
        Some(Commands::Verify { image }) => {
            let path = std::path::Path::new(&image);
            let res = toolkit_core::SparseImageVerifier::verify_file(path)?;
            println!("Image Integrity Verification:");
            println!("  File Path:          {}", image);
            println!(
                "  Format:             {}",
                if res.is_sparse {
                    "Android Sparse Image (0xED26FF3A)"
                } else {
                    "Raw Binary Image"
                }
            );
            println!(
                "  Logical Size:       {} bytes ({:.2} MiB)",
                res.logical_size_bytes,
                res.logical_size_bytes as f64 / (1024.0 * 1024.0)
            );
            println!("  Payload Bytes Read: {} bytes", res.payload_bytes_read);
            println!("  Total Chunks:       {}", res.total_chunks);
            println!("  CRC32 (IEEE):       0x{:08x}", res.crc32);
            println!("  SHA-256 Digest:     {}", res.sha256);
        }
        Some(Commands::Vbmeta {
            image,
            disable_verity_output,
        }) => {
            let bytes = std::fs::read(&image)?;
            if let Some(out_path) = disable_verity_output {
                let (patched, summary) = toolkit_core::VbmetaTools::patch_disable_verity(&bytes)?;
                std::fs::write(&out_path, patched)?;
                println!("AVB vbmeta.img patched (dm-verity & verification disabled):");
                println!(
                    "  AVB Version:           {}.{}",
                    summary.major_version, summary.minor_version
                );
                println!("  Release String:        {}", summary.release_string);
                println!("  Updated Flags:         0x{:08x}", summary.flags);
                println!("  Hashtree Disabled:     {}", summary.hashtree_disabled);
                println!("  Verification Disabled: {}", summary.verification_disabled);
                println!("  Output Written:        {}", out_path);
            } else {
                let summary = toolkit_core::VbmetaTools::inspect_vbmeta(&bytes)?;
                println!("AVB vbmeta.img Inspection:");
                println!(
                    "  AVB Version:           {}.{}",
                    summary.major_version, summary.minor_version
                );
                println!("  Release String:        {}", summary.release_string);
                println!("  Algorithm Type:        {}", summary.algorithm_type);
                println!("  Rollback Index:        {}", summary.rollback_index);
                println!("  Flags:                 0x{:08x}", summary.flags);
                println!("  Hashtree Disabled:     {}", summary.hashtree_disabled);
                println!("  Verification Disabled: {}", summary.verification_disabled);
            }
        }
        Some(Commands::SamsungFlash {
            bl,
            ap,
            cp,
            csc,
            pit,
            frp_lock,
            kg_state,
            oem_unlock,
            custom_binary,
            no_reboot,
        }) => {
            let pit_file = pit.map(std::path::PathBuf::from);
            let pit_table = pit_file
                .as_deref()
                .map(std::fs::read)
                .transpose()?
                .as_deref()
                .map(toolkit_core::PitTable::parse_bytes)
                .transpose()?;

            let cfg = toolkit_core::SamsungOdinConfig {
                bl_tar: bl.map(std::path::PathBuf::from),
                ap_tar: ap.map(std::path::PathBuf::from),
                cp_tar: cp.map(std::path::PathBuf::from),
                csc_tar: csc.map(std::path::PathBuf::from),
                pit_file,
                frp_lock_state: if frp_lock.eq_ignore_ascii_case("off") {
                    toolkit_core::FrpLockState::Off
                } else {
                    toolkit_core::FrpLockState::On
                },
                kg_lock_state: match kg_state.to_ascii_lowercase().as_str() {
                    "checking" => toolkit_core::KgLockState::Checking,
                    "prenormal" => toolkit_core::KgLockState::Prenormal,
                    "locked" => toolkit_core::KgLockState::Locked,
                    _ => toolkit_core::KgLockState::Completed,
                },
                oem_unlock_enabled: oem_unlock,
                ..toolkit_core::SamsungOdinConfig::default()
            };

            let preflight = cfg.evaluate_preflight(custom_binary);

            println!("=======================================================");
            println!("  Samsung Odin / Loke Real USB Flash");
            println!("=======================================================");
            println!(
                "  Loke Handshake:       {:?} -> {:?}",
                std::str::from_utf8(toolkit_core::ODIN_HANDSHAKE_REQUEST).unwrap_or("ODIN"),
                std::str::from_utf8(toolkit_core::LOKE_HANDSHAKE_RESPONSE).unwrap_or("LOKE")
            );
            if let Some(pit) = &pit_table {
                println!(
                    "  PIT Project / Gang:   {} / {} ({} partitions)",
                    pit.project_name,
                    pit.gang_name,
                    pit.entries.len()
                );
            } else {
                println!(
                    "  PIT Mapping:          Filename-based only (no device-specific PIT supplied)"
                );
            }
            println!("  FRP Lock State:       {}", cfg.frp_lock_state.label());
            println!("  KG Lock State:        {}", cfg.kg_lock_state.label());
            println!("  OEM Unlock Enabled:   {}", cfg.oem_unlock_enabled);
            println!("  Preflight Verdict:    {}", preflight.status_headline);
            println!("-------------------------------------------------------");
            for finding in &preflight.findings {
                println!("  • {}", finding);
            }
            if !preflight.recommended_actions.is_empty() {
                println!("  Recommended Actions:");
                for act in &preflight.recommended_actions {
                    println!("    -> {}", act);
                }
            }
            if !preflight.current_payload_allowed {
                return Err(format!(
                    "Samsung preflight blocked the selected payload: {}",
                    preflight.status_headline
                )
                .into());
            }

            // Inspect any supplied .tar / .tar.md5 archives
            for (slot_label, slot_path) in [
                ("BL", &cfg.bl_tar),
                ("AP", &cfg.ap_tar),
                ("CP", &cfg.cp_tar),
                ("CSC", &cfg.csc_tar),
            ] {
                if let Some(p) = slot_path
                    && p.exists()
                {
                    let manifest =
                        toolkit_core::OdinProtocolEngine::inspect_tar_file(p, pit_table.as_ref())?;
                    println!("-------------------------------------------------------");
                    println!(
                        "  [{}] Archive: {} (MD5 Match: {:?}, {} entries, {} bytes)",
                        slot_label,
                        manifest.archive_path,
                        manifest.md5_matches,
                        manifest.entries.len(),
                        manifest.total_payload_bytes
                    );
                    for entry in &manifest.entries {
                        println!(
                            "    • {:<24} {:>10} bytes -> PIT Partition: {}",
                            entry.filename,
                            entry.size_bytes,
                            entry.mapped_partition.as_deref().unwrap_or("UNMAPPED")
                        );
                    }
                }
            }
            println!("  USB Engine:           Bundled Heimdall (real Loke transport)");
            println!("=======================================================");
            let result = toolkit_core::HeimdallEngine::flash(&cfg, !no_reboot, |line| {
                println!("  [HEIMDALL] {line}");
            })?;
            println!(
                "Flash complete: {} partition(s) via {} {}",
                result.partition_count,
                result.heimdall_path.display(),
                result.heimdall_version
            );
        }
        Some(Commands::InspectFrp { image }) => {
            let bytes = std::fs::read(&image)?;
            let report = toolkit_core::FrpPartitionInspector::inspect_bytes(&bytes)?;
            println!("AOSP FRP / Persistent Partition Read-Only Inspection:");
            println!("  File Path:            {}", image);
            println!(
                "  Partition Size:       {} bytes",
                report.partition_size_bytes
            );
            println!(
                "  Header Marker:        0x{:08X} (Valid: {})",
                report.header_marker, report.marker_valid
            );
            println!(
                "  Credential Data Size: {} bytes (Enrolled: {})",
                report.credential_data_size, report.has_enrolled_credentials
            );
            println!("  OEM Unlock Enabled:   {}", report.oem_unlock_enabled);
            println!("  Stored SHA-256:       {}", report.stored_sha256_hex);
            println!("  Computed SHA-256:     {}", report.computed_sha256_hex);
            println!("  Digest Verified:      {}", report.digest_matches);
        }
        Some(Commands::RebootDownload { port, probe_only }) => {
            println!("=======================================================");
            println!("  Samsung Real vs. Fake Download Mode Probe & Reboot");
            println!("=======================================================");
            let port_path = port.as_deref().map(std::path::Path::new);
            let report =
                toolkit_core::OdinProtocolEngine::probe_samsung_download_mode_on(port_path);
            println!(
                "  Detected Sub-Mode:    {}",
                report.detected_submode.label()
            );
            println!(
                "  Serial Modem Port:    {}",
                report
                    .serial_port
                    .as_deref()
                    .unwrap_or("None (/dev/cu.usbmodem* not present)")
            );
            println!(
                "  Raw Device Response:  {}",
                if report.raw_response.is_empty() {
                    "(none)"
                } else {
                    &report.raw_response
                }
            );
            if let Some(ref info) = report.devconinfo {
                println!("  AT+DEVCONINFO:        {}", info);
            }
            if let Some(ref t) = report.parsed_telemetry {
                println!("-------------------------------------------------------");
                println!("  Samsung Hardware & Firmware Telemetry:");
                println!("  • Target Model:       {}", t.model);
                println!("  • Firmware Build:     {}", t.firmware_version);
                println!(
                    "  • Bootloader SW REV:  Bit {} (Binary Revision)",
                    t.sw_rev_bit
                );
                println!("  • Carrier Product:    {} (Sales Code)", t.carrier_prd);
                println!("  • USB Composition:    {}", t.usb_composition);
                println!("  • Lock State:         {}", t.lock_status);
                println!("  • Device Serial:      {}", t.serial_number);
                println!("  • IMEI:               {}", t.imei);
            }
            println!("  Diagnostic Summary:   {}", report.summary);
            if !probe_only {
                println!("-------------------------------------------------------");
                println!(
                    "  Executing Reboot to Real Download Mode (`AT+FUS?` / `adb reboot download`)..."
                );
                let logs = toolkit_core::OdinProtocolEngine::reboot_to_download_mode_on(port_path);
                for line in logs {
                    println!("  • {}", line);
                }
            }
            println!("=======================================================");
        }
        Some(Commands::Engine) => {
            println!("Project flashrust Dual-Engine Info:");
            println!(
                "  Host Orchestration Engine: Rust v1.85+ (Tokio, Embassy, nusb, clap, ratatui)"
            );
            println!("  Bare-Metal Binary Engine:  Zig {}", ZigEngine::version());
        }
        Some(Commands::Gui) => {
            println!("Launching Project flashrust Desktop Reactive GUI (eframe/egui)...");
            let status = std::process::Command::new("cargo")
                .args(["run", "-p", "flashrust-gui"])
                .status()?;
            if !status.success() {
                eprintln!("Failed to launch flashrust-gui: {:?}", status);
            }
        }
        Some(Commands::Tui) | None => {
            tui::run_tui()?;
        }
    }

    Ok(())
}
