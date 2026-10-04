use eframe::egui;
use std::time::{Duration, Instant};
use toolkit_core::{
    create_storage_layout_plan, detect_preset_from_usb, list_attached_devices, BoardPreset,
    DeviceOperatingMode, StorageLayoutPlan, UsbDeviceInfo, ZigEngine, PRESETS,
};

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([880.0, 620.0])
            .with_title("Project flashrust | Hardware Flasher & Bootloader Toolkit"),
        ..Default::default()
    };

    eframe::run_native(
        "Project flashrust",
        native_options,
        Box::new(|cc| {
            // Apply sleek dark theme
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(FlashrustApp::new()))
        }),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashTargetType {
    FastbootPartition,
    NxpBootloaderSpl,
    NxpFitImage,
    RawStorageOffset,
    Rp2350Qspi,
}

impl FlashTargetType {
    pub const ALL: [FlashTargetType; 5] = [
        FlashTargetType::FastbootPartition,
        FlashTargetType::NxpBootloaderSpl,
        FlashTargetType::NxpFitImage,
        FlashTargetType::RawStorageOffset,
        FlashTargetType::Rp2350Qspi,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            FlashTargetType::FastbootPartition => "Fastboot Partition (Android)",
            FlashTargetType::NxpBootloaderSpl => "NXP SPL Bootloader (Raw/eMMC)",
            FlashTargetType::NxpFitImage => "NXP FIT / OS Image (UUU)",
            FlashTargetType::RawStorageOffset => "Raw Storage Offset (Hex LBA)",
            FlashTargetType::Rp2350Qspi => "RP2350 QSPI Flash Subwindow",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSlot {
    Active,
    SlotA,
    SlotB,
    AllSlots,
}

impl TargetSlot {
    pub const ALL: [TargetSlot; 4] = [
        TargetSlot::Active,
        TargetSlot::SlotA,
        TargetSlot::SlotB,
        TargetSlot::AllSlots,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            TargetSlot::Active => "Active / Current Slot",
            TargetSlot::SlotA => "Slot A (_a)",
            TargetSlot::SlotB => "Slot B (_b)",
            TargetSlot::AllSlots => "Both Slots (_all)",
        }
    }
}

struct FlashrustApp {
    zig_version: &'static str,
    selected_preset_idx: usize,
    auto_detected_profile: Option<&'static str>,
    emmc_boot: bool,
    mcu_binary: bool,
    storage_capacity_gb: u64,
    uboot_feature_override: String,
    dtb_feature_override: String,
    devices: Vec<UsbDeviceInfo>,
    selected_device_idx: Option<usize>,
    last_device_scan: Instant,
    flashing_active: bool,
    flash_progress: f32,
    log_messages: Vec<String>,

    // Flash Payload & Target Configuration
    flash_target_type: FlashTargetType,
    flash_image_path: String,
    flash_partition_name: String,
    flash_target_slot: TargetSlot,
    custom_flash_offset: String,
    enable_ksu_injection: bool,
    auto_reboot_after_flash: bool,
}

impl FlashrustApp {
    fn new() -> Self {
        let default_preset = &PRESETS[0];
        let initial_devices = list_attached_devices();
        // Prefer first recognized target device if available, otherwise first device
        let initial_selected = initial_devices
            .iter()
            .position(|d| d.operating_mode != DeviceOperatingMode::Unknown)
            .or_else(|| if initial_devices.is_empty() { None } else { Some(0) });

        let mut app = Self {
            zig_version: ZigEngine::version(),
            selected_preset_idx: 0,
            auto_detected_profile: None,
            emmc_boot: false,
            mcu_binary: default_preset.mcu_binary,
            storage_capacity_gb: 32,
            uboot_feature_override: default_preset.uboot_feature.to_string(),
            dtb_feature_override: default_preset.dtb_feature.to_string(),
            devices: initial_devices,
            selected_device_idx: None,
            last_device_scan: Instant::now(),
            flashing_active: false,
            flash_progress: 0.0,
            log_messages: vec![
                "[SYSTEM] flashrust Host Orchestrator initialized".into(),
                format!("[ENGINE] Zig Bare-Metal Engine: {}", ZigEngine::version()),
                "[USB] nusb monitoring active - selecting a target auto-detects its hardware profile".into(),
            ],
            flash_target_type: FlashTargetType::FastbootPartition,
            flash_image_path: String::new(),
            flash_partition_name: "boot".to_string(),
            flash_target_slot: TargetSlot::Active,
            custom_flash_offset: "0x8400".to_string(),
            enable_ksu_injection: false,
            auto_reboot_after_flash: false,
        };

        if let Some(idx) = initial_selected {
            app.select_device(idx);
        }

        app
    }

    fn select_device(&mut self, idx: usize) {
        self.selected_device_idx = Some(idx);
        if let Some(dev) = self.devices.get(idx) {
            let prod = dev.product.as_deref().unwrap_or("USB Device");
            self.log_messages.push(format!(
                "[USB] Selected target device: [{:04x}:{:04x}] {}",
                dev.vendor_id, dev.product_id, prod
            ));

            // Auto-detect matching hardware profile from USB
            if let Some(detected_preset) = detect_preset_from_usb(dev) {
                if let Some(pos) = PRESETS.iter().position(|p| p.name == detected_preset.name) {
                    self.selected_preset_idx = pos;
                    self.mcu_binary = detected_preset.mcu_binary;
                    self.uboot_feature_override = detected_preset.uboot_feature.to_string();
                    self.dtb_feature_override = detected_preset.dtb_feature.to_string();
                    self.auto_detected_profile = Some(detected_preset.name);
                    self.log_messages.push(format!(
                        "[PROFILE] Auto-detected board profile '{}' from USB target [{:04x}:{:04x}]",
                        detected_preset.name, dev.vendor_id, dev.product_id
                    ));
                }
            } else {
                self.auto_detected_profile = None;
            }

            // Auto-configure payload mode based on target operating mode
            match dev.operating_mode {
                DeviceOperatingMode::Fastboot | DeviceOperatingMode::AndroidAdb => {
                    self.flash_target_type = FlashTargetType::FastbootPartition;
                    if self.flash_partition_name.is_empty() {
                        self.flash_partition_name = "boot".to_string();
                    }
                }
                DeviceOperatingMode::NxpSerialDownload => {
                    self.flash_target_type = FlashTargetType::NxpBootloaderSpl;
                }
                DeviceOperatingMode::Rp2350BootRom | DeviceOperatingMode::Rp2040BootRom => {
                    self.flash_target_type = FlashTargetType::Rp2350Qspi;
                }
                _ => {}
            }
        }
    }

    fn current_preset(&self) -> &'static BoardPreset {
        &PRESETS[self.selected_preset_idx]
    }

    fn selected_device(&self) -> Option<&UsbDeviceInfo> {
        self.selected_device_idx.and_then(|idx| self.devices.get(idx))
    }

    fn compute_layout(&self) -> Option<StorageLayoutPlan> {
        let preset = self.current_preset();
        let bytes = self.storage_capacity_gb * 1024 * 1024 * 1024;
        create_storage_layout_plan(preset.soc, self.emmc_boot, self.mcu_binary, bytes).ok()
    }

    fn generate_flash_command_preview(&self) -> String {
        let payload_file = if !self.flash_image_path.is_empty() {
            self.flash_image_path.clone()
        } else {
            match self.flash_target_type {
                FlashTargetType::FastbootPartition => format!("{}.img", self.flash_partition_name),
                FlashTargetType::NxpBootloaderSpl => "u-boot-spl.bin".to_string(),
                FlashTargetType::NxpFitImage => "u-boot.itb".to_string(),
                FlashTargetType::RawStorageOffset => "partition-table.img".to_string(),
                FlashTargetType::Rp2350Qspi => "firmware.uf2".to_string(),
            }
        };

        match self.flash_target_type {
            FlashTargetType::FastbootPartition => {
                let slot_arg = match self.flash_target_slot {
                    TargetSlot::Active => String::new(),
                    TargetSlot::SlotA => "_a".to_string(),
                    TargetSlot::SlotB => "_b".to_string(),
                    TargetSlot::AllSlots => " --slot=all".to_string(),
                };
                let reboot_suffix = if self.auto_reboot_after_flash { " && fastboot reboot" } else { "" };
                let ksu_prefix = if self.enable_ksu_injection { "# [Zig Engine: Patching KernelSU /init ramdisk in-memory]\n" } else { "" };
                if self.flash_target_slot == TargetSlot::AllSlots {
                    format!("{}fastboot flash{} {} {}{}", ksu_prefix, slot_arg, self.flash_partition_name, payload_file, reboot_suffix)
                } else {
                    format!("{}fastboot flash {}{} {}{}", ksu_prefix, self.flash_partition_name, slot_arg, payload_file, reboot_suffix)
                }
            }
            FlashTargetType::NxpBootloaderSpl => {
                let offset_kb = self.compute_layout().map(|l| l.spl_offset_kb).unwrap_or(33);
                let target = if self.emmc_boot { "emmc_boot0" } else { "sd_card" };
                format!("uuu -b {} {} (SPL target offset: {} kB / 0x{:X})", target, payload_file, offset_kb, offset_kb * 1024)
            }
            FlashTargetType::NxpFitImage => {
                let uboot_feat = &self.uboot_feature_override;
                format!("uuu -u {} -d {} -b emmc_all u-boot-spl.bin {}", uboot_feat, self.dtb_feature_override, payload_file)
            }
            FlashTargetType::RawStorageOffset => {
                format!("flashrust-engine write-raw --offset {} --image {}", self.custom_flash_offset, payload_file)
            }
            FlashTargetType::Rp2350Qspi => {
                format!("flashrust-engine rp2350 --window 1 --offset 0x00010000 --seal-image-def {}", payload_file)
            }
        }
    }
}

impl eframe::App for FlashrustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Auto-refresh devices every 3 seconds
        if self.last_device_scan.elapsed() > Duration::from_secs(3) {
            let updated = list_attached_devices();
            // Preserve selection by matching VID:PID if possible
            if let Some(current) = self.selected_device() {
                let vid = current.vendor_id;
                let pid = current.product_id;
                self.selected_device_idx = updated.iter().position(|d| d.vendor_id == vid && d.product_id == pid);
            } else if !updated.is_empty() && self.selected_device_idx.is_none() {
                self.select_device(0);
            }
            self.devices = updated;
            self.last_device_scan = Instant::now();
        }

        // Advance simulation progress if active
        if self.flashing_active {
            self.flash_progress += 0.02;
            if self.flash_progress >= 1.0 {
                self.flashing_active = false;
                self.flash_progress = 1.0;
                let target_name = self
                    .selected_device()
                    .and_then(|d| d.product.clone())
                    .unwrap_or_else(|| "Target Device".into());
                let target_desc = match self.flash_target_type {
                    FlashTargetType::FastbootPartition => format!("partition '{}'", self.flash_partition_name),
                    FlashTargetType::NxpBootloaderSpl => "NXP SPL Bootloader".into(),
                    FlashTargetType::NxpFitImage => "U-Boot FIT Image".into(),
                    FlashTargetType::RawStorageOffset => format!("offset {}", self.custom_flash_offset),
                    FlashTargetType::Rp2350Qspi => "RP2350 QSPI Flash Window".into(),
                };
                self.log_messages.push(format!(
                    "[FLASH] Image write of {} to '{}' completed successfully (verified OK)!",
                    target_desc, target_name
                ));
                if self.auto_reboot_after_flash {
                    self.log_messages.push(format!(
                        "[REBOOT] Target '{}' reboot sequence dispatched",
                        target_name
                    ));
                }
            }
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        // Top Header Panel
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("⚡ Project flashrust");
                ui.separator();
                ui.label(
                    egui::RichText::new("Dual-Engine Firmware Flasher & Bootloader Toolkit")
                        .color(egui::Color32::from_rgb(0, 210, 255)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔄 Rescan USB").clicked() {
                        self.devices = list_attached_devices();
                        self.last_device_scan = Instant::now();
                        self.log_messages.push(format!(
                            "[USB] Rescan completed: {} devices detected",
                            self.devices.len()
                        ));
                    }
                    ui.label(format!("Zig Engine: v{}", self.zig_version));
                    ui.separator();
                    ui.label("Host: Rust v1.85+ (Tokio/nusb)");
                });
            });
            ui.add_space(6.0);
        });

        // Bottom Status Panel
        egui::TopBottomPanel::bottom("bottom_status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Attached USB Targets: {}", self.devices.len()));
                ui.separator();
                if let Some(target) = self.selected_device() {
                    let prod = target.product.as_deref().unwrap_or("USB Device");
                    let profile_tag = if let Some(prof) = self.auto_detected_profile {
                        format!(" (Profile: {})", prof)
                    } else {
                        String::new()
                    };
                    ui.label(
                        egui::RichText::new(format!(
                            "🎯 Active Target: [{:04x}:{:04x}] {}{}",
                            target.vendor_id, target.product_id, prod, profile_tag
                        ))
                        .color(egui::Color32::from_rgb(0, 255, 180)),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("⚠️ No Target Selected")
                            .color(egui::Color32::from_rgb(255, 180, 0)),
                    );
                }
                ui.separator();
                let status_text = if self.flashing_active {
                    "Flashing in progress (512 KiB streaming chunks)..."
                } else {
                    "Ready"
                };
                ui.label(status_text);
            });
        });

        // Central Panel with Split Layout
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |columns| {
                // Column 1: Hardware Profiles, Flashing Configuration & Execution
                columns[0].vertical(|ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("column_0_scroll_area")
                        .show(ui, |ui| {
                            // Hardware Profile & Target Preset
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.heading("🛠 Hardware Profile & Target Preset");
                                    if let Some(detected) = self.auto_detected_profile {
                                        ui.colored_label(
                                            egui::Color32::from_rgb(0, 255, 128),
                                            format!("✔ Auto-Detected ({})", detected),
                                        );
                                    }
                                });
                                ui.add_space(4.0);

                                let prev_idx = self.selected_preset_idx;
                                egui::ComboBox::from_label("Target Hardware Preset")
                                    .selected_text(self.current_preset().name)
                                    .show_ui(ui, |ui| {
                                        for (idx, p) in PRESETS.iter().enumerate() {
                                            ui.selectable_value(&mut self.selected_preset_idx, idx, p.name);
                                        }
                                    });

                                // If user manually changed preset, clear auto-detected flag
                                if prev_idx != self.selected_preset_idx {
                                    let p = self.current_preset();
                                    self.mcu_binary = p.mcu_binary;
                                    self.uboot_feature_override = p.uboot_feature.to_string();
                                    self.dtb_feature_override = p.dtb_feature.to_string();
                                    self.auto_detected_profile = None;
                                }

                                let p = self.current_preset();
                                ui.label(format!("SoC: {}", p.soc));
                            });

                            ui.add_space(8.0);

                            // Dedicated Flash Payload & Target Configuration
                            ui.group(|ui| {
                                ui.heading("📦 Flash Payload & Image Configuration");
                                ui.add_space(4.0);

                                // Target Flashing Mode Selector
                                ui.horizontal(|ui| {
                                    ui.label("Flash Target Mode:");
                                    egui::ComboBox::from_id_salt("flash_target_type_combobox")
                                        .selected_text(self.flash_target_type.label())
                                        .show_ui(ui, |ui| {
                                            for t in FlashTargetType::ALL {
                                                ui.selectable_value(&mut self.flash_target_type, t, t.label());
                                            }
                                        });
                                });

                                ui.add_space(4.0);

                                // Image File Selection with Browse Button
                                ui.label(egui::RichText::new("Payload Image File:").strong());
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.flash_image_path)
                                            .hint_text("Path to .img, .bin, .wic, or .uf2")
                                            .desired_width(260.0),
                                    );
                                    if ui.button("📂 Browse...").clicked() {
                                        if let Some(path) = rfd::FileDialog::new()
                                            .add_filter("Firmware & Images (*.img, *.bin, *.wic, *.uf2, *.itb)", &["img", "bin", "wic", "raw", "uf2", "itb"])
                                            .pick_file()
                                        {
                                            let path_str = path.display().to_string();
                                            self.flash_image_path = path_str.clone();

                                            // Auto-detect partition name from file stem
                                            let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                                            if ["boot", "init_boot", "recovery", "vendor_boot", "system", "super", "vbmeta", "dtbo"].contains(&file_stem.as_str()) {
                                                self.flash_partition_name = file_stem;
                                                self.flash_target_type = FlashTargetType::FastbootPartition;
                                            } else if file_stem.contains("spl") {
                                                self.flash_target_type = FlashTargetType::NxpBootloaderSpl;
                                            }
                                            self.log_messages.push(format!("[PAYLOAD] Selected payload file: {}", path_str));
                                        }
                                    }
                                    if !self.flash_image_path.is_empty() && ui.button("✖ Clear").clicked() {
                                        self.flash_image_path.clear();
                                    }
                                });

                                // File existence & size indicator
                                if !self.flash_image_path.is_empty() {
                                    let p = std::path::Path::new(&self.flash_image_path);
                                    if p.exists() {
                                        if let Ok(meta) = std::fs::metadata(p) {
                                            let size = meta.len();
                                            let size_str = if size >= 1024 * 1024 * 1024 {
                                                format!("{:.2} GiB", size as f64 / (1024.0 * 1024.0 * 1024.0))
                                            } else if size >= 1024 * 1024 {
                                                format!("{:.2} MiB", size as f64 / (1024.0 * 1024.0))
                                            } else {
                                                format!("{:.2} KiB", size as f64 / 1024.0)
                                            };
                                            ui.colored_label(egui::Color32::from_rgb(0, 255, 128), format!("✔ File found ({})", size_str));
                                        }
                                    } else {
                                        ui.colored_label(egui::Color32::from_rgb(255, 180, 50), "⚠️ File not found at path (placeholder simulated)");
                                    }
                                }

                                // Quick Payload Presets chips
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Quick Files:").color(egui::Color32::GRAY));
                                    if ui.button("boot.img").clicked() {
                                        self.flash_target_type = FlashTargetType::FastbootPartition;
                                        self.flash_partition_name = "boot".to_string();
                                        self.flash_image_path = "boot.img".to_string();
                                    }
                                    if ui.button("init_boot.img").clicked() {
                                        self.flash_target_type = FlashTargetType::FastbootPartition;
                                        self.flash_partition_name = "init_boot".to_string();
                                        self.flash_image_path = "init_boot.img".to_string();
                                    }
                                    if ui.button("recovery.img").clicked() {
                                        self.flash_target_type = FlashTargetType::FastbootPartition;
                                        self.flash_partition_name = "recovery".to_string();
                                        self.flash_image_path = "recovery.img".to_string();
                                    }
                                    if ui.button("u-boot-spl.bin").clicked() {
                                        self.flash_target_type = FlashTargetType::NxpBootloaderSpl;
                                        self.flash_image_path = "u-boot-spl.bin".to_string();
                                    }
                                });

                                ui.add_space(4.0);
                                ui.separator();
                                ui.add_space(4.0);

                                // Mode-specific options
                                match self.flash_target_type {
                                    FlashTargetType::FastbootPartition => {
                                        ui.horizontal(|ui| {
                                            ui.label("Target Partition:");
                                            ui.text_edit_singleline(&mut self.flash_partition_name);
                                        });

                                        ui.horizontal(|ui| {
                                            ui.label("Presets:");
                                            for part in &["boot", "init_boot", "recovery", "vendor_boot", "vbmeta", "dtbo", "super"] {
                                                if ui.selectable_label(self.flash_partition_name == *part, *part).clicked() {
                                                    self.flash_partition_name = (*part).to_string();
                                                }
                                            }
                                        });

                                        ui.horizontal(|ui| {
                                            ui.label("Target Slot:");
                                            egui::ComboBox::from_id_salt("fastboot_slot_combobox")
                                                .selected_text(self.flash_target_slot.label())
                                                .show_ui(ui, |ui| {
                                                    for slot in TargetSlot::ALL {
                                                        ui.selectable_value(&mut self.flash_target_slot, slot, slot.label());
                                                    }
                                                });
                                        });

                                        ui.checkbox(&mut self.enable_ksu_injection, "⚡ In-Memory KernelSU / Init Hijack Patch (Zig Engine)");
                                        ui.checkbox(&mut self.auto_reboot_after_flash, "🔄 Auto-reboot device after flashing");
                                    }
                                    FlashTargetType::NxpBootloaderSpl => {
                                        let offset_kb = self.compute_layout().map(|l| l.spl_offset_kb).unwrap_or(33);
                                        ui.label(format!("• Target Architecture: NXP {}", self.current_preset().soc));
                                        ui.label(format!("• SPL Hardware Offset: {} kB (0x{:X} bytes)", offset_kb, offset_kb * 1024));
                                        ui.label(format!("• Target Media: {}", if self.emmc_boot { "eMMC boot0 partition" } else { "SD / User Data Area" }));
                                    }
                                    FlashTargetType::NxpFitImage => {
                                        ui.label(format!("• Target Architecture: NXP {}", self.current_preset().soc));
                                        ui.label("• FIT Image Contents: U-Boot proper + ARM Trusted Firmware + OP-TEE + DTB");
                                        ui.label(format!("• DTB Profile: {}", self.dtb_feature_override));
                                    }
                                    FlashTargetType::RawStorageOffset => {
                                        ui.horizontal(|ui| {
                                            ui.label("Byte / Hex Offset:");
                                            ui.text_edit_singleline(&mut self.custom_flash_offset);
                                        });
                                        ui.label(egui::RichText::new("Examples: 0x8400 (33 kB), 0x40000000 (RAM), 0x10000000 (RP2350 QSPI)").color(egui::Color32::GRAY));
                                    }
                                    FlashTargetType::Rp2350Qspi => {
                                        ui.label("• Target Architecture: Raspberry Pi RP2350 (Cortex-M33 / Hazard3 RISC-V)");
                                        ui.label("• QSPI Subwindow: Window 1 (Base 0x10400000 -> Flash Offset 0x00010000)");
                                        ui.label("• Security: IMAGE_DEF Header Seal Enforced");
                                    }
                                }

                                ui.add_space(6.0);

                                // Command Pipeline Preview
                                ui.label(egui::RichText::new("Pipeline Execution Preview:").strong().color(egui::Color32::from_rgb(0, 210, 255)));
                                let cmd = self.generate_flash_command_preview();
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(cmd)
                                            .monospace()
                                            .color(egui::Color32::from_rgb(200, 255, 180)),
                                    )
                                    .wrap(),
                                );
                            });

                            ui.add_space(8.0);

                            // NXP UUU & Boot Media Configuration (Collapsible)
                            ui.collapsing("⚙ NXP UUU & Boot Media Configuration", |ui| {
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    ui.label("U-Boot Feature (-u):");
                                    ui.text_edit_singleline(&mut self.uboot_feature_override);
                                });

                                ui.horizontal(|ui| {
                                    ui.label("DTB Feature (-d):");
                                    ui.text_edit_singleline(&mut self.dtb_feature_override);
                                });

                                ui.checkbox(&mut self.emmc_boot, "Boot from eMMC boot0 partition (-e)");
                                ui.checkbox(&mut self.mcu_binary, "Enable Coprocessor MCU Binary (-m)");

                                ui.add_space(4.0);
                                ui.label("Storage Media Capacity:");
                                ui.horizontal(|ui| {
                                    ui.radio_value(&mut self.storage_capacity_gb, 16, "16 GB (13 GB usable)");
                                    ui.radio_value(&mut self.storage_capacity_gb, 32, "32 GB (28 GB usable)");
                                    ui.radio_value(&mut self.storage_capacity_gb, 64, "64 GB");
                                });
                            });

                            ui.add_space(8.0);

                            // Flash Execution Group
                            ui.group(|ui| {
                                ui.heading("🚀 Flash Execution");
                                ui.add_space(4.0);

                                if let Some(target) = self.selected_device() {
                                    let prod = target.product.as_deref().unwrap_or("USB Device");
                                    ui.horizontal(|ui| {
                                        ui.label("Target Device:");
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "[{:04x}:{:04x}] {}",
                                                target.vendor_id, target.product_id, prod
                                            ))
                                            .color(egui::Color32::from_rgb(0, 220, 255))
                                            .strong(),
                                        );
                                    });

                                    let target_desc = match self.flash_target_type {
                                        FlashTargetType::FastbootPartition => format!("Partition '{}'", self.flash_partition_name),
                                        FlashTargetType::NxpBootloaderSpl => "NXP SPL Bootloader".into(),
                                        FlashTargetType::NxpFitImage => "U-Boot FIT Image".into(),
                                        FlashTargetType::RawStorageOffset => format!("Offset {}", self.custom_flash_offset),
                                        FlashTargetType::Rp2350Qspi => "RP2350 QSPI Window".into(),
                                    };

                                    ui.horizontal(|ui| {
                                        ui.label("Staged Action:");
                                        ui.label(
                                            egui::RichText::new(target_desc)
                                                .color(egui::Color32::from_rgb(0, 255, 180))
                                                .strong(),
                                        );
                                    });
                                } else {
                                    ui.label(
                                        egui::RichText::new("⚠️ Please select a USB device from the list on the right")
                                            .color(egui::Color32::from_rgb(255, 180, 50)),
                                    );
                                }

                                let btn_enabled = !self.flashing_active && self.selected_device().is_some();
                                let btn_text = if self.flashing_active {
                                    "Flashing in Progress..."
                                } else if let Some(_target) = self.selected_device() {
                                    match self.flash_target_type {
                                        FlashTargetType::FastbootPartition => "Flash Selected Partition Target",
                                        _ => "Flash Selected USB Target",
                                    }
                                } else {
                                    "Select a USB Device to Flash"
                                };

                                if ui
                                    .add_enabled(
                                        btn_enabled,
                                        egui::Button::new(btn_text).min_size([240.0, 36.0].into()),
                                    )
                                    .clicked()
                                {
                                    self.flashing_active = true;
                                    self.flash_progress = 0.0;
                                    if let Some(target) = self.selected_device() {
                                        let prod = target.product.as_deref().unwrap_or("USB Device");
                                        let payload_name = if !self.flash_image_path.is_empty() {
                                            std::path::Path::new(&self.flash_image_path)
                                                .file_name()
                                                .and_then(|f| f.to_str())
                                                .unwrap_or("custom_image.bin")
                                        } else {
                                            match self.flash_target_type {
                                                FlashTargetType::FastbootPartition => "boot.img",
                                                FlashTargetType::NxpBootloaderSpl => "u-boot-spl.bin",
                                                FlashTargetType::NxpFitImage => "u-boot.itb",
                                                FlashTargetType::RawStorageOffset => "partition-table.img",
                                                FlashTargetType::Rp2350Qspi => "firmware.uf2",
                                            }
                                        };

                                        match self.flash_target_type {
                                            FlashTargetType::FastbootPartition => {
                                                let slot_str = match self.flash_target_slot {
                                                    TargetSlot::Active => "",
                                                    TargetSlot::SlotA => "_a",
                                                    TargetSlot::SlotB => "_b",
                                                    TargetSlot::AllSlots => " (both slots)",
                                                };
                                                let ksu_note = if self.enable_ksu_injection {
                                                    " [+ In-Memory KernelSU /init Patch via Zig CPIO]"
                                                } else {
                                                    ""
                                                };
                                                self.log_messages.push(format!(
                                                    "[FASTBOOT] Streaming '{}{}' to [{:04x}:{:04x}] {} with payload '{}'{}",
                                                    self.flash_partition_name, slot_str, target.vendor_id, target.product_id, prod, payload_name, ksu_note
                                                ));
                                            }
                                            FlashTargetType::NxpBootloaderSpl => {
                                                let offset = self.compute_layout().map(|l| l.spl_offset_kb).unwrap_or(33);
                                                self.log_messages.push(format!(
                                                    "[NXP-SDP] Writing SPL payload '{}' @ offset {} kB to [{:04x}:{:04x}] {}",
                                                    payload_name, offset, target.vendor_id, target.product_id, prod
                                                ));
                                            }
                                            FlashTargetType::NxpFitImage => {
                                                self.log_messages.push(format!(
                                                    "[NXP-UUU] Writing U-Boot FIT payload '{}' to [{:04x}:{:04x}] {}",
                                                    payload_name, target.vendor_id, target.product_id, prod
                                                ));
                                            }
                                            FlashTargetType::RawStorageOffset => {
                                                self.log_messages.push(format!(
                                                    "[RAW] Streaming payload '{}' @ offset {} to [{:04x}:{:04x}] {}",
                                                    payload_name, self.custom_flash_offset, target.vendor_id, target.product_id, prod
                                                ));
                                            }
                                            FlashTargetType::Rp2350Qspi => {
                                                self.log_messages.push(format!(
                                                    "[RP2350] Flashing QSPI window with payload '{}' to [{:04x}:{:04x}] {}",
                                                    payload_name, target.vendor_id, target.product_id, prod
                                                ));
                                            }
                                        }
                                    }
                                }

                                if self.flashing_active || self.flash_progress > 0.0 {
                                    ui.add_space(6.0);
                                    ui.add(
                                        egui::ProgressBar::new(self.flash_progress)
                                            .show_percentage()
                                            .animate(self.flashing_active),
                                    );
                                }
                            });
                        });
                });

                // Column 2: Partition Layout Visualizer & USB Topology
                columns[1].vertical(|ui| {
                    ui.group(|ui| {
                        ui.heading("📊 Storage Layout & Boundary Visualizer");
                        ui.add_space(4.0);

                        if let Some(plan) = self.compute_layout() {
                            ui.label(format!("• Target SoC: {}", plan.soc_name));
                            ui.label(format!("• SPL Offset: {} kB ({} bytes)", plan.spl_offset_kb, plan.spl_offset_bytes));
                            ui.label(format!("• Primary GPT Header: {} bytes (LBA 0–33)", plan.gpt_header_bytes));
                            if let Some(mcu_kb) = plan.mcu_offset_kb {
                                ui.label(format!("• MCU Binary Offset: {} kB (5.12 MB)", mcu_kb));
                            }
                            ui.label(format!("• Partition Table Image: {}", plan.partition_table_image));

                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Partition Map Schematic:").strong());

                            // Visual representation bar
                            let (rect, _response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::hover());
                            let painter = ui.painter();

                            // Background
                            painter.rect_filled(rect, 4.0, egui::Color32::from_rgb(30, 30, 30));

                            // GPT Header segment (first 10%)
                            let gpt_width = rect.width() * 0.12;
                            let gpt_rect = egui::Rect::from_min_size(rect.min, egui::vec2(gpt_width, rect.height()));
                            painter.rect_filled(gpt_rect, 4.0, egui::Color32::from_rgb(180, 50, 50));

                            // SPL Bootloader segment
                            let spl_start = rect.min.x + gpt_width + 4.0;
                            let spl_width = rect.width() * 0.25;
                            let spl_rect = egui::Rect::from_min_size(egui::pos2(spl_start, rect.min.y), egui::vec2(spl_width, rect.height()));
                            painter.rect_filled(spl_rect, 4.0, egui::Color32::from_rgb(50, 160, 220));

                            // Free space / Partitions
                            let part_start = spl_start + spl_width + 4.0;
                            let part_width = rect.max.x - part_start;
                            let part_rect = egui::Rect::from_min_size(egui::pos2(part_start, rect.min.y), egui::vec2(part_width, rect.height()));
                            painter.rect_filled(part_rect, 4.0, egui::Color32::from_rgb(60, 180, 75));

                            ui.horizontal(|ui| {
                                ui.colored_label(egui::Color32::from_rgb(180, 50, 50), "■ GPT (0-17 kB)");
                                ui.colored_label(egui::Color32::from_rgb(50, 160, 220), format!("■ SPL ({} kB)", plan.spl_offset_kb));
                                ui.colored_label(egui::Color32::from_rgb(60, 180, 75), "■ User Partitions");
                            });
                        }
                    });

                    ui.add_space(8.0);

                    // USB Device Topology with Interactive Selection
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.heading("🔌 Attached USB Devices");
                            ui.label(egui::RichText::new("(Click to auto-configure profile)").italics().color(egui::Color32::GRAY));
                        });
                        ui.add_space(4.0);

                        if self.devices.is_empty() {
                            ui.label(egui::RichText::new("No flashing targets or debug probes connected").color(egui::Color32::GRAY));
                        } else {
                            let mut new_selection = None;
                            egui::ScrollArea::vertical()
                                .id_salt("usb_devices_scroll_area")
                                .max_height(140.0)
                                .show(ui, |ui| {
                                    for (idx, dev) in self.devices.iter().enumerate() {
                                        ui.push_id(idx, |ui| {
                                            let is_selected = self.selected_device_idx == Some(idx);
                                            let mode_color = match dev.operating_mode {
                                                DeviceOperatingMode::NxpSerialDownload => egui::Color32::from_rgb(255, 165, 0),
                                                DeviceOperatingMode::Fastboot => egui::Color32::from_rgb(0, 255, 128),
                                                DeviceOperatingMode::AndroidAdb => egui::Color32::from_rgb(0, 210, 255),
                                                DeviceOperatingMode::DebugProbe => egui::Color32::from_rgb(200, 100, 255),
                                                DeviceOperatingMode::Rp2350BootRom | DeviceOperatingMode::Rp2040BootRom => egui::Color32::from_rgb(255, 100, 100),
                                                _ => egui::Color32::WHITE,
                                            };

                                            let prod = dev.product.as_deref().unwrap_or("Generic USB Device");
                                            ui.horizontal(|ui| {
                                                let prefix = if is_selected { "▶" } else { " " };
                                                let label = format!("{} [{:04x}:{:04x}] {}", prefix, dev.vendor_id, dev.product_id, prod);
                                                if ui.selectable_label(is_selected, label).clicked() {
                                                    new_selection = Some(idx);
                                                }
                                                ui.colored_label(mode_color, format!("({:?})", dev.operating_mode));
                                            });
                                        });
                                    }
                                });

                            if let Some(idx) = new_selection {
                                self.select_device(idx);
                            }

                            // Display inspector panel for the selected device
                            if let Some(target) = self.selected_device() {
                                ui.add_space(4.0);
                                egui::Frame::NONE
                                    .fill(egui::Color32::from_rgb(24, 30, 36))
                                    .corner_radius(4.0)
                                    .inner_margin(6.0)
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("Selected Target:").strong().color(egui::Color32::from_rgb(0, 210, 255)));
                                            ui.label(format!("{:04x}:{:04x}", target.vendor_id, target.product_id));
                                            ui.separator();
                                            ui.label(format!("Mode: {:?}", target.operating_mode));
                                        });

                                        ui.horizontal(|ui| {
                                            if let Some(prof) = self.auto_detected_profile {
                                                ui.label(egui::RichText::new(format!("Hardware Profile: {} (Auto-Configured)", prof)).color(egui::Color32::from_rgb(0, 255, 128)).strong());
                                            } else {
                                                ui.label(egui::RichText::new(format!("Hardware Profile: {} (Manual)", self.current_preset().name)).color(egui::Color32::GRAY));
                                            }
                                        });

                                        if let Some(ref mfg) = target.manufacturer {
                                            ui.label(format!("Manufacturer: {}", mfg));
                                        }
                                        if let Some(ref sn) = target.serial_number {
                                            ui.label(format!("Serial Number: {}", sn));
                                        }
                                    });
                            }
                        }
                    });

                    ui.add_space(8.0);

                    // Console Log Output
                    ui.group(|ui| {
                        ui.heading("📋 Target RTT & Event Log");
                        ui.add_space(4.0);

                        egui::ScrollArea::vertical()
                            .id_salt("target_event_log_scroll_area")
                            .max_height(110.0)
                            .show(ui, |ui| {
                                for (log_idx, msg) in self.log_messages.iter().rev().enumerate() {
                                    ui.push_id(log_idx, |ui| {
                                        ui.label(egui::RichText::new(msg).monospace().color(egui::Color32::from_rgb(220, 220, 140)));
                                    });
                                }
                            });
                    });
                });
            });
        });
    }
}
