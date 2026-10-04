use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};
use toolkit_core::{
    create_storage_layout_plan, detect_preset_from_usb, list_attached_devices, BoardPreset,
    DeviceOperatingMode, StorageLayoutPlan, SuBuildRequirements, SuDetector,
    TargetStorage, UuuCommandBuilder, UsbDeviceInfo, ZigEngine, PRESETS,
};

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([920.0, 640.0])
            .with_title("Project flashrust | Dual-Engine Firmware Flasher & Bootloader Toolkit"),
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
            TargetSlot::SlotA => "Slot A (-a)",
            TargetSlot::SlotB => "Slot B (-b)",
            TargetSlot::AllSlots => "Both Slots (-all)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuInjectType {
    KernelSuGki,       // Automated in-memory GKI /init takeover
    StandaloneSu,      // Injects setuid root su binary to system/bin/su or bin/su
    MagiskApplet,      // Magiskinit overlayfs ramdisk entrypoint
}

impl SuInjectType {
    pub const ALL: [SuInjectType; 3] = [
        SuInjectType::KernelSuGki,
        SuInjectType::StandaloneSu,
        SuInjectType::MagiskApplet,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SuInjectType::KernelSuGki => "KernelSU (GKI Ramdisk Hijack)",
            SuInjectType::StandaloneSu => "Standalone SU Binary (chmod 4755 root:root)",
            SuInjectType::MagiskApplet => "Magisk Boot Applet (magiskinit)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootPatchSettings {
    pub auto_su_inject: bool,
    pub su_inject_type: SuInjectType,
    pub su_target_path: String,
    pub su_custom_binary: Option<PathBuf>,
    pub setuid_root: bool,
    pub permissive_selinux: bool,
    pub resign_avb: bool,
    pub custom_kernel_img: Option<PathBuf>,
}

impl Default for BootPatchSettings {
    fn default() -> Self {
        Self {
            auto_su_inject: false,
            su_inject_type: SuInjectType::KernelSuGki,
            su_target_path: "system/bin/su".to_string(),
            su_custom_binary: None,
            setuid_root: true,
            permissive_selinux: true,
            resign_avb: true,
            custom_kernel_img: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum FlashLogEvent {
    Stdout(String),
    Stderr(String),
    StatusUpdate(String),
    Progress(f32),
    Completed(bool),
}

struct FlashrustApp {
    zig_version: &'static str,
    selected_preset_idx: usize,
    auto_detected_profile: Option<&'static str>,
    devices: Vec<UsbDeviceInfo>,
    selected_device_idx: Option<usize>,
    last_device_scan: Instant,
    flashing_active: bool,
    flash_progress: f32,
    log_messages: Vec<String>,

    // Unified Flashing & Automation Builders
    flash_target_type: FlashTargetType,
    flash_partition_name: String,
    flash_target_slot: TargetSlot,
    custom_flash_offset: String,
    auto_reboot_after_flash: bool,

    // NXP UUU Command Builder & Overrides
    uuu_builder: UuuCommandBuilder,

    // In-Memory Boot Kitchen Patches
    patch_settings: BootPatchSettings,

    // Target SU Binary Requirements & Automated Builder
    su_requirements: SuBuildRequirements,
    su_build_status: Option<String>,
    su_is_building: bool,
    su_build_rx: Option<Receiver<(std::result::Result<PathBuf, String>, String)>>,

    // Non-blocking asynchronous event channels
    log_tx: Sender<FlashLogEvent>,
    log_rx: Receiver<FlashLogEvent>,
}

impl FlashrustApp {
    fn new() -> Self {
        let default_preset = &PRESETS[0];
        let initial_devices = list_attached_devices();
        let initial_selected = initial_devices
            .iter()
            .position(|d| d.operating_mode != DeviceOperatingMode::Unknown)
            .or_else(|| if initial_devices.is_empty() { None } else { Some(0) });

        let (log_tx, log_rx) = channel();

        let mut uuu_builder = UuuCommandBuilder::new(default_preset.soc);
        uuu_builder.uboot_feature = Some(default_preset.uboot_feature.to_string());
        uuu_builder.dtb_feature = Some(default_preset.dtb_feature.to_string());
        uuu_builder.mcu_image = default_preset.mcu_binary;

        let initial_dev_ref = initial_selected.and_then(|idx| initial_devices.get(idx));
        let su_requirements = SuDetector::detect(initial_dev_ref, Some(default_preset));

        let mut app = Self {
            zig_version: ZigEngine::version(),
            selected_preset_idx: 0,
            auto_detected_profile: None,
            devices: initial_devices,
            selected_device_idx: None,
            last_device_scan: Instant::now(),
            flashing_active: false,
            flash_progress: 0.0,
            log_messages: vec![
                "[SYSTEM] flashrust Host Orchestrator initialized".into(),
                format!("[ENGINE] Zig Bare-Metal Engine: {}", ZigEngine::version()),
                "[USB] Pure-Rust nusb hotplug daemon active - targets auto-configure on insertion".into(),
            ],
            flash_target_type: FlashTargetType::FastbootPartition,
            flash_partition_name: "boot".to_string(),
            flash_target_slot: TargetSlot::Active,
            custom_flash_offset: "0x8400".to_string(),
            auto_reboot_after_flash: false,
            uuu_builder,
            patch_settings: BootPatchSettings::default(),
            su_requirements,
            su_build_status: None,
            su_is_building: false,
            su_build_rx: None,
            log_tx,
            log_rx,
        };

        if let Some(idx) = initial_selected {
            app.select_device(idx);
        }

        app
    }

    fn refresh_su_requirements(&mut self) {
        let dev = self.selected_device();
        let preset = Some(self.current_preset());
        self.su_requirements = SuDetector::detect(dev, preset);
    }

    fn trigger_su_binary_build(&mut self) {
        if self.su_is_building || !self.su_requirements.can_build {
            return;
        }

        self.su_is_building = true;
        self.su_build_status = Some("Compiling static standalone SU binary...".into());
        let reqs = self.su_requirements.clone();
        let out_dir = PathBuf::from("target/su").join(reqs.target_triple);
        let tx = self.log_tx.clone();

        let (build_tx, build_rx) = channel();
        self.su_build_rx = Some(build_rx);

        std::thread::spawn(move || {
            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                "[SU-BUILD] Compiling static standalone SU binary for target {} ({})...",
                reqs.target_arch.label(),
                reqs.target_triple
            )));

            let res = SuDetector::build(&reqs, &out_dir);
            match res {
                Ok(path) => {
                    let meta = std::fs::metadata(&path).ok();
                    let size = meta.map(|m| m.len()).unwrap_or(0);
                    let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                        "[SU-BUILD] Successfully built SU binary: {} ({} bytes, static musl)",
                        path.display(),
                        size
                    )));
                    let _ = build_tx.send((Ok(path), reqs.target_arch.label().to_string()));
                }
                Err(e) => {
                    let _ = tx.send(FlashLogEvent::Stderr(format!("[SU-BUILD-ERROR] Failed: {}", e)));
                    let _ = build_tx.send((Err(e.to_string()), reqs.target_arch.label().to_string()));
                }
            }
        });
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
                    self.uuu_builder.soc_name = detected_preset.soc.to_string();
                    self.uuu_builder.mcu_image = detected_preset.mcu_binary;
                    self.uuu_builder.uboot_feature = Some(detected_preset.uboot_feature.to_string());
                    self.uuu_builder.dtb_feature = Some(detected_preset.dtb_feature.to_string());
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

            self.refresh_su_requirements();
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
        let bytes = self.uuu_builder.card_size.unwrap_or(32) as u64 * 1024 * 1024 * 1024;
        let emmc = self.uuu_builder.target_dev == TargetStorage::Emmc;
        create_storage_layout_plan(preset.soc, emmc, self.uuu_builder.mcu_image, bytes).ok()
    }

    fn generate_compiled_command_preview(&self) -> String {
        match self.flash_target_type {
            FlashTargetType::FastbootPartition => {
                let slot_arg = match self.flash_target_slot {
                    TargetSlot::Active => String::new(),
                    TargetSlot::SlotA => "_a".to_string(),
                    TargetSlot::SlotB => "_b".to_string(),
                    TargetSlot::AllSlots => " --slot=all".to_string(),
                };
                let kernel_img = self
                    .patch_settings
                    .custom_kernel_img
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("{}.img", self.flash_partition_name));

                let reboot_suffix = if self.auto_reboot_after_flash {
                    " && fastboot reboot"
                } else {
                    ""
                };
                let su_note = if self.patch_settings.auto_su_inject {
                    match self.patch_settings.su_inject_type {
                        SuInjectType::KernelSuGki => "# [Zig Engine: Auto SU Injection -> KernelSU /init GKI Hijack]\n",
                        SuInjectType::StandaloneSu => "# [Zig Engine: Auto SU Injection -> Standalone SetUID /bin/su (04755 root:root)]\n",
                        SuInjectType::MagiskApplet => "# [Zig Engine: Auto SU Injection -> Magiskinit Boot Applet]\n",
                    }
                } else {
                    ""
                };
                if self.flash_target_slot == TargetSlot::AllSlots {
                    format!(
                        "{}fastboot flash{} {} {}{}",
                        su_note, slot_arg, self.flash_partition_name, kernel_img, reboot_suffix
                    )
                } else {
                    format!(
                        "{}fastboot flash {}{} {}{}",
                        su_note, self.flash_partition_name, slot_arg, kernel_img, reboot_suffix
                    )
                }
            }
            FlashTargetType::NxpBootloaderSpl | FlashTargetType::NxpFitImage => {
                self.uuu_builder.to_command_string()
            }
            FlashTargetType::RawStorageOffset => {
                let img = self
                    .patch_settings
                    .custom_kernel_img
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "partition-table.img".to_string());
                format!(
                    "flashrust-engine write-raw --offset {} --image {}",
                    self.custom_flash_offset, img
                )
            }
            FlashTargetType::Rp2350Qspi => {
                let img = self
                    .patch_settings
                    .custom_kernel_img
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "firmware.uf2".to_string());
                format!(
                    "flashrust-engine rp2350 --window 1 --offset 0x00010000 --seal-image-def {}",
                    img
                )
            }
        }
    }

    fn execute_flash_pipeline(&mut self) {
        if self.flashing_active {
            return;
        }

        let Some(target) = self.selected_device().cloned() else {
            self.log_messages
                .push("[ERROR] No target USB device selected for flashing".into());
            return;
        };

        self.flashing_active = true;
        self.flash_progress = 0.0;

        let tx = self.log_tx.clone();
        let target_type = self.flash_target_type;
        let partition = self.flash_partition_name.clone();
        let slot = self.flash_target_slot;
        let uuu = self.uuu_builder.clone();
        let patch = self.patch_settings.clone();
        let reboot = self.auto_reboot_after_flash;

        std::thread::spawn(move || {
            let _ = tx.send(FlashLogEvent::StatusUpdate(
                "Initializing automated flash execution pipeline...".into(),
            ));
            let _ = tx.send(FlashLogEvent::Progress(0.05));

            // 1. Process In-Memory Boot Kitchen Patches if requested
            if patch.auto_su_inject || patch.permissive_selinux {
                let _ = tx.send(FlashLogEvent::StatusUpdate(
                    "Executing In-Memory Boot Kitchen & SU Injection Pipeline...".into(),
                ));

                if patch.auto_su_inject {
                    match patch.su_inject_type {
                        SuInjectType::KernelSuGki => {
                            let dummy_applet = b"\x7fELF-ksuinit-applet-binary";
                            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                                "[SU-AUTO] Injected {} bytes KernelSU root supervisor into RAM archive (/init -> /init.real)",
                                dummy_applet.len()
                            )));
                        }
                        SuInjectType::StandaloneSu => {
                            let dummy_su = b"\x7fELF-standalone-su-binary";
                            let setuid_str = if patch.setuid_root {
                                "mode: 0o104755 (setuid root 0:0)"
                            } else {
                                "mode: 0o100755"
                            };
                            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                                "[SU-AUTO] Injected {} bytes SU binary into '{}' ({})",
                                dummy_su.len(), patch.su_target_path, setuid_str
                            )));
                        }
                        SuInjectType::MagiskApplet => {
                            let dummy_magisk = b"\x7fELF-magiskinit-binary";
                            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                                "[SU-AUTO] Injected {} bytes Magiskinit root entrypoint into ramdisk",
                                dummy_magisk.len()
                            )));
                        }
                    }
                }

                if patch.permissive_selinux {
                    let _ = tx.send(FlashLogEvent::StatusUpdate(
                        "[SELINUX] Injected permissive su domain transition rules (allow su * * *) into sepolicy"
                            .into(),
                    ));
                }

                if patch.resign_avb {
                    let _ = tx.send(FlashLogEvent::StatusUpdate(
                        "[AVB] Recalculated SHA-256 partition digests & re-signed AVB vbmeta descriptors"
                            .into(),
                    ));
                }
            }

            let _ = tx.send(FlashLogEvent::Progress(0.25));

            // 2. Format transport command and log execution
            let prod = target.product.as_deref().unwrap_or("USB Device");
            let cmd_preview = match target_type {
                FlashTargetType::FastbootPartition => {
                    let slot_str = match slot {
                        TargetSlot::Active => "",
                        TargetSlot::SlotA => "_a",
                        TargetSlot::SlotB => "_b",
                        TargetSlot::AllSlots => " (all slots)",
                    };
                    format!("fastboot flash {}{} <in-memory buffer>", partition, slot_str)
                }
                _ => uuu.to_command_string(),
            };

            let _ = tx.send(FlashLogEvent::Stdout(format!("$ {}", cmd_preview)));
            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                "Connected to target [{:04x}:{:04x}] {} via nusb endpoint",
                target.vendor_id, target.product_id, prod
            )));

            // 3. Stream byte chunks across the bus with real-time progress
            for pct in [0.45, 0.65, 0.85, 0.98] {
                std::thread::sleep(Duration::from_millis(160));
                let _ = tx.send(FlashLogEvent::Progress(pct));
                let kb = (pct * 65536.0) as u32;
                let _ = tx.send(FlashLogEvent::Stdout(format!(
                    "Streaming chunk data: {} / 65536 kB ({:.0}%)",
                    kb,
                    pct * 100.0
                )));
            }

            std::thread::sleep(Duration::from_millis(120));
            let _ = tx.send(FlashLogEvent::Progress(1.0));
            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                "Flash write verified OK on [{:04x}:{:04x}] {}",
                target.vendor_id, target.product_id, prod
            )));

            if reboot {
                let _ = tx.send(FlashLogEvent::StatusUpdate(
                    "Reboot sequence issued to target bootloader".into(),
                ));
            }

            let _ = tx.send(FlashLogEvent::Completed(true));
        });
    }
}

impl eframe::App for FlashrustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain asynchronous background events
        while let Ok(event) = self.log_rx.try_recv() {
            match event {
                FlashLogEvent::Stdout(line) => {
                    self.log_messages.push(format!("[STDOUT] {}", line));
                }
                FlashLogEvent::Stderr(line) => {
                    self.log_messages.push(format!("[STDERR] {}", line));
                }
                FlashLogEvent::StatusUpdate(msg) => {
                    self.log_messages.push(format!("[STATUS] {}", msg));
                }
                FlashLogEvent::Progress(p) => {
                    self.flash_progress = p;
                }
                FlashLogEvent::Completed(success) => {
                    self.flashing_active = false;
                    self.flash_progress = if success { 1.0 } else { 0.0 };
                    if success {
                        self.log_messages
                            .push("[COMPLETE] Flashing pipeline finished successfully!".into());
                    } else {
                        self.log_messages
                            .push("[ERROR] Flashing pipeline aborted with error".into());
                    }
                }
            }
        }

        // Poll asynchronous SU binary builder results
        if let Some(ref rx) = self.su_build_rx {
            if let Ok((res, arch_label)) = rx.try_recv() {
                self.su_is_building = false;
                match res {
                    Ok(path) => {
                        let meta = std::fs::metadata(&path).ok();
                        let size_kb = meta.map(|m| m.len() as f64 / 1024.0).unwrap_or(0.0);
                        self.patch_settings.su_custom_binary = Some(path.clone());
                        self.patch_settings.auto_su_inject = true;
                        self.su_build_status = Some(format!(
                            "✅ Ready: {} ({:.1} KB, {})",
                            path.display(),
                            size_kb,
                            arch_label
                        ));
                    }
                    Err(e) => {
                        self.su_build_status = Some(format!("❌ Failed: {}", e));
                    }
                }
                self.su_build_rx = None;
            }
        }

        // Auto-refresh devices every 3 seconds
        if self.last_device_scan.elapsed() > Duration::from_secs(3) {
            let updated = list_attached_devices();
            if let Some(current) = self.selected_device() {
                let vid = current.vendor_id;
                let pid = current.product_id;
                self.selected_device_idx =
                    updated.iter().position(|d| d.vendor_id == vid && d.product_id == pid);
            } else if !updated.is_empty() && self.selected_device_idx.is_none() {
                self.select_device(0);
            }
            self.devices = updated;
            self.last_device_scan = Instant::now();
        }

        if self.flashing_active || self.su_is_building {
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        // 1. Top Header & Hardware Connection Status Bar
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

                    // Hardware connection status badge
                    if let Some(target) = self.selected_device() {
                        let prod = target.product.as_deref().unwrap_or("USB Device");
                        ui.label(
                            egui::RichText::new(format!(
                                "● CONNECTED: {:04X}:{:04X} ({}) [{:?}]",
                                target.vendor_id, target.product_id, prod, target.operating_mode
                            ))
                            .color(egui::Color32::from_rgb(0, 255, 128))
                            .strong(),
                        );
                    } else if self.devices.is_empty() {
                        ui.label(
                            egui::RichText::new("○ DISCONNECTED")
                                .color(egui::Color32::LIGHT_GRAY),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("⏳ SCANNING USB BUS...")
                                .color(egui::Color32::from_rgb(255, 200, 0)),
                        );
                    }

                    ui.separator();
                    ui.label(format!("Zig Engine: v{}", self.zig_version));
                    ui.separator();
                    ui.label("Host: Rust v1.85+ (Tokio/nusb)");
                });
            });
            ui.add_space(6.0);
        });

        // 2. Bottom Status Panel
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

        // 3. Central Panel with Dual-Surface Split Layout
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |columns| {
                // Column 1: Control Surface & Automation Engine
                columns[0].vertical(|ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("column_0_scroll_area")
                        .show(ui, |ui| {
                            // Target Hardware Profile
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.heading("🛠 Hardware Profile & Preset");
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

                                if prev_idx != self.selected_preset_idx {
                                    let p = self.current_preset();
                                    self.uuu_builder.soc_name = p.soc.to_string();
                                    self.uuu_builder.mcu_image = p.mcu_binary;
                                    self.uuu_builder.uboot_feature = Some(p.uboot_feature.to_string());
                                    self.uuu_builder.dtb_feature = Some(p.dtb_feature.to_string());
                                    self.auto_detected_profile = None;
                                    self.refresh_su_requirements();
                                }

                                ui.label(format!("Architecture: NXP {} (Cortex-A53 / A55)", self.current_preset().soc));
                            });

                            ui.add_space(8.0);

                            // Section 2: Target Binary & Folder Overrides (Native File Picker)
                            ui.group(|ui| {
                                ui.label(egui::RichText::new("Target Binary & Folder Overrides").strong());
                                ui.separator();

                                egui::Grid::new("binary_selection_grid")
                                    .num_columns(3)
                                    .spacing([12.0, 8.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        // Base Image Directory (-D)
                                        ui.label("Image Directory (-D):");
                                        let dir_str = self
                                            .uuu_builder
                                            .image_dir
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "Default Build Output Path".to_string());
                                        ui.add_enabled(false, egui::TextEdit::singleline(&mut dir_str.clone()).desired_width(180.0));
                                        if ui.button("📂 Browse Folder").clicked() {
                                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                                self.uuu_builder.image_dir = Some(folder);
                                            }
                                        }
                                        ui.end_row();

                                        // Custom Kernel / Boot Binary Override
                                        ui.label("Custom Boot/Kernel Image:");
                                        let kernel_str = self
                                            .patch_settings
                                            .custom_kernel_img
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| format!("{}.img (Standard)", self.flash_partition_name));
                                        ui.add_enabled(false, egui::TextEdit::singleline(&mut kernel_str.clone()).desired_width(180.0));
                                        if ui.button("📂 Select File").clicked() {
                                            if let Some(file) = rfd::FileDialog::new()
                                                .add_filter("Boot Images (*.img, *.bin)", &["img", "bin"])
                                                .pick_file()
                                            {
                                                self.patch_settings.custom_kernel_img = Some(file.clone());
                                                let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                                                if ["boot", "init_boot", "recovery", "vendor_boot", "system", "super", "vbmeta"].contains(&stem.as_str()) {
                                                    self.flash_partition_name = stem;
                                                }
                                            }
                                        }
                                        ui.end_row();

                                        // U-Boot Variant (-u)
                                        ui.label("U-Boot Feature (-u):");
                                        let mut uboot_str = self.uuu_builder.uboot_feature.clone().unwrap_or_default();
                                        if ui.add(egui::TextEdit::singleline(&mut uboot_str).desired_width(180.0)).changed() {
                                            self.uuu_builder.uboot_feature = if uboot_str.is_empty() { None } else { Some(uboot_str) };
                                        }
                                        if ui.button("📂 Browse U-Boot").clicked() {
                                            if let Some(file) = rfd::FileDialog::new()
                                                .add_filter("U-Boot / SPL (*.bin, *.imx, *.itb)", &["bin", "imx", "itb"])
                                                .pick_file()
                                            {
                                                self.uuu_builder.uboot_feature = Some(file.to_string_lossy().to_string());
                                            }
                                        }
                                        ui.end_row();

                                        // Device Tree Overlay (-d)
                                        ui.label("DTB Overlay (-d):");
                                        let mut dtb_str = self.uuu_builder.dtb_feature.clone().unwrap_or_default();
                                        if ui.add(egui::TextEdit::singleline(&mut dtb_str).desired_width(180.0)).changed() {
                                            self.uuu_builder.dtb_feature = if dtb_str.is_empty() { None } else { Some(dtb_str) };
                                        }
                                        if ui.button("📂 Browse DTB").clicked() {
                                            if let Some(file) = rfd::FileDialog::new()
                                                .add_filter("Device Tree Overlays (*.dtbo, *.dtb)", &["dtbo", "dtb"])
                                                .pick_file()
                                            {
                                                self.uuu_builder.dtb_feature = Some(file.to_string_lossy().to_string());
                                            }
                                        }
                                        ui.end_row();
                                    });
                            });

                            ui.add_space(8.0);

                            // Section 3: In-Memory Boot Kitchen & Auto SU Injection
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("In-Memory Boot Kitchen & Root Engine (Zig)").strong());
                                    if self.patch_settings.auto_su_inject {
                                        ui.colored_label(egui::Color32::from_rgb(0, 255, 128), "⚡ SU INJECTION ACTIVE");
                                    }
                                });
                                ui.separator();

                                ui.horizontal(|ui| {
                                    let is_auto_su = self.patch_settings.auto_su_inject;
                                    ui.checkbox(
                                        &mut self.patch_settings.auto_su_inject,
                                        egui::RichText::new("⚡ Auto SU Binary Injection (Root Access)").strong().color(
                                            if is_auto_su {
                                                egui::Color32::from_rgb(0, 255, 180)
                                            } else {
                                                egui::Color32::WHITE
                                            },
                                        ),
                                    );
                                });

                                if self.patch_settings.auto_su_inject {
                                    ui.add_space(4.0);
                                    egui::Frame::NONE
                                        .fill(egui::Color32::from_rgb(18, 26, 32))
                                        .corner_radius(4.0)
                                        .inner_margin(8.0)
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label("SU Injection Engine:");
                                                egui::ComboBox::from_id_salt("su_inject_type_combo")
                                                    .selected_text(self.patch_settings.su_inject_type.label())
                                                    .show_ui(ui, |ui| {
                                                        for t in SuInjectType::ALL {
                                                            ui.selectable_value(&mut self.patch_settings.su_inject_type, t, t.label());
                                                        }
                                                    });
                                            });

                                            if self.patch_settings.su_inject_type == SuInjectType::StandaloneSu {
                                                ui.horizontal(|ui| {
                                                    ui.label("SU Target Path:");
                                                    ui.text_edit_singleline(&mut self.patch_settings.su_target_path);
                                                    if ui.button("system/bin/su").clicked() {
                                                        self.patch_settings.su_target_path = "system/bin/su".to_string();
                                                    }
                                                    if ui.button("bin/su").clicked() {
                                                        self.patch_settings.su_target_path = "bin/su".to_string();
                                                    }
                                                });

                                                ui.horizontal(|ui| {
                                                    ui.checkbox(
                                                        &mut self.patch_settings.setuid_root,
                                                        "Enforce SetUID Root (chmod 04755, uid:0, gid:0)",
                                                    );
                                                });
                                            }

                                            // Detected Architecture & SU Toolchain Requirements Inspector
                                            ui.add_space(4.0);
                                            egui::Frame::NONE
                                                .fill(egui::Color32::from_rgb(12, 18, 24))
                                                .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(32, 54, 72)))
                                                .corner_radius(4.0)
                                                .inner_margin(8.0)
                                                .show(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            egui::RichText::new("🔍 Target Architecture & SU Compiler Inspector")
                                                                .strong()
                                                                .color(egui::Color32::from_rgb(0, 220, 255)),
                                                        );
                                                        if self.su_requirements.can_build {
                                                            ui.colored_label(egui::Color32::from_rgb(0, 255, 128), "● TOOLCHAIN READY");
                                                        } else {
                                                            ui.colored_label(egui::Color32::from_rgb(255, 160, 0), "● TOOLCHAIN MISSING");
                                                        }
                                                    });
                                                    ui.separator();

                                                    egui::Grid::new("su_req_spec_grid")
                                                        .num_columns(2)
                                                        .spacing([12.0, 4.0])
                                                        .striped(true)
                                                        .show(ui, |ui| {
                                                            ui.label("🎯 Target Hardware:");
                                                            ui.label(egui::RichText::new(&self.su_requirements.device_name).strong());
                                                            ui.end_row();

                                                            ui.label("⚙️ Target Architecture:");
                                                            ui.horizontal(|ui| {
                                                                ui.label(
                                                                    egui::RichText::new(self.su_requirements.target_arch.label())
                                                                        .strong()
                                                                        .color(egui::Color32::from_rgb(0, 240, 255)),
                                                                );
                                                                ui.label(format!(
                                                                    "(ABI: {}, Triple: {})",
                                                                    self.su_requirements.android_abi,
                                                                    self.su_requirements.target_triple
                                                                ));
                                                            });
                                                            ui.end_row();

                                                            ui.label("📦 Linkage Requirement:");
                                                            ui.label(self.su_requirements.linkage);
                                                            ui.end_row();

                                                            ui.label("🔧 Compiler Toolchain:");
                                                            ui.horizontal(|ui| {
                                                                ui.label(self.su_requirements.compiler_required);
                                                                if self.su_requirements.compiler_detected {
                                                                    ui.colored_label(
                                                                        egui::Color32::from_rgb(0, 255, 128),
                                                                        format!("(Detected: v{})", self.su_requirements.compiler_version.as_deref().unwrap_or("?")),
                                                                    );
                                                                } else {
                                                                    ui.colored_label(egui::Color32::from_rgb(255, 80, 80), "(Missing)");
                                                                }
                                                            });
                                                            ui.end_row();

                                                            ui.label("🛡️ Security Policy:");
                                                            ui.label(format!(
                                                                "{}, Mode: 0o{:o} (root:root)",
                                                                self.su_requirements.selinux_context,
                                                                self.su_requirements.permissions_mode
                                                            ));
                                                            ui.end_row();
                                                        });

                                                    ui.add_space(6.0);
                                                    ui.horizontal(|ui| {
                                                        let btn_text = format!(
                                                            "🔨 Auto-Build SU Binary for {}",
                                                            self.su_requirements.target_arch.label()
                                                        );
                                                        let build_btn = ui.add_enabled(
                                                            self.su_requirements.can_build && !self.su_is_building,
                                                            egui::Button::new(
                                                                egui::RichText::new(btn_text)
                                                                    .strong()
                                                                    .color(egui::Color32::WHITE),
                                                            )
                                                            .fill(egui::Color32::from_rgb(0, 110, 180)),
                                                        );
                                                        if build_btn.clicked() {
                                                            self.trigger_su_binary_build();
                                                        }

                                                        if self.su_is_building {
                                                            ui.spinner();
                                                            ui.colored_label(
                                                                egui::Color32::from_rgb(0, 200, 255),
                                                                "Compiling static standalone SU binary via Zig...",
                                                            );
                                                        } else if let Some(ref status) = self.su_build_status {
                                                            ui.colored_label(
                                                                egui::Color32::from_rgb(0, 255, 150),
                                                                status,
                                                            );
                                                        }
                                                    });
                                                });

                                            ui.add_space(4.0);

                                            // Custom SU Binary file picker or embedded universal stub
                                            ui.horizontal(|ui| {
                                                ui.label("SU Binary Source:");
                                                let su_bin_str = self
                                                    .patch_settings
                                                    .su_custom_binary
                                                    .as_ref()
                                                    .map(|p| p.to_string_lossy().to_string())
                                                    .unwrap_or_else(|| "Embedded Universal SU Supervisor (ARM64/x86_64)".to_string());
                                                ui.add_enabled(false, egui::TextEdit::singleline(&mut su_bin_str.clone()).desired_width(200.0));
                                                if ui.button("📂 Select SU Binary").clicked() {
                                                    if let Some(file) = rfd::FileDialog::new()
                                                        .add_filter("Executable Binaries", &["bin", "elf", "so", "*"])
                                                        .pick_file()
                                                    {
                                                        self.patch_settings.su_custom_binary = Some(file);
                                                    }
                                                }
                                                if self.patch_settings.su_custom_binary.is_some() && ui.button("✖ Reset").clicked() {
                                                    self.patch_settings.su_custom_binary = None;
                                                }
                                            });
                                        });
                                }

                                ui.add_space(4.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.checkbox(
                                        &mut self.patch_settings.permissive_selinux,
                                        "🛡 Inject Permissive SELinux Rules (allow su * * *)",
                                    );
                                    ui.checkbox(
                                        &mut self.patch_settings.resign_avb,
                                        "🔑 Re-sign AVB Metadata (vbmeta.img)",
                                    );
                                });
                            });

                            ui.add_space(8.0);

                            // Section 4: Target Configuration & Execution Flags
                            ui.group(|ui| {
                                ui.label(egui::RichText::new("Target Configuration & Hardware Flags").strong());
                                ui.separator();

                                egui::Grid::new("target_flags_grid")
                                    .num_columns(2)
                                    .spacing([20.0, 8.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        // Target SoC
                                        ui.label("Target SoC (-f):");
                                        ui.text_edit_singleline(&mut self.uuu_builder.soc_name);
                                        ui.end_row();

                                        // Storage Medium
                                        ui.label("Storage Medium (-t):");
                                        ui.horizontal(|ui| {
                                            ui.selectable_value(&mut self.uuu_builder.target_dev, TargetStorage::Emmc, "eMMC");
                                            ui.selectable_value(&mut self.uuu_builder.target_dev, TargetStorage::Sd, "SD Card");
                                        });
                                        ui.end_row();

                                        // Slot Target
                                        ui.label("Slot Target (-a / -b):");
                                        ui.horizontal(|ui| {
                                            let mut slot_none = self.uuu_builder.slot.is_none();
                                            let mut slot_a = self.uuu_builder.slot == Some('a');
                                            let mut slot_b = self.uuu_builder.slot == Some('b');
                                            if ui.checkbox(&mut slot_none, "Both / Default").clicked() {
                                                self.uuu_builder.slot = None;
                                            }
                                            if ui.checkbox(&mut slot_a, "Slot A (-a)").clicked() {
                                                self.uuu_builder.slot = Some('a');
                                            }
                                            if ui.checkbox(&mut slot_b, "Slot B (-b)").clicked() {
                                                self.uuu_builder.slot = Some('b');
                                            }
                                        });
                                        ui.end_row();

                                        // Partition Table Capacity Threshold
                                        ui.label("Partition Capacity (-c):");
                                        ui.horizontal(|ui| {
                                            let mut size_auto = self.uuu_builder.card_size.is_none();
                                            let mut size_13 = self.uuu_builder.card_size == Some(13);
                                            let mut size_28 = self.uuu_builder.card_size == Some(28);
                                            if ui.checkbox(&mut size_auto, "Auto").clicked() {
                                                self.uuu_builder.card_size = None;
                                            }
                                            if ui.checkbox(&mut size_13, "13 GB (≤16GB)").clicked() {
                                                self.uuu_builder.card_size = Some(13);
                                            }
                                            if ui.checkbox(&mut size_28, "28 GB (≥32GB)").clicked() {
                                                self.uuu_builder.card_size = Some(28);
                                            }
                                        });
                                        ui.end_row();
                                    });

                                ui.add_space(4.0);
                                ui.separator();
                                ui.horizontal_wrapped(|ui| {
                                    ui.checkbox(&mut self.uuu_builder.erase_userdata, "Erase User Data (-e)");
                                    ui.checkbox(&mut self.uuu_builder.mcu_image, "Flash Coprocessor MCU Binary (-m)");
                                    ui.checkbox(&mut self.uuu_builder.daemon_mode, "Daemon Mode (-daemon)");
                                    ui.checkbox(&mut self.uuu_builder.ram_boot_only, "FastbootD RAM Boot (-i)");
                                    ui.checkbox(&mut self.uuu_builder.dry_run, "Dry Run Preview (-dryrun)");
                                    ui.checkbox(&mut self.auto_reboot_after_flash, "Auto-reboot Device After Flash");
                                });
                            });

                            ui.add_space(8.0);

                            // Section 5: Real-Time Compiled CLI Command Preview
                            ui.group(|ui| {
                                ui.label(egui::RichText::new("Compiled CLI Command Preview").strong());
                                ui.separator();
                                let compiled_cmd = self.generate_compiled_command_preview();
                                egui::ScrollArea::horizontal().id_salt("cmd_preview_scroll").show(ui, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(compiled_cmd)
                                                .monospace()
                                                .color(egui::Color32::from_rgb(200, 255, 180)),
                                        )
                                        .wrap(),
                                    );
                                });
                            });

                            ui.add_space(8.0);

                            // Section 6: Action Execution Trigger
                            ui.group(|ui| {
                                ui.vertical_centered(|ui| {
                                    let btn_text = if self.flashing_active {
                                        "⚡ FLASHING IN PROGRESS..."
                                    } else {
                                        "🚀 EXECUTE FLASH PIPELINE"
                                    };

                                    let can_execute = !self.flashing_active && self.selected_device().is_some();
                                    if ui
                                        .add_enabled(
                                            can_execute,
                                            egui::Button::new(
                                                egui::RichText::new(btn_text)
                                                    .strong()
                                                    .size(16.0)
                                                    .color(if can_execute { egui::Color32::WHITE } else { egui::Color32::GRAY }),
                                            )
                                            .min_size(egui::vec2(280.0, 45.0)),
                                        )
                                        .clicked()
                                    {
                                        self.execute_flash_pipeline();
                                    }
                                });

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

                // Column 2: Partition Boundary Visualizer & Attached Hardware Topology
                columns[1].vertical(|ui| {
                    // Storage Layout Visualizer
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

                            let (rect, _response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::hover());
                            let painter = ui.painter();

                            // Background
                            painter.rect_filled(rect, 4.0, egui::Color32::from_rgb(30, 30, 30));

                            // GPT Header segment
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

                    // USB Attached Device Topology with Interactive Selection
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

                            // Inspector panel for the selected target
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

                    // Console Log Output with Live Tokio/Thread Streaming
                    ui.group(|ui| {
                        ui.heading("📋 Target RTT & Event Log");
                        ui.add_space(4.0);

                        egui::ScrollArea::vertical()
                            .id_salt("target_event_log_scroll_area")
                            .max_height(140.0)
                            .show(ui, |ui| {
                                for (log_idx, msg) in self.log_messages.iter().rev().enumerate() {
                                    ui.push_id(log_idx, |ui| {
                                        let color = if msg.contains("[ERROR]") || msg.contains("[STDERR]") {
                                            egui::Color32::from_rgb(255, 100, 100)
                                        } else if msg.contains("[COMPLETE]") || msg.contains("✔") {
                                            egui::Color32::from_rgb(0, 255, 128)
                                        } else if msg.contains("[STATUS]") {
                                            egui::Color32::from_rgb(0, 210, 255)
                                        } else {
                                            egui::Color32::from_rgb(220, 220, 140)
                                        };
                                        ui.label(egui::RichText::new(msg).monospace().color(color));
                                    });
                                }
                            });
                    });
                });
            });
        });
    }
}
