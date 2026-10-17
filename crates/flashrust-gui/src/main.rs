use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};
use toolkit_core::{
    BoardPreset, BootKitchen, DeviceOperatingMode, FrpLockState, FrpPartitionInspector,
    FrpPartitionReport, HeimdallEngine, KgLockState, OdinProtocolEngine, PRESETS, PatchSummary,
    PitTable, SamsungDetectedSubMode, SamsungModeProbeReport, SamsungOdinConfig, StorageLayoutPlan,
    SuBuildRequirements, SuDetector, TargetStorage, UsbDeviceInfo, UuuCommandBuilder, ZigEngine,
    create_storage_layout_plan, detect_preset_from_usb, list_attached_devices,
};

type BootPatchJobResult = std::result::Result<(PathBuf, PatchSummary), String>;

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
    let temporary_path = parent.join(format!(
        ".{}.flashrust-{}.tmp",
        filename.to_string_lossy(),
        std::process::id()
    ));
    let mut temporary = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary_path)?;
    let result = (|| {
        temporary.write_all(bytes)?;
        temporary.sync_all()?;
        drop(temporary);
        std::fs::rename(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1650.0, 1050.0])
            .with_min_inner_size([1400.0, 900.0])
            .with_resizable(true)
            .with_title("Project flashrust | Samsung Firmware Inspector & Offline Boot Patcher"),
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
    SamsungOdinLoke,
    FastbootPartition,
    NxpBootloaderSpl,
    NxpFitImage,
    RawStorageOffset,
    Rp2350Qspi,
}

impl FlashTargetType {
    pub const ALL: [FlashTargetType; 6] = [
        FlashTargetType::SamsungOdinLoke,
        FlashTargetType::FastbootPartition,
        FlashTargetType::NxpBootloaderSpl,
        FlashTargetType::NxpFitImage,
        FlashTargetType::RawStorageOffset,
        FlashTargetType::Rp2350Qspi,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            FlashTargetType::SamsungOdinLoke => {
                "Samsung Odin / Loke Download Mode (BL/AP/CP/CSC + FRP)"
            }
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
    KernelSuGki,  // Automated in-memory GKI /init takeover
    StandaloneSu, // Injects setuid root su binary to system/bin/su or bin/su
    MagiskApplet, // Magiskinit overlayfs ramdisk entrypoint
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
    pub adb_preauth: bool,
}

impl Default for BootPatchSettings {
    fn default() -> Self {
        Self {
            auto_su_inject: false,
            su_inject_type: SuInjectType::KernelSuGki,
            su_target_path: "system/bin/su".to_string(),
            su_custom_binary: None,
            setuid_root: true,
            permissive_selinux: false,
            resign_avb: false,
            custom_kernel_img: None,
            adb_preauth: false,
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

    // Samsung Odin / Loke & FRP Studio State
    samsung_config: SamsungOdinConfig,
    pit_table: Option<PitTable>,
    frp_report: Option<FrpPartitionReport>,
    samsung_mode_report: Option<SamsungModeProbeReport>,
    samsung_flash_confirmed: bool,
    samsung_custom_payload: bool,

    // NXP UUU Command Builder & Overrides
    uuu_builder: UuuCommandBuilder,

    // In-Memory Boot Kitchen Patches
    patch_settings: BootPatchSettings,
    boot_image_path: Option<PathBuf>,
    adb_public_key_path: Option<PathBuf>,
    custom_image_confirmed: bool,
    boot_patch_active: bool,
    boot_patch_status: Option<String>,
    boot_patch_rx: Option<Receiver<BootPatchJobResult>>,

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
            .or({
                if initial_devices.is_empty() {
                    None
                } else {
                    Some(0)
                }
            });

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
                "[ODIN] Samsung Loke Download Mode (04E8:685D) & PIT/FRP Inspector Ready".into(),
                "[USB] Pure-Rust nusb hotplug daemon active - targets auto-configure on insertion"
                    .into(),
            ],
            flash_target_type: FlashTargetType::SamsungOdinLoke,
            flash_partition_name: "boot".to_string(),
            flash_target_slot: TargetSlot::Active,
            custom_flash_offset: "0x8400".to_string(),
            auto_reboot_after_flash: true,
            samsung_config: SamsungOdinConfig::default(),
            pit_table: None,
            frp_report: None,
            samsung_mode_report: None,
            samsung_flash_confirmed: false,
            samsung_custom_payload: false,
            uuu_builder,
            patch_settings: BootPatchSettings::default(),
            boot_image_path: None,
            adb_public_key_path: BootKitchen::default_adb_public_key_path()
                .filter(|path| path.is_file()),
            custom_image_confirmed: false,
            boot_patch_active: false,
            boot_patch_status: None,
            boot_patch_rx: None,
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
                    let _ = tx.send(FlashLogEvent::Stderr(format!(
                        "[SU-BUILD-ERROR] Failed: {}",
                        e
                    )));
                    let _ =
                        build_tx.send((Err(e.to_string()), reqs.target_arch.label().to_string()));
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
                    self.uuu_builder.uboot_feature =
                        Some(detected_preset.uboot_feature.to_string());
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
                DeviceOperatingMode::SamsungLokeDownload => {
                    self.flash_target_type = FlashTargetType::SamsungOdinLoke;
                }
                DeviceOperatingMode::Fastboot | DeviceOperatingMode::AndroidAdb => {
                    if dev.vendor_id == 0x04E8 {
                        self.flash_target_type = FlashTargetType::SamsungOdinLoke;
                    } else {
                        self.flash_target_type = FlashTargetType::FastbootPartition;
                    }
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
        self.selected_device_idx
            .and_then(|idx| self.devices.get(idx))
    }

    fn compute_layout(&self) -> Option<StorageLayoutPlan> {
        let preset = self.current_preset();
        let bytes = self.uuu_builder.card_size.unwrap_or(32) as u64 * 1024 * 1024 * 1024;
        let emmc = self.uuu_builder.target_dev == TargetStorage::Emmc;
        create_storage_layout_plan(preset.soc, emmc, self.uuu_builder.mcu_image, bytes).ok()
    }

    fn generate_compiled_command_preview(&self) -> String {
        match self.flash_target_type {
            FlashTargetType::SamsungOdinLoke => {
                let preflight = self
                    .samsung_config
                    .evaluate_preflight(self.samsung_custom_payload);
                let header_comment = format!(
                    "# [{} | {}]\n# [{}]\n",
                    self.samsung_config.frp_lock_state.label(),
                    self.samsung_config.kg_lock_state.label(),
                    preflight.status_headline
                );
                let mut command = self
                    .samsung_config
                    .to_command_string(self.auto_reboot_after_flash);
                if self.samsung_custom_payload {
                    command.push_str(" --custom-binary");
                }
                format!("{header_comment}{command}")
            }
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
                        SuInjectType::KernelSuGki => {
                            "# [Zig Engine: Auto SU Injection -> KernelSU /init GKI Hijack]\n"
                        }
                        SuInjectType::StandaloneSu => {
                            "# [Zig Engine: Auto SU Injection -> Standalone SetUID /bin/su (04755 root:root)]\n"
                        }
                        SuInjectType::MagiskApplet => {
                            "# [Zig Engine: Auto SU Injection -> Magiskinit Boot Applet]\n"
                        }
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

    fn trigger_adb_patch_export(&mut self, output_path: PathBuf) {
        if self.boot_patch_active {
            return;
        }
        let Some(input_path) = self.boot_image_path.clone() else {
            self.boot_patch_status = Some("Select a boot or init_boot image first".into());
            return;
        };
        let Some(key_path) = self.adb_public_key_path.clone() else {
            self.boot_patch_status = Some("Select an Android adbkey.pub file first".into());
            return;
        };
        if !self.custom_image_confirmed {
            self.boot_patch_status =
                Some("Confirm that this device accepts custom boot images before exporting".into());
            return;
        }
        if self.flash_target_type == FlashTargetType::SamsungOdinLoke
            && !self
                .samsung_config
                .evaluate_preflight(true)
                .current_payload_allowed
        {
            self.boot_patch_status = Some(
                "Samsung preflight blocks custom images until FRP is off, OEM unlock is enabled, and KG is completed"
                    .into(),
            );
            return;
        }
        let same_path = input_path == output_path
            || match (
                std::fs::canonicalize(&input_path),
                std::fs::canonicalize(&output_path),
            ) {
                (Ok(input), Ok(output)) => input == output,
                _ => false,
            };
        if same_path {
            self.boot_patch_status = Some("Choose an output path different from the input".into());
            return;
        }

        self.boot_patch_active = true;
        self.boot_patch_status = Some("Patching and validating boot image…".into());
        let (result_tx, result_rx) = channel();
        self.boot_patch_rx = Some(result_rx);
        std::thread::spawn(move || {
            let result = (|| -> BootPatchJobResult {
                let boot = std::fs::read(&input_path)
                    .map_err(|error| format!("Could not read {}: {error}", input_path.display()))?;
                let key = std::fs::read(&key_path)
                    .map_err(|error| format!("Could not read {}: {error}", key_path.display()))?;
                let (patched, summary) = BootKitchen::patch_boot_image_adb_preauth(&boot, &key)
                    .map_err(|error| error.to_string())?;
                write_atomically(&output_path, &patched).map_err(|error| {
                    format!("Could not write {}: {error}", output_path.display())
                })?;
                Ok((output_path, summary))
            })();
            let _ = result_tx.send(result);
        });
    }

    fn execute_flash_pipeline(&mut self) {
        if self.flashing_active {
            return;
        }

        let target_type = self.flash_target_type;
        let selected_target = self.selected_device().cloned();
        if target_type != FlashTargetType::SamsungOdinLoke && selected_target.is_none() {
            self.log_messages
                .push("[ERROR] No target USB device selected for flashing".into());
            return;
        }
        if target_type == FlashTargetType::SamsungOdinLoke && !self.samsung_flash_confirmed {
            self.log_messages.push(
                "[ERROR] Confirm the firmware model and data-loss acknowledgement before flashing"
                    .into(),
            );
            return;
        }

        self.flashing_active = true;
        self.flash_progress = 0.0;

        let tx = self.log_tx.clone();
        let samsung = self.samsung_config.clone();
        let samsung_custom_payload = self.samsung_custom_payload;
        let reboot = self.auto_reboot_after_flash;
        let non_samsung_cmd = self.generate_compiled_command_preview();

        std::thread::spawn(move || {
            let _ = tx.send(FlashLogEvent::StatusUpdate(
                "Initializing automated flash execution pipeline...".into(),
            ));
            let _ = tx.send(FlashLogEvent::Progress(0.05));

            // Special branch for Samsung Odin / Loke Download Mode protocol
            if target_type == FlashTargetType::SamsungOdinLoke {
                let preflight = samsung.evaluate_preflight(samsung_custom_payload);
                let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                    "[ODIN-PREFLIGHT] {}",
                    preflight.status_headline
                )));

                if !preflight.current_payload_allowed {
                    let _ = tx.send(FlashLogEvent::Stderr(
                        "[BOOTLOADER-REJECT] Custom Binary (BOOT/VBMETA) Blocked by FRP / KG Lock! Disable 'Auto SU Binary Injection' to flash stock signed TARs, or enable OEM Unlock.".into(),
                    ));
                    let _ = tx.send(FlashLogEvent::Completed(false));
                    return;
                }

                let result = HeimdallEngine::flash(&samsung, reboot, |line| {
                    let _ = tx.send(FlashLogEvent::Stdout(format!("[HEIMDALL] {line}")));
                    if let Some(percent) = line
                        .trim()
                        .strip_suffix('%')
                        .and_then(|value| value.parse::<f32>().ok())
                    {
                        let _ = tx.send(FlashLogEvent::Progress(percent / 100.0));
                    }
                });
                match result {
                    Ok(result) => {
                        let _ = tx.send(FlashLogEvent::Progress(1.0));
                        let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                            "Real Samsung flash completed for {} partition(s): {}",
                            result.partition_count,
                            result.partitions.join(", ")
                        )));
                        let _ = tx.send(FlashLogEvent::Completed(true));
                    }
                    Err(error) => {
                        let _ = tx.send(FlashLogEvent::Stderr(format!("[HEIMDALL-ERROR] {error}")));
                        let _ = tx.send(FlashLogEvent::Completed(false));
                    }
                }
                return;
            }

            // Non-Samsung targets: execute the compiled CLI command via subprocess
            // so every flash target type actually works from the GUI.
            let compiled = non_samsung_cmd;
            let _ = tx.send(FlashLogEvent::StatusUpdate(format!(
                "[EXECUTE] Running compiled command: {}",
                compiled
            )));

            let comment_lines: Vec<&str> = compiled
                .lines()
                .filter(|l| l.trim_start().starts_with('#'))
                .collect();
            let body_lines: Vec<&str> = compiled
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .filter(|l| !l.trim().is_empty())
                .collect();

            let body = body_lines.join(" ");
            let mut body_parts = body.split_whitespace();
            let program = match body_parts.next() {
                Some(p) => p.to_string(),
                None => {
                    let _ = tx.send(FlashLogEvent::Stderr(
                        "[EXECUTE-ERROR] Empty command — nothing to run.".into(),
                    ));
                    let _ = tx.send(FlashLogEvent::Completed(false));
                    return;
                }
            };
            let args: Vec<&str> = body_parts.collect();

            for comment in &comment_lines {
                let _ = tx.send(FlashLogEvent::Stdout(format!("# {}", comment)));
            }

            let mut child = match std::process::Command::new(&program)
                .args(&args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(FlashLogEvent::Stderr(format!(
                        "[EXECUTE-ERROR] Failed to spawn {}: {}",
                        program, e
                    )));
                    let _ = tx.send(FlashLogEvent::Completed(false));
                    return;
                }
            };

            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let tx_out = tx.clone();
            let tx_err = tx.clone();

            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
                    let _ = tx_out.send(FlashLogEvent::Stdout(line));
                }
            });
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::BufReader::new(stderr).lines().map_while(Result::ok) {
                    let _ = tx_err.send(FlashLogEvent::Stderr(line));
                }
            });

            let status = match child.wait() {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(FlashLogEvent::Stderr(format!(
                        "[EXECUTE-ERROR] Command wait failed: {}",
                        e
                    )));
                    let _ = tx.send(FlashLogEvent::Completed(false));
                    return;
                }
            };

            let _ = tx.send(FlashLogEvent::Progress(1.0));
            if status.success() {
                let _ = tx.send(FlashLogEvent::StatusUpdate(
                    "Non-Samsung flash pipeline completed successfully.".into(),
                ));
                let _ = tx.send(FlashLogEvent::Completed(true));
            } else {
                let _ = tx.send(FlashLogEvent::Stderr(format!(
                    "[EXECUTE-ERROR] Command exited with status {}",
                    status
                )));
                let _ = tx.send(FlashLogEvent::Completed(false));
            }
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

        let boot_patch_result = self
            .boot_patch_rx
            .as_ref()
            .and_then(|rx| rx.try_recv().ok());
        if let Some(result) = boot_patch_result {
            self.boot_patch_active = false;
            match result {
                Ok((path, summary)) => {
                    let message = format!(
                        "Exported {} ({} → {} bytes, {}, preserved {} trailing bytes)",
                        path.display(),
                        summary.original_ramdisk_size,
                        summary.patched_ramdisk_size,
                        summary.ramdisk_compression.label(),
                        summary.preserved_suffix_bytes
                    );
                    self.boot_patch_status = Some(format!("✅ {message}"));
                    self.log_messages.push(format!("[ADB-PREAUTH] {message}"));
                }
                Err(error) => {
                    self.boot_patch_status = Some(format!("❌ {error}"));
                    self.log_messages
                        .push(format!("[ADB-PREAUTH-ERROR] {error}"));
                }
            }
            self.boot_patch_rx = None;
        }

        // Poll asynchronous SU binary builder results
        let su_build_result = self.su_build_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some((res, arch_label)) = su_build_result {
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

        // Auto-refresh devices every 3 seconds
        if self.last_device_scan.elapsed() > Duration::from_secs(3) {
            let updated = list_attached_devices();
            if let Some(current) = self.selected_device() {
                let vid = current.vendor_id;
                let pid = current.product_id;
                self.selected_device_idx = updated
                    .iter()
                    .position(|d| d.vendor_id == vid && d.product_id == pid);
            } else if !updated.is_empty() && self.selected_device_idx.is_none() {
                self.select_device(0);
            }
            self.devices = updated;
            self.last_device_scan = Instant::now();
        }

        if self.flashing_active || self.su_is_building || self.boot_patch_active {
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
                            egui::RichText::new("○ DISCONNECTED").color(egui::Color32::LIGHT_GRAY),
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
                            // Target Protocol Mode Selector
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.heading("⚡ Flash Protocol Engine");
                                    egui::ComboBox::from_id_salt("flash_target_type_combo")
                                        .selected_text(self.flash_target_type.label())
                                        .show_ui(ui, |ui| {
                                            for t in FlashTargetType::ALL {
                                                ui.selectable_value(&mut self.flash_target_type, t, t.label());
                                            }
                                        });
                                });
                            });

                            ui.add_space(6.0);

                            // Samsung Odin / Loke & FRP Lock Preflight Studio
                            ui.group(|ui| {
                                let preflight = self
                                    .samsung_config
                                    .evaluate_preflight(self.samsung_custom_payload);

                                ui.horizontal(|ui| {
                                    ui.heading("📱 Samsung Odin / Loke & FRP Studio");
                                    let badge_color = if preflight.current_payload_allowed {
                                        egui::Color32::from_rgb(0, 255, 140)
                                    } else {
                                        egui::Color32::from_rgb(255, 90, 90)
                                    };
                                    ui.colored_label(
                                        badge_color,
                                        if preflight.current_payload_allowed {
                                            "● FRP PREFLIGHT PASS"
                                        } else {
                                            "● BLOCKED BY FRP / KG LOCK"
                                        },
                                    );
                                });
                                ui.separator();

                                // Bootloader Lock Status Bar (FRP LOCK / KG STATE / OEM UNLOCK)
                                egui::Grid::new("samsung_lock_grid")
                                    .num_columns(4)
                                    .spacing([20.0, 8.0])
                                    .striped(false)
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("Download Mode State:").strong(),
                                        );
                                        ui.end_row();

                                        ui.label("FRP Lock:");
                                        if ui
                                            .selectable_label(
                                                self.samsung_config.frp_lock_state
                                                    == FrpLockState::On,
                                                "🔒 ON",
                                            )
                                            .clicked()
                                        {
                                            self.samsung_config.frp_lock_state =
                                                FrpLockState::On;
                                        }
                                        if ui
                                            .selectable_label(
                                                self.samsung_config.frp_lock_state
                                                    == FrpLockState::Off,
                                                "🔓 OFF",
                                            )
                                            .clicked()
                                        {
                                            self.samsung_config.frp_lock_state =
                                                FrpLockState::Off;
                                        }
                                        ui.checkbox(
                                            &mut self.samsung_config.oem_unlock_enabled,
                                            "OEM UNLOCK: ENABLED",
                                        );
                                        ui.end_row();

                                        ui.label("KG State:");
                                        egui::ComboBox::from_id_salt("kg_state_combo")
                                            .selected_text(self.samsung_config.kg_lock_state.label())
                                            .show_ui(ui, |ui| {
                                                for kg in KgLockState::ALL {
                                                    ui.selectable_value(
                                                        &mut self.samsung_config.kg_lock_state,
                                                        kg,
                                                        kg.label(),
                                                    );
                                                }
                                            });
                                        ui.end_row();
                                    });

                                // Live Preflight Diagnostic Box
                                ui.add_space(4.0);
                                let frame_bg = if preflight.current_payload_allowed {
                                    egui::Color32::from_rgb(14, 34, 24)
                                } else {
                                    egui::Color32::from_rgb(42, 16, 18)
                                };
                                egui::Frame::NONE
                                    .fill(frame_bg)
                                    .corner_radius(4.0)
                                    .inner_margin(8.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new(&preflight.status_headline)
                                                .strong()
                                                .color(if preflight.current_payload_allowed {
                                                    egui::Color32::from_rgb(120, 255, 170)
                                                } else {
                                                    egui::Color32::from_rgb(255, 130, 130)
                                                }),
                                        );
                                        for finding in &preflight.findings {
                                            ui.label(format!("• {}", finding));
                                        }
                                        for action in &preflight.recommended_actions {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(255, 215, 100),
                                                format!("👉 {}", action),
                                            );
                                        }
                                    });

                                let heimdall_path = HeimdallEngine::find_executable();
                                ui.horizontal_wrapped(|ui| {
                                    ui.label("Real USB engine:");
                                    match heimdall_path {
                                        Some(path) => {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(120, 255, 170),
                                                format!("Heimdall ready ({})", path.display()),
                                            );
                                        }
                                        None => {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(255, 130, 130),
                                                "Heimdall missing; flashing is disabled",
                                            );
                                        }
                                    }
                                });
                                ui.checkbox(
                                    &mut self.samsung_flash_confirmed,
                                    "I verified the firmware matches this exact model and understand CSC may erase user data",
                                );
                                ui.checkbox(
                                    &mut self.samsung_custom_payload,
                                    "Selected archives contain custom or modified images",
                                );

                                // Real Download Mode detection and reboot controls
                                ui.add_space(6.0);
                                egui::Grid::new("samsung_usb_control_grid")
                                    .num_columns(3)
                                    .spacing([16.0, 10.0])
                                    .striped(false)
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("Download Mode USB Control:")
                                                .strong()
                                                .color(egui::Color32::from_rgb(255, 200, 90)),
                                        );
                                        ui.end_row();

                                        if ui
                                            .button("🔍 Detect with Heimdall USB")
                                            .clicked()
                                        {
                                            match HeimdallEngine::detect() {
                                                Ok(output) => self.log_messages.push(format!(
                                                    "[HEIMDALL-DETECT] {output}"
                                                )),
                                                Err(error) => self.log_messages.push(format!(
                                                    "[HEIMDALL-DETECT-ERROR] {error}"
                                                )),
                                            }
                                        }
                                        ui.end_row();

                                        if ui
                                            .button(
                                                egui::RichText::new(
                                                    "🔄 Reboot to Real Download Mode",
                                                )
                                                .strong()
                                                .color(egui::Color32::from_rgb(0, 255, 160)),
                                            )
                                            .clicked()
                                        {
                                            let logs = OdinProtocolEngine::reboot_to_download_mode();
                                            for line in logs {
                                                self.log_messages.push(format!(
                                                    "[ODIN-REBOOT] {}",
                                                    line
                                                ));
                                            }
                                            let rep =
                                                OdinProtocolEngine::probe_samsung_download_mode();
                                            self.samsung_mode_report = Some(rep);
                                        }
                                        ui.label(
                                            egui::RichText::new(
                                                "(AT+FUS? / ADB / fastboot reboot download)",
                                            )
                                            .small()
                                            .color(egui::Color32::from_rgb(150, 150, 150)),
                                        );
                                        ui.end_row();

                                        if ui
                                            .button("🔁 Loke Reboot Device (0x67 EndSession)")
                                            .clicked()
                                        {
                                            let logs = OdinProtocolEngine::loke_reboot_device();
                                            for line in logs {
                                                self.log_messages.push(line);
                                            }
                                        }
                                        ui.end_row();
                                    });

                                if let Some(ref mode_rep) = self.samsung_mode_report {
                                    let mode_color = match mode_rep.detected_submode {
                                        SamsungDetectedSubMode::RealLokeDownload => {
                                            egui::Color32::from_rgb(0, 255, 150)
                                        }
                                        SamsungDetectedSubMode::FakeOrAtModemMode => {
                                            egui::Color32::from_rgb(255, 185, 60)
                                        }
                                        SamsungDetectedSubMode::UnresponsiveOrBusy => {
                                            egui::Color32::from_rgb(255, 130, 110)
                                        }
                                        SamsungDetectedSubMode::NoSerialPortFound => {
                                            egui::Color32::LIGHT_GRAY
                                        }
                                    };
                                    egui::Frame::NONE
                                        .fill(egui::Color32::from_rgb(22, 26, 36))
                                        .corner_radius(4.0)
                                        .inner_margin(6.0)
                                        .show(ui, |ui| {
                                            ui.colored_label(
                                                mode_color,
                                                format!(
                                                    "📡 Mode Probe: {} (Port: {})",
                                                    mode_rep.detected_submode.label(),
                                                    mode_rep
                                                        .serial_port
                                                        .as_deref()
                                                        .unwrap_or("No /dev/cu.usbmodem* found")
                                                ),
                                            );
                                            if let Some(ref t) = mode_rep.parsed_telemetry {
                                                egui::Frame::NONE
                                                    .fill(egui::Color32::from_rgb(16, 22, 30))
                                                    .corner_radius(4.0)
                                                    .inner_margin(6.0)
                                                    .show(ui, |ui| {
                                                        ui.horizontal(|ui| {
                                                            ui.label(egui::RichText::new("📱 Model:").strong());
                                                            ui.colored_label(egui::Color32::from_rgb(0, 240, 255), &t.model);
                                                            ui.separator();
                                                            ui.label(egui::RichText::new("⚡ Bootloader Bit:").strong());
                                                            ui.colored_label(egui::Color32::from_rgb(255, 215, 0), format!("Bit {}", t.sw_rev_bit));
                                                            ui.separator();
                                                            ui.label(egui::RichText::new("🌐 Carrier:").strong());
                                                            ui.label(&t.carrier_prd);
                                                        });
                                                        ui.horizontal(|ui| {
                                                            ui.label(egui::RichText::new("🏷️ Firmware:").strong());
                                                            ui.small(&t.firmware_version);
                                                            ui.separator();
                                                            ui.label(egui::RichText::new("🔌 USB State:").strong());
                                                            ui.colored_label(
                                                                if t.usb_composition.contains("ADB") {
                                                                    egui::Color32::from_rgb(0, 255, 128)
                                                                } else {
                                                                    egui::Color32::from_rgb(255, 170, 50)
                                                                },
                                                                &t.usb_composition,
                                                            );
                                                            ui.separator();
                                                            ui.label(egui::RichText::new("🔒 Lock:").strong());
                                                            ui.label(&t.lock_status);
                                                        });
                                                        ui.small(format!("Serial: {} | IMEI: {}", t.serial_number, t.imei));
                                                    });
                                            } else if let Some(ref info) = mode_rep.devconinfo {
                                                ui.small(format!("AT+DEVCONINFO: {}", info));
                                            }
                                            if !mode_rep.raw_response.is_empty() {
                                                ui.small(format!(
                                                    "Raw Serial Reply: {}",
                                                    mode_rep.raw_response
                                                ));
                                            }
                                            ui.small(format!("• {}", mode_rep.summary));
                                        });
                                }

                                ui.add_space(6.0);
                                ui.label(
                                    egui::RichText::new("Odin 4-Slot Firmware Packages (.tar / .tar.md5) & PIT:")
                                        .strong(),
                                );

                                egui::Grid::new("samsung_odin_slots_grid")
                                    .num_columns(3)
                                    .spacing([10.0, 6.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        // BL Slot
                                        ui.label("BL (Bootloader):");
                                        let bl_str = self
                                            .samsung_config
                                            .bl_tar
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "BL_*.tar.md5 (sboot.bin / param.bin)".into());
                                        ui.add_enabled(
                                            false,
                                            egui::TextEdit::singleline(&mut bl_str.clone()).desired_width(180.0),
                                        );
                                        if ui.button("📂 Select BL").clicked()
                                            && let Some(f) = rfd::FileDialog::new()
                                                .add_filter("Odin TAR (*.tar, *.md5)", &["tar", "md5"])
                                                .pick_file()
                                        {
                                                if let Ok(m) = OdinProtocolEngine::inspect_tar_file(&f, self.pit_table.as_ref()) {
                                                    self.log_messages.push(format!(
                                                        "[ODIN-BL] Loaded {} ({} files, {} bytes, MD5 trailer: {})",
                                                        m.archive_path, m.entries.len(), m.total_payload_bytes, m.has_md5_trailer
                                                    ));
                                                }
                                                self.samsung_config.bl_tar = Some(f);
                                                self.flash_target_type = FlashTargetType::SamsungOdinLoke;
                                        }
                                        ui.end_row();

                                        // AP Slot
                                        ui.label("AP (System / Boot):");
                                        let ap_str = self
                                            .samsung_config
                                            .ap_tar
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "AP_*.tar.md5 (boot / super / vbmeta)".into());
                                        ui.add_enabled(
                                            false,
                                            egui::TextEdit::singleline(&mut ap_str.clone()).desired_width(180.0),
                                        );
                                        if ui.button("📂 Select AP").clicked()
                                            && let Some(f) = rfd::FileDialog::new()
                                                .add_filter("Odin TAR (*.tar, *.md5)", &["tar", "md5"])
                                                .pick_file()
                                        {
                                                if let Ok(m) = OdinProtocolEngine::inspect_tar_file(&f, self.pit_table.as_ref()) {
                                                    self.log_messages.push(format!(
                                                        "[ODIN-AP] Loaded {} ({} files, {} bytes, MD5 trailer: {})",
                                                        m.archive_path, m.entries.len(), m.total_payload_bytes, m.has_md5_trailer
                                                    ));
                                                }
                                                self.samsung_config.ap_tar = Some(f);
                                                self.flash_target_type = FlashTargetType::SamsungOdinLoke;
                                        }
                                        ui.end_row();

                                        // CP Slot
                                        ui.label("CP (Modem / Radio):");
                                        let cp_str = self
                                            .samsung_config
                                            .cp_tar
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "CP_*.tar.md5 (modem.bin)".into());
                                        ui.add_enabled(
                                            false,
                                            egui::TextEdit::singleline(&mut cp_str.clone()).desired_width(180.0),
                                        );
                                        if ui.button("📂 Select CP").clicked()
                                            && let Some(f) = rfd::FileDialog::new()
                                                .add_filter("Odin TAR (*.tar, *.md5)", &["tar", "md5"])
                                                .pick_file()
                                        {
                                                self.samsung_config.cp_tar = Some(f);
                                                self.flash_target_type = FlashTargetType::SamsungOdinLoke;
                                        }
                                        ui.end_row();

                                        // CSC Slot
                                        ui.label("CSC / HOME_CSC:");
                                        let csc_str = self
                                            .samsung_config
                                            .csc_tar
                                            .as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "CSC_*.tar.md5 (optics / prism / pit)".into());
                                        ui.add_enabled(
                                            false,
                                            egui::TextEdit::singleline(&mut csc_str.clone()).desired_width(180.0),
                                        );
                                        if ui.button("📂 Select CSC").clicked()
                                            && let Some(f) = rfd::FileDialog::new()
                                                .add_filter("Odin TAR (*.tar, *.md5)", &["tar", "md5"])
                                                .pick_file()
                                        {
                                                self.samsung_config.csc_tar = Some(f);
                                                self.flash_target_type = FlashTargetType::SamsungOdinLoke;
                                        }
                                        ui.end_row();
                                    });

                                ui.horizontal(|ui| {
                                    ui.label("Device PIT mapping:");
                                    ui.label(
                                        self.samsung_config
                                            .pit_file
                                            .as_ref()
                                            .map(|path| path.display().to_string())
                                            .unwrap_or_else(|| {
                                                "None (matching CSC/HOME_CSC must contain PIT)".into()
                                            }),
                                    );
                                    if ui.button("📂 Select device .pit").clicked()
                                        && let Some(path) = rfd::FileDialog::new()
                                            .add_filter("Samsung PIT", &["pit"])
                                            .pick_file()
                                    {
                                        match std::fs::read(&path)
                                            .map_err(|error| error.to_string())
                                            .and_then(|bytes| {
                                                PitTable::parse_bytes(&bytes)
                                                    .map_err(|error| error.to_string())
                                            })
                                        {
                                            Ok(table) => {
                                                self.log_messages.push(format!(
                                                    "[ODIN-PIT] Loaded {} / {} with {} entries",
                                                    table.project_name,
                                                    table.gang_name,
                                                    table.entries.len()
                                                ));
                                                self.samsung_config.pit_file = Some(path);
                                                self.pit_table = Some(table);
                                            }
                                            Err(error) => self.log_messages.push(format!(
                                                "[ODIN-PIT-ERROR] {error}"
                                            )),
                                        }
                                    }
                                });

                                ui.add_space(6.0);
                                ui.separator();
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        egui::RichText::new("Authorized FRP / Persistent Partition Inspector (Zig):")
                                            .strong()
                                            .color(egui::Color32::from_rgb(0, 220, 255)),
                                    );
                                    if ui.button("🔍 Inspect frp.img / persistent.img").clicked()
                                        && let Some(file) = rfd::FileDialog::new()
                                            .add_filter("Partition Images (*.img, *.bin)", &["img", "bin"])
                                            .pick_file()
                                        && let Ok(bytes) = std::fs::read(&file)
                                    {
                                                match FrpPartitionInspector::inspect_bytes(&bytes) {
                                                    Ok(rep) => {
                                                        self.log_messages.push(format!(
                                                            "[FRP-INSPECT] {}: Marker 0x{:08X} (valid={}), OEM Unlock={}, SHA-256 Match={}",
                                                            file.display(),
                                                            rep.header_marker,
                                                            rep.marker_valid,
                                                            rep.oem_unlock_enabled,
                                                            rep.digest_matches
                                                        ));
                                                        self.frp_report = Some(rep);
                                                    }
                                                    Err(e) => {
                                                        self.log_messages.push(format!(
                                                            "[ERROR] Failed to inspect FRP partition: {}",
                                                            e
                                                        ));
                                                    }
                                                }
                                    }

                                    ui.small(
                                        "FRP images are inspected read-only. OEM unlock state must be changed on the device through its supported settings flow.",
                                    );
                                });

                                if let Some(ref rep) = self.frp_report {
                                    ui.small(format!(
                                        "✔ Inspected FRP Block ({} bytes) | Marker: 0x{:08X} | Enrolled Credentials: {} | OEM Unlock Byte: {} | SHA-256 Digest Verified: {}",
                                        rep.partition_size_bytes,
                                        rep.header_marker,
                                        rep.has_enrolled_credentials,
                                        rep.oem_unlock_enabled,
                                        rep.digest_matches
                                    ));
                                }
                            });

                            ui.add_space(8.0);

                            if self.flash_target_type != FlashTargetType::SamsungOdinLoke {
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
                                        if ui.button("📂 Browse Folder").clicked()
                                            && let Some(folder) = rfd::FileDialog::new().pick_folder()
                                        {
                                                self.uuu_builder.image_dir = Some(folder);
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
                                        if ui.button("📂 Select File").clicked()
                                            && let Some(file) = rfd::FileDialog::new()
                                                .add_filter("Boot Images (*.img, *.bin)", &["img", "bin"])
                                                .pick_file()
                                        {
                                                self.patch_settings.custom_kernel_img = Some(file.clone());
                                                let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                                                if ["boot", "init_boot", "recovery", "vendor_boot", "system", "super", "vbmeta"].contains(&stem.as_str()) {
                                                    self.flash_partition_name = stem;
                                                }
                                        }
                                        ui.end_row();

                                        // U-Boot Variant (-u)
                                        ui.label("U-Boot Feature (-u):");
                                        let mut uboot_str = self.uuu_builder.uboot_feature.clone().unwrap_or_default();
                                        if ui.add(egui::TextEdit::singleline(&mut uboot_str).desired_width(180.0)).changed() {
                                            self.uuu_builder.uboot_feature = if uboot_str.is_empty() { None } else { Some(uboot_str) };
                                        }
                                        if ui.button("📂 Browse U-Boot").clicked()
                                            && let Some(file) = rfd::FileDialog::new()
                                                .add_filter("U-Boot / SPL (*.bin, *.imx, *.itb)", &["bin", "imx", "itb"])
                                                .pick_file()
                                        {
                                                self.uuu_builder.uboot_feature = Some(file.to_string_lossy().to_string());
                                        }
                                        ui.end_row();

                                        // Device Tree Overlay (-d)
                                        ui.label("DTB Overlay (-d):");
                                        let mut dtb_str = self.uuu_builder.dtb_feature.clone().unwrap_or_default();
                                        if ui.add(egui::TextEdit::singleline(&mut dtb_str).desired_width(180.0)).changed() {
                                            self.uuu_builder.dtb_feature = if dtb_str.is_empty() { None } else { Some(dtb_str) };
                                        }
                                        if ui.button("📂 Browse DTB").clicked()
                                            && let Some(file) = rfd::FileDialog::new()
                                                .add_filter("Device Tree Overlays (*.dtbo, *.dtb)", &["dtbo", "dtb"])
                                                .pick_file()
                                        {
                                                self.uuu_builder.dtb_feature = Some(file.to_string_lossy().to_string());
                                        }
                                        ui.end_row();
                                    });
                                });
                            }

                            ui.add_space(8.0);

                            // Section 3: Implemented offline boot-image patching
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("Offline ADB Boot Image Patcher")
                                            .strong(),
                                    );
                                });
                                ui.separator();

                                // Offline ADB Boot Image Patcher controls
                                // (bound to patch_settings checkboxes above — state persists across frames)
                                ui.checkbox(
                                    &mut self.patch_settings.auto_su_inject,
                                    "Auto SU Injection",
                                );
                                ui.checkbox(
                                    &mut self.patch_settings.permissive_selinux,
                                    "Permissive SELinux",
                                );
                                ui.checkbox(
                                    &mut self.patch_settings.resign_avb,
                                    "Resign AVB (disable verity)",
                                );

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
                                                if ui.button("📂 Select SU Binary").clicked()
                                                    && let Some(file) = rfd::FileDialog::new()
                                                        .add_filter("Executable Binaries", &["bin", "elf", "so", "*"])
                                                        .pick_file()
                                                {
                                                        self.patch_settings.su_custom_binary = Some(file);
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
                                        &mut self.patch_settings.adb_preauth,
                                        "⚡ Export boot image with ADB preauthorization",
                                    );
                                });

                                if self.patch_settings.adb_preauth {
                                    ui.add_space(6.0);
                                    egui::Frame::NONE
                                        .fill(egui::Color32::from_rgb(15, 24, 32))
                                        .inner_margin(8.0)
                                        .corner_radius(4.0)
                                        .show(ui, |ui| {
                                            ui.label(
                                                egui::RichText::new("Offline ADB Boot Image Export")
                                                    .strong(),
                                            );
                                            ui.small(
                                                "The exported image is custom firmware and requires an unlocked bootloader. This action does not flash the phone.",
                                            );

                                            ui.horizontal(|ui| {
                                                ui.label("Boot image:");
                                                ui.label(
                                                    self.boot_image_path
                                                        .as_ref()
                                                        .map(|path| path.display().to_string())
                                                        .unwrap_or_else(|| "Not selected".into()),
                                                );
                                                if ui.button("📂 Select boot.img").clicked()
                                                    && let Some(path) = rfd::FileDialog::new()
                                                        .add_filter(
                                                            "Android Boot Images",
                                                            &["img", "bin"],
                                                        )
                                                        .pick_file()
                                                {
                                                    self.boot_image_path = Some(path);
                                                    self.boot_patch_status = None;
                                                }
                                            });

                                            ui.horizontal(|ui| {
                                                ui.label("ADB public key:");
                                                ui.label(
                                                    self.adb_public_key_path
                                                        .as_ref()
                                                        .map(|path| path.display().to_string())
                                                        .unwrap_or_else(|| "Not selected".into()),
                                                );
                                                if ui.button("📂 Select adbkey.pub").clicked()
                                                    && let Some(path) = rfd::FileDialog::new()
                                                        .add_filter("Android ADB Public Key", &["pub"])
                                                        .pick_file()
                                                {
                                                    self.adb_public_key_path = Some(path);
                                                    self.boot_patch_status = None;
                                                }
                                            });

                                            ui.checkbox(
                                                &mut self.custom_image_confirmed,
                                                "I confirm this device is mine and its bootloader accepts custom images",
                                            );

                                            let preflight_allowed = self.flash_target_type
                                                != FlashTargetType::SamsungOdinLoke
                                                || self
                                                    .samsung_config
                                                    .evaluate_preflight(true)
                                                    .current_payload_allowed;
                                            let export_ready = self.boot_image_path.is_some()
                                                && self.adb_public_key_path.is_some()
                                                && self.custom_image_confirmed
                                                && preflight_allowed
                                                && !self.boot_patch_active;
                                            let export_button = ui.add_enabled(
                                                export_ready,
                                                egui::Button::new(
                                                    "💾 Patch and Export Custom Boot Image",
                                                ),
                                            );
                                            if export_button.clicked() {
                                                let default_name = self
                                                    .boot_image_path
                                                    .as_ref()
                                                    .and_then(|path| path.file_stem())
                                                    .map(|stem| {
                                                        format!(
                                                            "{}-adb.img",
                                                            stem.to_string_lossy()
                                                        )
                                                    })
                                                    .unwrap_or_else(|| "boot-adb.img".into());
                                                if let Some(output) = rfd::FileDialog::new()
                                                    .set_file_name(&default_name)
                                                    .save_file()
                                                {
                                                    self.trigger_adb_patch_export(output);
                                                }
                                            }
                                            if !preflight_allowed {
                                                ui.colored_label(
                                                    egui::Color32::from_rgb(255, 120, 100),
                                                    "Samsung custom-image preflight is blocked by the selected FRP, OEM unlock, or KG state.",
                                                );
                                            }
                                            if self.boot_patch_active {
                                                ui.horizontal(|ui| {
                                                    ui.spinner();
                                                    ui.label("Patching image…");
                                                });
                                            }
                                            if let Some(status) = &self.boot_patch_status {
                                                ui.label(status);
                                            }
                                        });
                                }
                            });

                            ui.add_space(8.0);

                            // Section 4: Target Configuration & Execution Flags
                            if self.flash_target_type == FlashTargetType::SamsungOdinLoke {
                                ui.group(|ui| {
                                    ui.label(
                                        egui::RichText::new("Samsung Flash Options").strong(),
                                    );
                                    ui.separator();
                                    ui.checkbox(
                                        &mut self.auto_reboot_after_flash,
                                        "Reboot device after successful flash",
                                    );
                                });
                            } else {
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
                            }

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
                                        "⚡ WORKING..."
                                    } else if self.flash_target_type == FlashTargetType::SamsungOdinLoke {
                                        "⚡ FLASH SAMSUNG VIA HEIMDALL"
                                    } else {
                                        "🚀 EXECUTE FLASH PIPELINE"
                                    };

                                    let samsung_ready = self.flash_target_type
                                        == FlashTargetType::SamsungOdinLoke
                                        && self.samsung_flash_confirmed
                                        && HeimdallEngine::find_executable().is_some()
                                        && [
                                            self.samsung_config.bl_tar.as_ref(),
                                            self.samsung_config.ap_tar.as_ref(),
                                            self.samsung_config.cp_tar.as_ref(),
                                            self.samsung_config.csc_tar.as_ref(),
                                        ]
                                        .iter()
                                        .any(|path| path.is_some());
                                    let can_execute = !self.flashing_active
                                        && (samsung_ready
                                            || (self.flash_target_type
                                                != FlashTargetType::SamsungOdinLoke
                                                && self.selected_device().is_some()));
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
                                .show(ui, |ui| {
                                    for (idx, dev) in self.devices.iter().enumerate() {
                                        ui.push_id(idx, |ui| {
                                            let is_selected = self.selected_device_idx == Some(idx);
                                            let mode_color = match dev.operating_mode {
                                                DeviceOperatingMode::SamsungLokeDownload => egui::Color32::from_rgb(0, 230, 255),
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
