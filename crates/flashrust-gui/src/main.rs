use eframe::egui;
use std::time::{Duration, Instant};
use toolkit_core::{
    create_storage_layout_plan, list_attached_devices, BoardPreset, DeviceOperatingMode,
    StorageLayoutPlan, UsbDeviceInfo, ZigEngine, PRESETS,
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

struct FlashrustApp {
    zig_version: &'static str,
    selected_preset_idx: usize,
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
}

impl FlashrustApp {
    fn new() -> Self {
        let default_preset = &PRESETS[0];
        let initial_devices = list_attached_devices();
        // Auto-select first recognized target device if available, otherwise first device
        let initial_selected = initial_devices
            .iter()
            .position(|d| d.operating_mode != DeviceOperatingMode::Unknown)
            .or_else(|| if initial_devices.is_empty() { None } else { Some(0) });

        Self {
            zig_version: ZigEngine::version(),
            selected_preset_idx: 0,
            emmc_boot: false,
            mcu_binary: default_preset.mcu_binary,
            storage_capacity_gb: 32,
            uboot_feature_override: default_preset.uboot_feature.to_string(),
            dtb_feature_override: default_preset.dtb_feature.to_string(),
            devices: initial_devices,
            selected_device_idx: initial_selected,
            last_device_scan: Instant::now(),
            flashing_active: false,
            flash_progress: 0.0,
            log_messages: vec![
                "[SYSTEM] flashrust Host Orchestrator initialized".into(),
                format!("[ENGINE] Zig Bare-Metal Engine: {}", ZigEngine::version()),
                "[USB] nusb monitoring active - click any device to select it as flash target".into(),
            ],
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
                self.selected_device_idx = Some(0);
            }
            self.devices = updated;
            self.last_device_scan = Instant::now();
        }

        // Advance simulation progress if active
        if self.flashing_active {
            self.flash_progress += 0.015;
            if self.flash_progress >= 1.0 {
                self.flashing_active = false;
                self.flash_progress = 1.0;
                let target_name = self
                    .selected_device()
                    .and_then(|d| d.product.clone())
                    .unwrap_or_else(|| "Target Device".into());
                self.log_messages.push(format!(
                    "[FLASH] Image write to '{}' completed successfully!",
                    target_name
                ));
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
                    ui.label(
                        egui::RichText::new(format!(
                            "🎯 Active Target: [{:04x}:{:04x}] {} ({:?})",
                            target.vendor_id, target.product_id, prod, target.operating_mode
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
                // Column 1: Hardware Profiles & UUU Controls
                columns[0].vertical(|ui| {
                    ui.group(|ui| {
                        ui.heading("🛠 Hardware Profile & Target Preset");
                        ui.add_space(4.0);

                        let prev_idx = self.selected_preset_idx;
                        egui::ComboBox::from_label("Target Hardware Preset")
                            .selected_text(self.current_preset().name)
                            .show_ui(ui, |ui| {
                                for (idx, p) in PRESETS.iter().enumerate() {
                                    ui.selectable_value(&mut self.selected_preset_idx, idx, p.name);
                                }
                            });

                        // If preset changed, update defaults
                        if prev_idx != self.selected_preset_idx {
                            let p = self.current_preset();
                            self.mcu_binary = p.mcu_binary;
                            self.uboot_feature_override = p.uboot_feature.to_string();
                            self.dtb_feature_override = p.dtb_feature.to_string();
                        }

                        let p = self.current_preset();
                        ui.label(format!("SoC: {}", p.soc));
                    });

                    ui.add_space(8.0);

                    ui.group(|ui| {
                        ui.heading("⚙ NXP UUU Execution Flags");
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

                    // Flash Action Button with Target Awareness
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
                        } else {
                            ui.label(
                                egui::RichText::new("⚠️ Please select a USB device from the list on the right")
                                    .color(egui::Color32::from_rgb(255, 180, 50)),
                            );
                        }

                        let btn_enabled = !self.flashing_active && self.selected_device().is_some();
                        let btn_text = if self.flashing_active {
                            "Flashing..."
                        } else if self.selected_device().is_some() {
                            "Flash Selected USB Target"
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
                                self.log_messages.push(format!(
                                    "[FLASH] Staging SPL payload to [{:04x}:{:04x}] {} (SoC: {})",
                                    target.vendor_id, target.product_id, prod, self.current_preset().soc
                                ));
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
                            ui.label(egui::RichText::new("(Click to select target)").italics().color(egui::Color32::GRAY));
                        });
                        ui.add_space(4.0);

                        if self.devices.is_empty() {
                            ui.label(egui::RichText::new("No flashing targets or debug probes connected").color(egui::Color32::GRAY));
                        } else {
                            egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                                for (idx, dev) in self.devices.iter().enumerate() {
                                    let is_selected = self.selected_device_idx == Some(idx);
                                    let mode_color = match dev.operating_mode {
                                        DeviceOperatingMode::NxpSerialDownload => egui::Color32::from_rgb(255, 165, 0),
                                        DeviceOperatingMode::Fastboot => egui::Color32::from_rgb(0, 255, 128),
                                        DeviceOperatingMode::AndroidAdb => egui::Color32::from_rgb(0, 210, 255),
                                        DeviceOperatingMode::DebugProbe => egui::Color32::from_rgb(200, 100, 255),
                                        _ => egui::Color32::WHITE,
                                    };

                                    let prod = dev.product.as_deref().unwrap_or("Generic USB Device");
                                    ui.horizontal(|ui| {
                                        let prefix = if is_selected { "▶" } else { " " };
                                        let label = format!("{} [{:04x}:{:04x}] {}", prefix, dev.vendor_id, dev.product_id, prod);
                                        if ui.selectable_label(is_selected, label).clicked() {
                                            self.selected_device_idx = Some(idx);
                                            self.log_messages.push(format!(
                                                "[USB] Selected target device: [{:04x}:{:04x}] {}",
                                                dev.vendor_id, dev.product_id, prod
                                            ));
                                        }
                                        ui.colored_label(mode_color, format!("({:?})", dev.operating_mode));
                                    });
                                }
                            });

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

                        egui::ScrollArea::vertical().max_height(110.0).show(ui, |ui| {
                            for msg in self.log_messages.iter().rev() {
                                ui.label(egui::RichText::new(msg).monospace().color(egui::Color32::from_rgb(220, 220, 140)));
                            }
                        });
                    });
                });
            });
        });
    }
}
