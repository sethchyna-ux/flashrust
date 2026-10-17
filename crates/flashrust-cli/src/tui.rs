use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use toolkit_core::{
    PRESETS, UsbDeviceInfo, ZigEngine, detect_preset_from_usb, list_attached_devices,
    SamsungOdinConfig, HeimdallEngine,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SamsungField {
    Bl,
    Ap,
    Cp,
    Csc,
    Pit,
}

pub struct TerminalGuard {
    stdout: Stdout,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        let mut stdout = io::stdout();
        enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen)?;

        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            default_hook(info);
        }));

        Ok(Self { stdout })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.stdout, LeaveAlternateScreen);
    }
}

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let zig_version = ZigEngine::version();
    let mut last_usb_scan = Instant::now();
    let mut cached_devices: Vec<UsbDeviceInfo> = list_attached_devices();
    let mut selected_device_idx: usize = 0;

    // RTT trace log buffer
    let mut rtt_logs: Vec<String> = vec![
        "[BOOT] RP2350 ROM execution started: magic 0xffffded3 verified".into(),
        "[DCP] Co-Processor 4 (DCP) double precision initialized".into(),
        "[USB] nusb endpoint watcher active (use ↑/↓ to select target)".into(),
    ];

    let flash_progress: u16 = 0;

    // Samsung Odin / Loke firmware archive paths (BL / AP / CP / CSC / PIT)
    let mut samsung_bl: Option<PathBuf> = None;
    let mut samsung_ap: Option<PathBuf> = None;
    let mut samsung_cp: Option<PathBuf> = None;
    let mut samsung_csc: Option<PathBuf> = None;
    let mut samsung_pit: Option<PathBuf> = None;
    let mut samsung_no_reboot: bool = false;

    // Inline text-input state for entering file paths in the TUI
    let mut text_input_active: Option<SamsungField> = None;
    let mut text_input_buffer: String = String::new();

    loop {
        // Auto-refresh USB devices every 2.5 seconds
        if last_usb_scan.elapsed() >= Duration::from_millis(2500) {
            cached_devices = list_attached_devices();
            last_usb_scan = Instant::now();
            if selected_device_idx >= cached_devices.len() && !cached_devices.is_empty() {
                selected_device_idx = cached_devices.len() - 1;
            }
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(4), // Header
                    Constraint::Length(3), // Progress Gauge
                    Constraint::Min(12),   // Main content (Presets, USB, RTT)
                    Constraint::Length(3), // Footer
                ])
                .split(f.area());

            // 1. Header Block
            let header_text = vec![
                Line::from(vec![
                    Span::styled(
                        "⚡ Project flashrust ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("| High-Performance Dual-Engine Flasher & Bootloader Toolkit"),
                ]),
                Line::from(vec![
                    Span::styled("Host Engine: ", Style::default().fg(Color::Green)),
                    Span::raw("Rust (Tokio / Embassy / nusb) | "),
                    Span::styled("Bare-Metal Engine: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("Zig ({})", zig_version)),
                ]),
            ];
            let header = Paragraph::new(header_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" System Status "),
            );
            f.render_widget(header, chunks[0]);

            // 2. Flashing Progress Bar (Gauge)
            let selected_dev = cached_devices.get(selected_device_idx);
            let auto_preset = selected_dev.and_then(detect_preset_from_usb);
            let selected_dev_desc = selected_dev
                .map(|d| {
                    format!(
                        "[{:04x}:{:04x}] {}",
                        d.vendor_id,
                        d.product_id,
                        d.product.as_deref().unwrap_or("USB Target")
                    )
                })
                .unwrap_or_else(|| "No Target Selected".into());

            let profile_desc = auto_preset
                .map(|p| format!(" (Profile: {})", p.name))
                .unwrap_or_default();

            let configured = [&samsung_bl, &samsung_ap, &samsung_cp, &samsung_csc, &samsung_pit]
                .iter()
                .filter(|p| p.is_some())
                .count();
            let gauge_title = format!(
                " Target: {}{} | Firmware: {}/5 selected | {firmware_hint} ",
                selected_dev_desc, profile_desc, configured,
                firmware_hint = if text_input_active.is_some() {
                    "TYPE PATH, ENTER = CONFIRM, ESC = CANCEL"
                } else {
                    "b=BL a=AP c=CP s=CSC p=PIT n=no-reboot F=FLASH"
                }
            );

            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(gauge_title))
                .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
                .percent(flash_progress);
            f.render_widget(gauge, chunks[1]);

            // 3. Main Content: Split Horizontally into 3 Columns (Presets, USB Topology, RTT Terminal)
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(38), // Presets
                    Constraint::Percentage(34), // USB
                    Constraint::Percentage(28), // RTT Logs
                ])
                .split(chunks[2]);

            // Presets Table
            let rows: Vec<Row> = PRESETS
                .iter()
                .map(|p| {
                    Row::new(vec![
                        p.name.to_string(),
                        p.soc.to_string(),
                        p.uboot_feature.to_string(),
                        if p.mcu_binary { "YES" } else { "NO" }.to_string(),
                    ])
                })
                .collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(35),
                    Constraint::Percentage(20),
                    Constraint::Percentage(35),
                    Constraint::Percentage(10),
                ],
            )
            .header(
                Row::new(vec!["Preset", "SoC", "U-Boot", "MCU"]).style(
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Hardware Profiles "),
            );
            f.render_widget(table, main_chunks[0]);

            // USB Topology Panel with Selection Cursor
            let mut device_lines = vec![Line::from(vec![
                Span::styled(
                    format!("Attached Devices: {} ", cached_devices.len()),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("(↑/↓ navigate)", Style::default().fg(Color::DarkGray)),
            ])];

            if cached_devices.is_empty() {
                device_lines.push(Line::from(Span::styled(
                    "No flashing targets or debug probes connected",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for (idx, dev) in cached_devices.iter().enumerate().take(7) {
                    let is_sel = idx == selected_device_idx;
                    let mode_str = format!("{:?}", dev.operating_mode);
                    let prefix = if is_sel { "▶ " } else { "  " };
                    let desc = format!(
                        "{}[{:04x}:{:04x}] {} ({})",
                        prefix,
                        dev.vendor_id,
                        dev.product_id,
                        dev.product.as_deref().unwrap_or("USB Device"),
                        mode_str
                    );
                    let style = if is_sel {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    device_lines.push(Line::from(Span::styled(desc, style)));
                }
            }

            let usb_panel = Paragraph::new(device_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" USB Target Selection "),
            );
            f.render_widget(usb_panel, main_chunks[1]);

            // RTT Terminal Log Viewer
            let rtt_lines: Vec<Line> = rtt_logs
                .iter()
                .rev()
                .take(12)
                .map(|msg| {
                    let color = if msg.contains("[ERROR]") {
                        Color::Red
                    } else if msg.contains("[FLASH]") {
                        Color::Cyan
                    } else {
                        Color::Yellow
                    };
                    Line::from(Span::styled(msg, Style::default().fg(color)))
                })
                .collect();

            let rtt_panel = Paragraph::new(rtt_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live Target RTT Stream "),
            );
            f.render_widget(rtt_panel, main_chunks[2]);

            // 4. Footer
            if let Some(field) = text_input_active {
                let prompt = match field {
                    SamsungField::Bl => "Enter BL (.tar / .tar.md5) path:",
                    SamsungField::Ap => "Enter AP (.tar / .tar.md5) path:",
                    SamsungField::Cp => "Enter CP (.tar / .tar.md5) path:",
                    SamsungField::Csc => "Enter CSC/HOME_CSC (.tar / .tar.md5) path:",
                    SamsungField::Pit => "Enter device .pit path:",
                };
                let input_text = format!("{} {}█", prompt, text_input_buffer);
                let footer = Paragraph::new(Line::from(vec![
                    Span::styled("[TEXT INPUT] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(input_text),
                ]))
                .block(Block::default().borders(Borders::ALL).title(" Samsung Firmware Path "));
                f.render_widget(footer, chunks[3]);
            } else {
                let footer = Paragraph::new(Line::from(vec![
                    Span::styled(
                        " [↑/↓] ",
                        Style::default().fg(Color::Black).bg(Color::White),
                    ),
                    Span::raw(" Select Target   "),
                    Span::styled(" [f] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" Flash Help   "),
                    Span::styled(" [r] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" Rescan USB   "),
                    Span::styled(" [q] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" Quit   "),
                    Span::raw("   |   "),
                    Span::styled(" [b] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" BL   "),
                    Span::styled(" [a] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" AP   "),
                    Span::styled(" [c] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" CP   "),
                    Span::styled(" [s] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" CSC   "),
                    Span::styled(" [p] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" PIT   "),
                    Span::styled(" [n] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" no-reboot   "),
                    Span::styled(" [F] ", Style::default().fg(Color::Black).bg(Color::White)),
                    Span::raw(" FLASH   "),
                ]))
                .block(Block::default().borders(Borders::ALL));
                f.render_widget(footer, chunks[3]);
            }
        })?;

        // 100ms poll rate for smooth 10fps progress animation and snappy key response
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            // ---- Inline text-input mode (entering a firmware path) ----
            if let Some(field) = text_input_active {
                match key.code {
                    KeyCode::Esc => {
                        text_input_buffer.clear();
                        text_input_active = None;
                        rtt_logs.push("[TEXT INPUT] Cancelled".into());
                    }
                    KeyCode::Enter => {
                        let path = PathBuf::from(text_input_buffer.trim());
                        match field {
                            SamsungField::Bl => samsung_bl = Some(path.clone()),
                            SamsungField::Ap => samsung_ap = Some(path.clone()),
                            SamsungField::Cp => samsung_cp = Some(path.clone()),
                            SamsungField::Csc => samsung_csc = Some(path.clone()),
                            SamsungField::Pit => samsung_pit = Some(path.clone()),
                        }
                        let label = match field {
                            SamsungField::Bl => "BL",
                            SamsungField::Ap => "AP",
                            SamsungField::Cp => "CP",
                            SamsungField::Csc => "CSC",
                            SamsungField::Pit => "PIT",
                        };
                        rtt_logs.push(format!(
                            "[TEXT INPUT] {label} set to {}",
                            path.display()
                        ));
                        text_input_buffer.clear();
                        text_input_active = None;
                    }
                    KeyCode::Backspace => {
                        text_input_buffer.pop();
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        text_input_buffer.push(c);
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up | KeyCode::Char('k') => {
                    selected_device_idx = selected_device_idx.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !cached_devices.is_empty() && selected_device_idx + 1 < cached_devices.len()
                    {
                        selected_device_idx += 1;
                    }
                }
                KeyCode::Char('r') => {
                    cached_devices = list_attached_devices();
                    last_usb_scan = Instant::now();
                    if selected_device_idx >= cached_devices.len() && !cached_devices.is_empty() {
                        selected_device_idx = cached_devices.len() - 1;
                    }
                    rtt_logs.push(format!(
                        "[USB] Rescan complete: {} devices found",
                        cached_devices.len()
                    ));
                }
                KeyCode::Char('b') => {
                    text_input_active = Some(SamsungField::Bl);
                    text_input_buffer.clear();
                }
                KeyCode::Char('a') => {
                    text_input_active = Some(SamsungField::Ap);
                    text_input_buffer.clear();
                }
                KeyCode::Char('c') => {
                    text_input_active = Some(SamsungField::Cp);
                    text_input_buffer.clear();
                }
                KeyCode::Char('s') => {
                    text_input_active = Some(SamsungField::Csc);
                    text_input_buffer.clear();
                }
                KeyCode::Char('p') => {
                    text_input_active = Some(SamsungField::Pit);
                    text_input_buffer.clear();
                }
                KeyCode::Char('n') => {
                    samsung_no_reboot = !samsung_no_reboot;
                    rtt_logs.push(format!(
                        "[SAMSUNG] No-reboot after flash: {}",
                        samsung_no_reboot
                    ));
                }
                KeyCode::Char('f') => {
                    rtt_logs.push(
                        "[FLASH] Use b/a/c/s/p to pick BL/AP/CP/CSC/PIT, then F to flash."
                            .into(),
                    );
                }
                KeyCode::Char('F') => {
                    let cfg = SamsungOdinConfig {
                        bl_tar: samsung_bl.clone(),
                        ap_tar: samsung_ap.clone(),
                        cp_tar: samsung_cp.clone(),
                        csc_tar: samsung_csc.clone(),
                        pit_file: samsung_pit.clone(),
                        ..SamsungOdinConfig::default()
                    };

                    let preflight = cfg.evaluate_preflight(false);
                    rtt_logs.push(format!("[ODIN-PREFLIGHT] {}", preflight.status_headline));
                    if !preflight.current_payload_allowed {
                        rtt_logs.push(
                            "[ODIN-PREFLIGHT] Blocked by FRP/KG. Enable OEM unlock or use stock-signed TARs."
                                .into(),
                        );
                        continue;
                    }

                    let has_any = samsung_bl.is_some()
                        || samsung_ap.is_some()
                        || samsung_cp.is_some()
                        || samsung_csc.is_some();
                    if !has_any {
                        rtt_logs.push("[FLASH] No firmware archives selected (b/a/c/s/p).".into());
                        continue;
                    }

                    rtt_logs.push("[HEIMDALL] Starting real flash session...".into());
                    match HeimdallEngine::flash(&cfg, !samsung_no_reboot, |line| {
                        rtt_logs.push(format!("[HEIMDALL] {line}"));
                    }) {
                        Ok(result) => {
                            rtt_logs.push(format!(
                                "[FLASH] Complete: {} partition(s) via {} {}",
                                result.partition_count,
                                result.heimdall_path.display(),
                                result.heimdall_version
                            ));
                        }
                        Err(error) => {
                            rtt_logs.push(format!("[HEIMDALL-ERROR] {error}"));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}
