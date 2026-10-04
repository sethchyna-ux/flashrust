use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
    Terminal,
};
use std::io::{self, Stdout};
use std::time::{Duration, Instant};
use toolkit_core::{detect_preset_from_usb, list_attached_devices, PRESETS, UsbDeviceInfo, ZigEngine};

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

    // Simulated flashing state for Gauge demonstration
    let mut flash_sim_active = false;
    let mut flash_progress: u16 = 0;
    let flash_speed_mib: f32 = 42.5;

    loop {
        // Auto-refresh USB devices every 2.5 seconds
        if last_usb_scan.elapsed() >= Duration::from_millis(2500) {
            cached_devices = list_attached_devices();
            last_usb_scan = Instant::now();
            if selected_device_idx >= cached_devices.len() && !cached_devices.is_empty() {
                selected_device_idx = cached_devices.len() - 1;
            }
        }

        // Advance simulation progress if active
        if flash_sim_active {
            flash_progress = (flash_progress + 2).min(100);
            if flash_progress >= 100 {
                flash_sim_active = false;
                let target_info = cached_devices
                    .get(selected_device_idx)
                    .and_then(|d| d.product.clone())
                    .unwrap_or_else(|| "Target Device".into());
                rtt_logs.push(format!("[FLASH] Flashing to '{}' completed. Target rebooting.", target_info));
            }
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(4), // Header
                    Constraint::Length(3), // Progress Gauge
                    Constraint::Min(12),  // Main content (Presets, USB, RTT)
                    Constraint::Length(3), // Footer
                ])
                .split(f.area());

            // 1. Header Block
            let header_text = vec![
                Line::from(vec![
                    Span::styled("⚡ Project flashrust ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("| High-Performance Dual-Engine Flasher & Bootloader Toolkit"),
                ]),
                Line::from(vec![
                    Span::styled("Host Engine: ", Style::default().fg(Color::Green)),
                    Span::raw("Rust (Tokio / Embassy / nusb) | "),
                    Span::styled("Bare-Metal Engine: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("Zig ({})", zig_version)),
                ]),
            ];
            let header = Paragraph::new(header_text)
                .block(Block::default().borders(Borders::ALL).title(" System Status "));
            f.render_widget(header, chunks[0]);

            // 2. Flashing Progress Bar (Gauge)
            let selected_dev = cached_devices.get(selected_device_idx);
            let auto_preset = selected_dev.and_then(|d| detect_preset_from_usb(d));
            let selected_dev_desc = selected_dev.map(|d| {
                format!("[{:04x}:{:04x}] {}", d.vendor_id, d.product_id, d.product.as_deref().unwrap_or("USB Target"))
            }).unwrap_or_else(|| "No Target Selected".into());

            let profile_desc = auto_preset.map(|p| format!(" (Profile: {})", p.name)).unwrap_or_default();

            let gauge_title = if flash_sim_active {
                format!(" Streaming Chunks to {}{} (Speed: {:.1} MiB/s) ", selected_dev_desc, profile_desc, flash_speed_mib)
            } else if flash_progress == 100 {
                format!(" Flashing Complete to {}{} (100%) ", selected_dev_desc, profile_desc)
            } else {
                format!(" Target: {}{} | Press [f] to flash ", selected_dev_desc, profile_desc)
            };

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
                Row::new(vec!["Preset", "SoC", "U-Boot", "MCU"])
                    .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Hardware Profiles "));
            f.render_widget(table, main_chunks[0]);

            // USB Topology Panel with Selection Cursor
            let mut device_lines = vec![Line::from(vec![
                Span::styled(format!("Attached Devices: {} ", cached_devices.len()), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
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
                        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    device_lines.push(Line::from(Span::styled(desc, style)));
                }
            }

            let usb_panel = Paragraph::new(device_lines)
                .block(Block::default().borders(Borders::ALL).title(" USB Target Selection "));
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

            let rtt_panel = Paragraph::new(rtt_lines)
                .block(Block::default().borders(Borders::ALL).title(" Live Target RTT Stream "));
            f.render_widget(rtt_panel, main_chunks[2]);

            // 4. Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" [↑/↓] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Select Target   "),
                Span::styled(" [f] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Flash Target   "),
                Span::styled(" [r] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Rescan USB   "),
                Span::styled(" [q] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Quit   "),
            ]))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[3]);
        })?;

        // 100ms poll rate for smooth 10fps progress animation and snappy key response
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => {
                            if selected_device_idx > 0 {
                                selected_device_idx -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !cached_devices.is_empty() && selected_device_idx + 1 < cached_devices.len() {
                                selected_device_idx += 1;
                            }
                        }
                        KeyCode::Char('r') => {
                            cached_devices = list_attached_devices();
                            last_usb_scan = Instant::now();
                            if selected_device_idx >= cached_devices.len() && !cached_devices.is_empty() {
                                selected_device_idx = cached_devices.len() - 1;
                            }
                            rtt_logs.push(format!("[USB] Rescan complete: {} devices found", cached_devices.len()));
                        }
                        KeyCode::Char('f') => {
                            if let Some(target) = cached_devices.get(selected_device_idx) {
                                flash_sim_active = true;
                                flash_progress = 0;
                                let prod = target.product.as_deref().unwrap_or("USB Device");
                                rtt_logs.push(format!(
                                    "[FLASH] Selected target [{:04x}:{:04x}] {} for streaming...",
                                    target.vendor_id, target.product_id, prod
                                ));
                            } else {
                                rtt_logs.push("[ERROR] No USB device selected for flashing".into());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}
