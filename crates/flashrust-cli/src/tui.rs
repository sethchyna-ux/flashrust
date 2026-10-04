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
use toolkit_core::{list_attached_devices, PRESETS, ZigEngine, UsbDeviceInfo};

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

    // RTT trace log buffer
    let mut rtt_logs: Vec<String> = vec![
        "[BOOT] RP2350 ROM execution started: magic 0xffffded3 verified".into(),
        "[DCP] Co-Processor 4 (DCP) double precision initialized".into(),
        "[USB] nusb endpoint watcher active (polling IOKit/usbfs)".into(),
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
        }

        // Advance simulation progress if active
        if flash_sim_active {
            flash_progress = (flash_progress + 2).min(100);
            if flash_progress >= 100 {
                flash_sim_active = false;
                rtt_logs.push("[FLASH] Flashing completed successfully. Target rebooting.".into());
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
            let gauge_title = if flash_sim_active {
                format!(" Streaming Chunks over nusb (Speed: {:.1} MiB/s) ", flash_speed_mib)
            } else if flash_progress == 100 {
                " Flashing Complete (100%) ".to_string()
            } else {
                " Flashing Engine Idle - Press [f] to trigger test flash stream ".to_string()
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
                    Constraint::Percentage(40), // Presets
                    Constraint::Percentage(30), // USB
                    Constraint::Percentage(30), // RTT Logs
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

            // USB Topology Panel
            let mut device_lines = vec![Line::from(Span::styled(
                format!("Attached Devices: {}", cached_devices.len()),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ))];

            if cached_devices.is_empty() {
                device_lines.push(Line::from(Span::styled(
                    "No flashing targets or debug probes connected",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for dev in cached_devices.iter().take(6) {
                    let mode_str = format!("{:?}", dev.operating_mode);
                    let desc = format!(
                        "• [{:04x}:{:04x}] {} ({})",
                        dev.vendor_id,
                        dev.product_id,
                        dev.product.as_deref().unwrap_or("USB Device"),
                        mode_str
                    );
                    device_lines.push(Line::from(Span::styled(desc, Style::default().fg(Color::White))));
                }
            }

            let usb_panel = Paragraph::new(device_lines)
                .block(Block::default().borders(Borders::ALL).title(" USB Hotplug Topology "));
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
                Span::styled(" [q] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Quit   "),
                Span::styled(" [r] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Force Rescan   "),
                Span::styled(" [f] ", Style::default().fg(Color::Black).bg(Color::White)),
                Span::raw(" Test Flash Stream   "),
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
                        KeyCode::Char('r') => {
                            cached_devices = list_attached_devices();
                            last_usb_scan = Instant::now();
                            rtt_logs.push(format!("[USB] Manual rescan complete: {} devices found", cached_devices.len()));
                        }
                        KeyCode::Char('f') => {
                            flash_sim_active = true;
                            flash_progress = 0;
                            rtt_logs.push("[FLASH] Initiating chunked streaming over nusb (512 KiB blocks)...".into());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}
