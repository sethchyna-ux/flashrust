use crate::error::{FlashrustError, Result};
use crate::samsung_odin::{OdinProtocolEngine, PitTable, SamsungOdinConfig};
use lz4_flex::frame::FrameDecoder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamsungFlashResult {
    pub heimdall_path: PathBuf,
    pub heimdall_version: String,
    pub partition_count: usize,
    pub partitions: Vec<String>,
    pub reboot_requested: bool,
    pub output: String,
}

pub struct HeimdallEngine;

impl HeimdallEngine {
    pub fn find_executable() -> Option<PathBuf> {
        let mut candidates = Vec::new();
        if let Some(path) = std::env::var_os("FLASHRUST_HEIMDALL") {
            candidates.push(PathBuf::from(path));
        }
        if let Ok(current) = std::env::current_exe()
            && let Some(macos_dir) = current.parent()
        {
            candidates.push(macos_dir.join("../Resources/heimdall"));
            candidates.push(macos_dir.join("heimdall"));
        }
        candidates
            .push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/heimdall/heimdall"));
        candidates.push(PathBuf::from("vendor/heimdall/heimdall"));
        candidates.push(PathBuf::from("/opt/homebrew/bin/heimdall"));
        candidates.push(PathBuf::from("/usr/local/bin/heimdall"));

        candidates.into_iter().find(|path| path.is_file())
    }

    pub fn version() -> Result<String> {
        let executable = Self::required_executable()?;
        let output = Command::new(&executable)
            .arg("version")
            .output()
            .map_err(|error| Self::process_error("version", error))?;
        if !output.status.success() {
            return Err(FlashrustError::UsbError(format!(
                "{} version failed: {}",
                executable.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn detect() -> Result<String> {
        let executable = Self::required_executable()?;
        let output = Command::new(&executable)
            .args(["detect", "--stdout-errors"])
            .output()
            .map_err(|error| Self::process_error("detect", error))?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() {
            return Err(FlashrustError::UsbError(format!(
                "Heimdall did not detect a Samsung device in Download Mode: {}",
                combined.trim()
            )));
        }
        Ok(combined.trim().to_string())
    }

    pub fn flash<F>(
        config: &SamsungOdinConfig,
        reboot: bool,
        mut on_line: F,
    ) -> Result<SamsungFlashResult>
    where
        F: FnMut(&str),
    {
        let executable = Self::required_executable()?;
        let heimdall_version = Self::version()?;
        on_line(&format!(
            "Using real Heimdall USB engine {} ({})",
            executable.display(),
            heimdall_version
        ));
        let detection = Self::detect()?;
        on_line(&format!("Download Mode device detected: {detection}"));

        let workspace = tempfile::Builder::new()
            .prefix("flashrust-samsung-")
            .tempdir()
            .map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let archives = [
            ("BL", config.bl_tar.as_ref()),
            ("AP", config.ap_tar.as_ref()),
            ("CP", config.cp_tar.as_ref()),
            ("CSC", config.csc_tar.as_ref()),
        ];
        if archives.iter().all(|(_, path)| path.is_none()) {
            return Err(FlashrustError::StorageValidationError(
                "Select at least one BL, AP, CP, or CSC firmware archive".into(),
            ));
        }

        let mut extracted = Vec::new();
        for (slot, path) in archives {
            let Some(path) = path else { continue };
            if !path.is_file() {
                return Err(FlashrustError::IoError(format!(
                    "{slot} archive does not exist: {}",
                    path.display()
                )));
            }
            let manifest = OdinProtocolEngine::inspect_tar_file(path, None)?;
            if manifest.md5_matches == Some(false) {
                return Err(FlashrustError::StorageValidationError(format!(
                    "{slot} archive MD5 trailer does not match: {}",
                    path.display()
                )));
            }
            if path
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("md5"))
                && !manifest.has_md5_trailer
            {
                return Err(FlashrustError::StorageValidationError(format!(
                    "{slot} archive is named .md5 but has no valid trailing checksum: {}",
                    path.display()
                )));
            }
            on_line(&format!(
                "Verified {slot}: {} entries, {} payload bytes, MD5={:?}",
                manifest.entries.len(),
                manifest.total_payload_bytes,
                manifest.md5_matches
            ));
            extracted.extend(Self::extract_archive(path, &workspace.path().join(slot))?);
        }

        let pit_path = if let Some(path) = config.pit_file.as_ref() {
            path.clone()
        } else {
            extracted
                .iter()
                .find(|path| {
                    path.extension()
                        .and_then(OsStr::to_str)
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("pit"))
                })
                .cloned()
                .ok_or_else(|| {
                    FlashrustError::StorageValidationError(
                        "A device-specific PIT is required. Select the matching CSC/HOME_CSC archive or choose a .pit file.".into(),
                    )
                })?
        };
        let pit_bytes =
            std::fs::read(&pit_path).map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let pit = PitTable::parse_bytes(&pit_bytes)?;
        on_line(&format!(
            "Using PIT {} / {} with {} partitions",
            pit.project_name,
            pit.gang_name,
            pit.entries.len()
        ));

        let prepared_dir = workspace.path().join("prepared");
        std::fs::create_dir_all(&prepared_dir)
            .map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let mut plan = BTreeMap::<String, PathBuf>::new();
        for image in extracted {
            if image
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pit"))
            {
                continue;
            }
            let Some(filename) = image.file_name().and_then(OsStr::to_str).map(str::to_owned)
            else {
                continue;
            };
            let Some(entry) = pit.find_by_filename(&filename) else {
                on_line(&format!("Skipping {filename}: no matching PIT partition"));
                continue;
            };
            let ready = if filename.to_ascii_lowercase().ends_with(".lz4") {
                let output_name = filename.strip_suffix(".lz4").unwrap_or(&filename);
                let output = prepared_dir.join(format!("{}-{}", entry.partition_name, output_name));
                Self::decompress_lz4(&image, &output)?;
                output
            } else {
                image
            };
            if plan.insert(entry.partition_name.clone(), ready).is_some() {
                on_line(&format!(
                    "{} replaces an earlier image for partition {}",
                    filename, entry.partition_name
                ));
            } else {
                on_line(&format!("Mapped {filename} -> {}", entry.partition_name));
            }
        }
        if plan.is_empty() {
            return Err(FlashrustError::StorageValidationError(
                "No selected firmware image matched the supplied PIT".into(),
            ));
        }

        let mut arguments = vec!["flash".to_string()];
        if config.repartition {
            arguments.push("--repartition".into());
        } else {
            arguments.push("--use-local-pit".into());
        }
        arguments.push("--pit".into());
        arguments.push(pit_path.to_string_lossy().to_string());
        for (partition, image) in &plan {
            arguments.push(format!("--{partition}"));
            arguments.push(image.to_string_lossy().to_string());
        }
        if !reboot {
            arguments.push("--no-reboot".into());
        }
        arguments.push("--stdout-errors".into());

        on_line(&format!(
            "Starting one real Heimdall session for {} partition(s)",
            plan.len()
        ));
        let (status, output) = Self::run_streaming(&executable, &arguments, &mut on_line)?;
        if !Self::successful_flash(status.success(), &output) {
            let tail = output.lines().rev().take(12).collect::<Vec<_>>();
            return Err(FlashrustError::UsbError(format!(
                "Heimdall flash failed:\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            )));
        }

        Ok(SamsungFlashResult {
            heimdall_path: executable,
            heimdall_version,
            partition_count: plan.len(),
            partitions: plan.into_keys().collect(),
            reboot_requested: reboot,
            output,
        })
    }

    fn required_executable() -> Result<PathBuf> {
        Self::find_executable().ok_or_else(|| {
            FlashrustError::UsbError(
                "Real Heimdall USB engine was not found in the app bundle, vendor directory, or PATH override FLASHRUST_HEIMDALL".into(),
            )
        })
    }

    fn extract_archive(archive_path: &Path, destination: &Path) -> Result<Vec<PathBuf>> {
        std::fs::create_dir_all(destination)
            .map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let file =
            File::open(archive_path).map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let mut archive = tar::Archive::new(file);
        let mut files = Vec::new();
        let entries = archive
            .entries()
            .map_err(|error| FlashrustError::StorageValidationError(error.to_string()))?;
        for entry in entries {
            let mut entry =
                entry.map_err(|error| FlashrustError::StorageValidationError(error.to_string()))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let relative = entry
                .path()
                .map_err(|error| FlashrustError::StorageValidationError(error.to_string()))?
                .into_owned();
            let unpacked = entry
                .unpack_in(destination)
                .map_err(|error| FlashrustError::StorageValidationError(error.to_string()))?;
            if !unpacked {
                return Err(FlashrustError::StorageValidationError(format!(
                    "Archive entry escaped its extraction directory: {}",
                    relative.display()
                )));
            }
            files.push(destination.join(relative));
        }
        Ok(files)
    }

    fn decompress_lz4(input: &Path, output: &Path) -> Result<()> {
        let source =
            File::open(input).map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let mut decoder = FrameDecoder::new(BufReader::new(source));
        let target =
            File::create(output).map_err(|error| FlashrustError::IoError(error.to_string()))?;
        let mut writer = BufWriter::new(target);
        std::io::copy(&mut decoder, &mut writer).map_err(|error| {
            FlashrustError::StorageValidationError(format!(
                "Failed to decompress {}: {error}",
                input.display()
            ))
        })?;
        writer
            .flush()
            .map_err(|error| FlashrustError::IoError(error.to_string()))?;
        Ok(())
    }

    fn run_streaming<F>(
        executable: &Path,
        arguments: &[String],
        on_line: &mut F,
    ) -> Result<(std::process::ExitStatus, String)>
    where
        F: FnMut(&str),
    {
        let mut child = Command::new(executable)
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Self::process_error("flash", error))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| FlashrustError::IoError("Failed to capture Heimdall stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| FlashrustError::IoError("Failed to capture Heimdall stderr".into()))?;
        let (sender, receiver) = mpsc::channel::<String>();
        let stdout_sender = sender.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout)
                .lines()
                .map_while(std::result::Result::ok)
            {
                let _ = stdout_sender.send(line);
            }
        });
        std::thread::spawn(move || {
            for line in BufReader::new(stderr)
                .lines()
                .map_while(std::result::Result::ok)
            {
                let _ = sender.send(line);
            }
        });

        let mut output = String::new();
        for line in receiver {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            on_line(line);
            output.push_str(line);
            output.push('\n');
        }
        let status = child
            .wait()
            .map_err(|error| Self::process_error("flash", error))?;
        Ok((status, output))
    }

    fn successful_flash(exit_success: bool, output: &str) -> bool {
        if !exit_success {
            return false;
        }
        let lower = output.to_ascii_lowercase();
        let argument_errors = [
            "duplicate argument:",
            "unknown argument:",
            "invalid argument:",
            "unknown argument type:",
        ];
        !argument_errors.iter().any(|error| lower.contains(error))
            && !(lower.contains("action: flash") && lower.contains("arguments:"))
    }

    fn process_error(command: &str, error: std::io::Error) -> FlashrustError {
        FlashrustError::UsbError(format!("Failed to run Heimdall {command}: {error}"))
    }
}
