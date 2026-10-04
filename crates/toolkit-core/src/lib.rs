pub mod board_presets;
pub mod boot_kitchen;
pub mod error;
pub mod nxp_transport;
pub mod offset_validator;
pub mod rp2350;
pub mod su_builder;
pub mod usb_monitor;
pub mod uuu_builder;
pub mod zig_bridge;

pub use board_presets::{detect_preset_from_usb, find_preset, BoardPreset, PRESETS};
pub use boot_kitchen::{BootKitchen, InitHijackTarget, PatchSummary};
pub use error::{FlashrustError, Result};
pub use nxp_transport::{
    FlashProgress, SdpCommandPacket, SdpCommandType, UuuTransport, DEFAULT_CHUNK_SIZE,
};
pub use offset_validator::{
    create_storage_layout_plan, get_required_spl_offset_kb, select_partition_table_image,
    StorageLayoutPlan, MCU_BINARY_OFFSET_KB,
};
pub use rp2350::{DcpBenchmarkProfile, QspiWindowMapping, Rp2350Manager, DCP_PROFILES};
pub use su_builder::{
    SuBuildRequirements, SuDetector, TargetCpuArch, STANDALONE_SU_C_SOURCE,
};
pub use usb_monitor::{identify_operating_mode, list_attached_devices, DeviceOperatingMode, UsbDeviceInfo};
pub use uuu_builder::{TargetStorage, UuuCommandBuilder};
pub use zig_bridge::{BootHeaderVersion, BootImageMetadata, Rp2350CoreMode, ZigEngine};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zig_engine_version() {
        let v = ZigEngine::version();
        assert!(v.contains("0.1.0"), "Expected 0.1.0 version string, got {}", v);
    }

    #[test]
    fn test_offset_rules_imx() {
        assert_eq!(get_required_spl_offset_kb("imx8mm", false), 33);
        assert_eq!(get_required_spl_offset_kb("imx8mq", false), 33);
        assert_eq!(get_required_spl_offset_kb("imx8mn", false), 32);
        assert_eq!(get_required_spl_offset_kb("imx8mp", false), 32);
        assert_eq!(get_required_spl_offset_kb("imx8mm", true), 0); // eMMC boot0
    }

    #[test]
    fn test_board_presets() {
        let preset = find_preset("imx8mm").expect("imx8mm should exist");
        assert_eq!(preset.soc, "imx8mm");
        assert_eq!(preset.uboot_feature, "trusty-dual");
        assert_eq!(preset.dtb_feature, "mipi-panel");
        assert!(!preset.mcu_binary);
    }

    #[test]
    fn test_detect_preset_from_usb() {
        // Test NXP i.MX 8M Mini PID 0x013E
        let nxp_8mm = UsbDeviceInfo {
            vendor_id: 0x1FC9,
            product_id: 0x013E,
            manufacturer: Some("NXP Semiconductors".into()),
            product: Some("SE Blank 8MMini".into()),
            serial_number: None,
            operating_mode: DeviceOperatingMode::NxpSerialDownload,
        };
        let detected = detect_preset_from_usb(&nxp_8mm).expect("Should detect imx8mm");
        assert_eq!(detected.soc, "imx8mm");

        // Test descriptor string heuristic for i.MX 95
        let frdm_95 = UsbDeviceInfo {
            vendor_id: 0x1FC9,
            product_id: 0x0999, // Unlisted PID but product string has FRDM
            manufacturer: Some("NXP".into()),
            product: Some("FRDM-IMX95 Freedom Board".into()),
            serial_number: None,
            operating_mode: DeviceOperatingMode::NxpSerialDownload,
        };
        let detected_95 = detect_preset_from_usb(&frdm_95).expect("Should detect imx95");
        assert_eq!(detected_95.soc, "imx95");
    }

    #[test]
    fn test_rp2350_image_def_roundtrip() {
        let mut buf = vec![0u8; 256];
        ZigEngine::seal_rp2350_image_def(&mut buf, Rp2350CoreMode::RiscVMachine, 0x10000000)
            .expect("Sealing should succeed");

        let mode = ZigEngine::verify_rp2350_image_def(&buf)
            .expect("Verification should succeed");
        assert_eq!(mode, Rp2350CoreMode::RiscVMachine);
    }

    #[test]
    fn test_rp2350_qspi_window_translation() {
        // Map subwindow 1 (4MB) to physical flash offset 0x0001_0000 (64 KiB)
        let mapping = Rp2350Manager::configure_qspi_window(1, 0x0001_0000, Rp2350CoreMode::ArmNonSecure)
            .expect("QSPI window mapping should succeed");

        assert_eq!(mapping.window_index, 1);
        assert_eq!(mapping.virtual_base_address, 0x1000_0000 + 4 * 1024 * 1024);
        assert_eq!(mapping.physical_flash_offset, 0x0001_0000);
        assert_eq!(mapping.hardware_register_val, 0x0001_0000 >> 12);
    }

    #[test]
    fn test_nxp_sdp_packet_generation() {
        let cmd = SdpCommandPacket::new_write_file(0x4000_0000, 1024 * 1024);
        let bytes = cmd.to_bytes();
        assert_eq!(bytes.len(), 16);
        // SDP_WRITE_FILE = 0x0202
        assert_eq!(bytes[0..2], [0x02, 0x02]);
        // Address 0x4000_0000
        assert_eq!(bytes[2..6], [0x40, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_nxp_chunking_plan() {
        let chunks = UuuTransport::plan_chunks(1200 * 1024, 512 * 1024);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], (0, 512 * 1024));
        assert_eq!(chunks[1], (512 * 1024, 512 * 1024));
        assert_eq!(chunks[2], (1024 * 1024, 176 * 1024));
    }

    fn create_synthetic_cpio() -> Vec<u8> {
        let mut archive = Vec::new();

        let mut append_entry = |name: &str, data: &[u8]| {
            let namesize = name.len() + 1;
            let filesize = data.len();
            let header = format!(
                "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                1, 0o100755, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namesize, 0
            );
            archive.extend_from_slice(header.as_bytes());
            archive.extend_from_slice(name.as_bytes());
            archive.push(0);

            let name_pad = (4 - (archive.len() % 4)) % 4;
            archive.extend(std::iter::repeat(0).take(name_pad));

            archive.extend_from_slice(data);
            let data_pad = (4 - (archive.len() % 4)) % 4;
            archive.extend(std::iter::repeat(0).take(data_pad));
        };

        append_entry("init", b"#!/bin/sh\necho original-init\n");
        append_entry("TRAILER!!!", b"");

        archive
    }

    #[test]
    fn test_in_memory_cpio_patch_init() {
        let original_cpio = create_synthetic_cpio();
        let ksu_binary = b"\x7fELF-ksuinit-binary-mock";

        let patched_cpio = ZigEngine::patch_cpio_init(&original_cpio, ksu_binary)
            .expect("CPIO init patch should succeed");

        let patched_str = String::from_utf8_lossy(&patched_cpio);
        assert!(patched_str.contains("init.real"), "Should contain renamed init.real");
        assert!(patched_str.contains("init"), "Should contain newly injected init");
        assert!(patched_str.contains("TRAILER!!!"), "Should contain trailer");
        assert!(patched_cpio.windows(ksu_binary.len()).any(|w| w == ksu_binary));
    }

    #[test]
    fn test_in_memory_boot_kitchen_gki_patch() {
        let mut boot_img = vec![0u8; 8192];
        boot_img[0..8].copy_from_slice(b"ANDROID!");
        boot_img[8..12].copy_from_slice(&0u32.to_le_bytes());
        let cpio = create_synthetic_cpio();
        boot_img[12..16].copy_from_slice(&(cpio.len() as u32).to_le_bytes());
        boot_img[40..44].copy_from_slice(&4u32.to_le_bytes());

        boot_img[4096..4096 + cpio.len()].copy_from_slice(&cpio);

        let ksu_payload = b"ELF_KSU_INIT_PAYLOAD";
        let (patched_img, summary) = BootKitchen::patch_boot_image(
            &boot_img,
            ksu_payload,
            InitHijackTarget::KernelSU,
            None,
        )
        .expect("BootKitchen patch should succeed");

        assert_eq!(summary.target, InitHijackTarget::KernelSU);
        assert_eq!(summary.header_version, "V4");
        assert!(summary.patched_ramdisk_size > summary.original_ramdisk_size);
        assert!(patched_img.len() >= 8192);

        let new_size = u32::from_le_bytes(patched_img[12..16].try_into().unwrap());
        assert_eq!(new_size as usize, summary.patched_ramdisk_size);
    }

    #[test]
    fn test_selinux_rule_injection() {
        let original_policy = b"mock-selinux-binary-policy-content";
        let patched = ZigEngine::inject_selinux_rules(original_policy)
            .expect("SELinux rule injection should succeed");

        let policy_str = String::from_utf8_lossy(&patched);
        assert!(policy_str.contains("allow su * * *"));
        assert!(policy_str.contains("mock-selinux-binary-policy-content"));
    }

    #[test]
    fn test_in_memory_su_binary_injection() {
        let original_cpio = create_synthetic_cpio();
        let su_bytes = b"\x7fELF-standalone-su-binary";

        // Inject at system/bin/su with setuid true and replace_init true
        let patched_cpio = ZigEngine::inject_su_binary(
            &original_cpio,
            su_bytes,
            "system/bin/su",
            true,
            true,
        )
        .expect("SU binary injection should succeed");

        let patched_str = String::from_utf8_lossy(&patched_cpio);
        assert!(patched_str.contains("system/bin/su"), "Should contain system/bin/su");
        assert!(patched_str.contains("init.real"), "Should contain renamed init.real");
        assert!(patched_str.contains("init"), "Should contain new init entry");
        assert!(patched_cpio.windows(su_bytes.len()).any(|w| w == su_bytes));
    }

    #[test]
    fn test_su_detector_requirements_samsung() {
        let samsung_dev = UsbDeviceInfo {
            vendor_id: 0x04E8,
            product_id: 0x6860,
            manufacturer: Some("SAMSUNG".into()),
            product: Some("SAMSUNG_Android".into()),
            serial_number: Some("R5CY744N4KP".into()),
            operating_mode: DeviceOperatingMode::AndroidAdb,
        };

        let reqs = SuDetector::detect(Some(&samsung_dev), None);
        assert_eq!(reqs.target_arch, TargetCpuArch::Aarch64);
        assert_eq!(reqs.target_triple, "aarch64-linux-musl");
        assert_eq!(reqs.android_abi, "arm64-v8a");
        assert!(reqs.is_64bit);
        assert!(reqs.compiler_detected, "Zig compiler should be detected on host");
        assert_eq!(reqs.permissions_mode, 0o104755);
        assert_eq!(reqs.selinux_context, "u:r:su:s0 (Permissive Domain)");
        assert!(reqs.can_build);
    }

    #[test]
    fn test_su_detector_build_arm64() {
        let samsung_dev = UsbDeviceInfo {
            vendor_id: 0x04E8,
            product_id: 0x6860,
            manufacturer: Some("SAMSUNG".into()),
            product: Some("SAMSUNG_Android".into()),
            serial_number: Some("R5CY744N4KP".into()),
            operating_mode: DeviceOperatingMode::AndroidAdb,
        };

        let reqs = SuDetector::detect(Some(&samsung_dev), None);
        let temp_dir = std::env::temp_dir().join("flashrust_su_test");
        let bin_path = SuDetector::build(&reqs, &temp_dir).expect("Building static SU binary should succeed");

        assert!(bin_path.exists());
        let meta = std::fs::metadata(&bin_path).expect("File metadata");
        assert!(meta.len() > 10_000, "Expected stripped binary > 10KB, got {}", meta.len());

        let bytes = std::fs::read(&bin_path).expect("Read binary bytes");
        assert_eq!(&bytes[0..4], b"\x7fELF");
        assert_eq!(bytes[4], 2, "Expected 64-bit ELF (ELFCLASS64)");
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        assert_eq!(machine, 0x00B7, "Expected EM_AARCH64 machine code 0x00B7");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
