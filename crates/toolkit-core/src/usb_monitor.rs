use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceOperatingMode {
    NxpSerialDownload,
    AndroidAdb,
    Fastboot,
    SamsungLokeDownload,
    DebugProbe,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub operating_mode: DeviceOperatingMode,
}

pub fn identify_operating_mode(vendor_id: u16, product_id: u16) -> DeviceOperatingMode {
    match (vendor_id, product_id) {
        // NXP Serial Download Mode
        (0x1FC9, _) | (0x15A2, _) => DeviceOperatingMode::NxpSerialDownload,

        // Android ADB Interface
        (0x18D1, 0x4EE7) | (0x18D1, 0x4EE0) => DeviceOperatingMode::AndroidAdb,

        // Fastboot / FastbootD Mode
        (0x18D1, 0x4EE8) => DeviceOperatingMode::Fastboot,

        // Samsung Loke Download Mode
        (0x04E8, 0x685D) => DeviceOperatingMode::SamsungLokeDownload,

        // Debug Probes (CMSIS-DAP / ST-Link / J-Link)
        (0x1366, _) | (0x0483, _) => DeviceOperatingMode::DebugProbe,

        _ => DeviceOperatingMode::Unknown,
    }
}

pub fn list_attached_devices() -> Vec<UsbDeviceInfo> {
    match nusb::list_devices() {
        Ok(dev_iter) => dev_iter
            .map(|dev| {
                let vid = dev.vendor_id();
                let pid = dev.product_id();
                let mode = identify_operating_mode(vid, pid);
                UsbDeviceInfo {
                    vendor_id: vid,
                    product_id: pid,
                    manufacturer: dev.manufacturer_string().map(|s| s.to_string()),
                    product: dev.product_string().map(|s| s.to_string()),
                    serial_number: dev.serial_number().map(|s| s.to_string()),
                    operating_mode: mode,
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}
