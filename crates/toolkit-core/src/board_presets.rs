use crate::error::{FlashrustError, Result};
use crate::usb_monitor::UsbDeviceInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoardPreset {
    pub name: &'static str,
    pub soc: &'static str,
    pub uboot_feature: &'static str,
    pub dtb_feature: &'static str,
    pub mcu_binary: bool,
}

pub const PRESETS: &[BoardPreset] = &[
    BoardPreset {
        name: "imx8mm-evk-revc",
        soc: "imx8mm",
        uboot_feature: "trusty-dual",
        dtb_feature: "mipi-panel",
        mcu_binary: false,
    },
    BoardPreset {
        name: "imx8mn-evk",
        soc: "imx8mn",
        uboot_feature: "trusty-dual",
        dtb_feature: "rpmsg",
        mcu_binary: true,
    },
    BoardPreset {
        name: "imx8mp-evk",
        soc: "imx8mp",
        uboot_feature: "trusty-dual",
        dtb_feature: "basler-ov5640",
        mcu_binary: false,
    },
    BoardPreset {
        name: "imx8ulp-evk-lpa",
        soc: "imx8ulp",
        uboot_feature: "trusty-lpa-dual",
        dtb_feature: "lpa",
        mcu_binary: true,
    },
    BoardPreset {
        name: "frdm-imx95",
        soc: "imx95",
        uboot_feature: "trusty-15x15-frdm-dual",
        dtb_feature: "15x15-frdm",
        mcu_binary: false,
    },
    BoardPreset {
        name: "imx952-evk-rpmsg",
        soc: "imx952",
        uboot_feature: "trusty-dual",
        dtb_feature: "rpmsg",
        mcu_binary: true,
    },
    BoardPreset {
        name: "imx6q-sabresd",
        soc: "imx6q",
        uboot_feature: "sd",
        dtb_feature: "ldo",
        mcu_binary: false,
    },
    BoardPreset {
        name: "imx6ull-evk",
        soc: "imx6ull",
        uboot_feature: "sd",
        dtb_feature: "14x14-evk",
        mcu_binary: false,
    },
    BoardPreset {
        name: "imx6sx-sdb",
        soc: "imx6sx",
        uboot_feature: "sd",
        dtb_feature: "m4",
        mcu_binary: true,
    },
    BoardPreset {
        name: "imx7d-sabresd",
        soc: "imx7d",
        uboot_feature: "sd",
        dtb_feature: "m4",
        mcu_binary: true,
    },
];

pub fn find_preset(name_or_soc: &str) -> Result<&'static BoardPreset> {
    let query = name_or_soc.trim().to_ascii_lowercase();
    for preset in PRESETS {
        if preset.name.eq_ignore_ascii_case(&query) || preset.soc.eq_ignore_ascii_case(&query) {
            return Ok(preset);
        }
    }
    Err(FlashrustError::UnknownBoardPreset(name_or_soc.to_string()))
}

/// Auto-detect the matching board preset from an attached USB device
pub fn detect_preset_from_usb(dev: &UsbDeviceInfo) -> Option<&'static BoardPreset> {
    // 1. Exact PID matching for NXP Serial Download Boot ROM (VID 0x1FC9 or 0x15A2)
    if dev.vendor_id == 0x1FC9 || dev.vendor_id == 0x15A2 {
        match dev.product_id {
            0x0054 => return find_preset("imx6q").ok(),
            0x0071 => return find_preset("imx6sx").ok(),
            0x0076 => return find_preset("imx7d").ok(),
            0x0080 => return find_preset("imx6ull").ok(),
            0x013E | 0x0134 => return find_preset("imx8mm").ok(),
            0x0139 => return find_preset("imx8mn").ok(),
            0x0146 => return find_preset("imx8mp").ok(),
            0x014C => return find_preset("imx8ulp").ok(),
            0x014E | 0x0150 => return find_preset("imx95").ok(),
            0x0151 | 0x0152 => return find_preset("imx952").ok(),
            _ => {}
        }
    }

    // 2. String heuristic matching across product descriptor and manufacturer
    let mut search_text = String::new();
    if let Some(ref prod) = dev.product {
        search_text.push_str(prod);
        search_text.push(' ');
    }
    if let Some(ref mfg) = dev.manufacturer {
        search_text.push_str(mfg);
    }
    let lower = search_text.to_ascii_lowercase();

    if lower.contains("6ull") {
        find_preset("imx6ull").ok()
    } else if lower.contains("6sx") || lower.contains("6solox") {
        find_preset("imx6sx").ok()
    } else if lower.contains("6q") || lower.contains("6dq") {
        find_preset("imx6q").ok()
    } else if lower.contains("7d") || lower.contains("7dual") {
        find_preset("imx7d").ok()
    } else if lower.contains("8mm") || lower.contains("8m mini") {
        find_preset("imx8mm").ok()
    } else if lower.contains("8mn") || lower.contains("8m nano") {
        find_preset("imx8mn").ok()
    } else if lower.contains("8mp") || lower.contains("8m plus") {
        find_preset("imx8mp").ok()
    } else if lower.contains("8ulp") {
        find_preset("imx8ulp").ok()
    } else if lower.contains("952") {
        find_preset("imx952").ok()
    } else if lower.contains("imx95") || lower.contains("frdm") || lower.contains("i.mx95") {
        find_preset("imx95").ok()
    } else {
        None
    }
}
