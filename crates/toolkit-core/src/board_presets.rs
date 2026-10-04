use crate::error::{FlashrustError, Result};
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
