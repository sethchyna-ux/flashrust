use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStorage {
    Emmc,
    Sd,
}

impl TargetStorage {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetStorage::Emmc => "emmc",
            TargetStorage::Sd => "sd",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UuuCommandBuilder {
    pub soc_name: String,
    pub slot: Option<char>,
    pub target_dev: TargetStorage,
    pub erase_userdata: bool,
    pub uboot_feature: Option<String>,
    pub dtb_feature: Option<String>,
    pub mcu_image: bool,
    pub card_size: Option<u32>,
    pub image_dir: Option<PathBuf>,
    pub daemon_mode: bool,
    pub ram_boot_only: bool,
    pub dry_run: bool,
    pub usb_paths: Vec<String>,
}

impl UuuCommandBuilder {
    pub fn new(soc_name: &str) -> Self {
        Self {
            soc_name: soc_name.to_string(),
            slot: None,
            target_dev: TargetStorage::Emmc,
            erase_userdata: false,
            uboot_feature: None,
            dtb_feature: None,
            mcu_image: false,
            card_size: None,
            image_dir: None,
            daemon_mode: false,
            ram_boot_only: false,
            dry_run: false,
            usb_paths: Vec::new(),
        }
    }

    /// Compiles arguments into an array matching NXP specifications
    pub fn build_args(&self) -> Vec<String> {
        let mut args = vec!["-f".to_string(), self.soc_name.clone()];

        if let Some(s) = self.slot {
            match s.to_ascii_lowercase() {
                'a' => args.push("-a".to_string()),
                'b' => args.push("-b".to_string()),
                _ => {}
            }
        }

        if self.target_dev == TargetStorage::Sd {
            args.push("-t".to_string());
            args.push("sd".to_string());
        }

        if self.erase_userdata {
            args.push("-e".to_string());
        }

        if let Some(ref u) = self.uboot_feature {
            if !u.is_empty() {
                args.push("-u".to_string());
                args.push(u.clone());
            }
        }

        if let Some(ref d) = self.dtb_feature {
            if !d.is_empty() {
                args.push("-d".to_string());
                args.push(d.clone());
            }
        }

        if self.mcu_image {
            args.push("-m".to_string());
        }

        if let Some(c) = self.card_size {
            args.push("-c".to_string());
            args.push(c.to_string());
        }

        if let Some(ref dir) = self.image_dir {
            args.push("-D".to_string());
            args.push(dir.to_string_lossy().to_string());
        }

        if self.daemon_mode {
            args.push("-daemon".to_string());
        }

        if self.ram_boot_only {
            args.push("-i".to_string());
        }

        if self.dry_run {
            args.push("-dryrun".to_string());
        }

        for path in &self.usb_paths {
            args.push("-usb".to_string());
            args.push(path.clone());
        }

        args
    }

    pub fn to_command_string(&self) -> String {
        format!("uuu_imx_android_flash.sh {}", self.build_args().join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuu_command_builder_basic() {
        let builder = UuuCommandBuilder::new("imx8mm");
        let args = builder.build_args();
        assert_eq!(args, vec!["-f", "imx8mm"]);
        assert_eq!(builder.to_command_string(), "uuu_imx_android_flash.sh -f imx8mm");
    }

    #[test]
    fn test_uuu_command_builder_full() {
        let mut builder = UuuCommandBuilder::new("imx8mp");
        builder.slot = Some('a');
        builder.target_dev = TargetStorage::Sd;
        builder.erase_userdata = true;
        builder.uboot_feature = Some("trusty-dual".to_string());
        builder.dtb_feature = Some("mipi-panel".to_string());
        builder.mcu_image = true;
        builder.card_size = Some(28);
        builder.image_dir = Some(PathBuf::from("/custom/build/output"));
        builder.daemon_mode = true;
        builder.ram_boot_only = true;
        builder.dry_run = true;
        builder.usb_paths.push("1-1.2".to_string());

        let args = builder.build_args();
        assert!(args.contains(&"-f".to_string()));
        assert!(args.contains(&"imx8mp".to_string()));
        assert!(args.contains(&"-a".to_string()));
        assert!(args.contains(&"-t".to_string()));
        assert!(args.contains(&"sd".to_string()));
        assert!(args.contains(&"-e".to_string()));
        assert!(args.contains(&"-u".to_string()));
        assert!(args.contains(&"trusty-dual".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"mipi-panel".to_string()));
        assert!(args.contains(&"-m".to_string()));
        assert!(args.contains(&"-c".to_string()));
        assert!(args.contains(&"28".to_string()));
        assert!(args.contains(&"-D".to_string()));
        assert!(args.contains(&"/custom/build/output".to_string()));
        assert!(args.contains(&"-daemon".to_string()));
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"-dryrun".to_string()));
        assert!(args.contains(&"-usb".to_string()));
        assert!(args.contains(&"1-1.2".to_string()));
    }
}
