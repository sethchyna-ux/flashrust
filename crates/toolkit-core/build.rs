use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let zig_dir = manifest_dir.join("../../zig");
    let zig_out_lib = zig_dir.join("zig-out/lib");

    std::fs::create_dir_all(&zig_out_lib).expect("Failed to create zig-out/lib directory");

    let obj_path = zig_out_lib.join("libflashrust_zig.o");
    let lib_path = zig_out_lib.join("libflashrust_zig.a");

    // 1. Detect Zig version to select module flag syntax (Zig 0.15+ uses -Mroot=)
    let version_out = Command::new("zig")
        .arg("version")
        .output()
        .expect("Failed to execute `zig version`. Ensure zig is installed and in PATH.");
    let version_str = String::from_utf8_lossy(&version_out.stdout)
        .trim()
        .to_string();
    let uses_module_flag = !version_str.starts_with("0.13.") && !version_str.starts_with("0.14.");

    let emit_bin = format!("-femit-bin={}", obj_path.display());
    let mut cmd = Command::new("zig");
    cmd.arg("build-obj");
    if uses_module_flag {
        cmd.args(["-Mroot=src/root.zig", "-lc", "-OReleaseSafe", &emit_bin]);
    } else {
        cmd.args(["src/root.zig", "-lc", "-OReleaseSafe", &emit_bin]);
    }

    let obj_status = cmd
        .current_dir(&zig_dir)
        .status()
        .expect("Failed to execute `zig build-obj`. Ensure zig is installed and in PATH.");

    if !obj_status.success() {
        panic!("`zig build-obj` failed with status: {:?}", obj_status);
    }

    // 2. Archive object into static library with native archiver (libtool on macOS, ar on Linux)
    #[cfg(target_os = "macos")]
    {
        let libtool_status = Command::new("libtool")
            .args(["-static", "-o"])
            .arg(&lib_path)
            .arg(&obj_path)
            .status()
            .expect("Failed to execute `libtool` for static archive");

        if !libtool_status.success() {
            panic!("`libtool -static` failed with status: {:?}", libtool_status);
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let ar_status = Command::new("ar")
            .args(["rcs"])
            .arg(&lib_path)
            .arg(&obj_path)
            .status()
            .expect("Failed to execute `ar` for static archive");

        if !ar_status.success() {
            panic!("`ar rcs` failed with status: {:?}", ar_status);
        }
    }

    println!("cargo:rustc-link-search=native={}", zig_out_lib.display());
    println!("cargo:rustc-link-lib=static=flashrust_zig");

    println!("cargo:rerun-if-changed={}", zig_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        zig_dir.join("build.zig").display()
    );
}
