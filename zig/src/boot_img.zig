const std = @import("std");

pub const ANDROID_BOOT_MAGIC = "ANDROID!";
pub const ANDROID_BOOT_MAGIC_LEN = 8;

pub const BootImgError = error{
    BufferTooSmall,
    InvalidMagic,
    UnsupportedHeaderVersion,
};

pub const BootHeaderVersion = enum(u32) {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
};

pub const BootImageMetadata = struct {
    version: BootHeaderVersion,
    kernel_size: u32,
    ramdisk_size: u32,
    ramdisk_offset: usize,
    page_size: u32,
};

pub fn parseBootImage(data: []const u8) BootImgError!BootImageMetadata {
    if (data.len < 64) {
        return error.BufferTooSmall;
    }

    if (!std.mem.eql(u8, data[0..ANDROID_BOOT_MAGIC_LEN], ANDROID_BOOT_MAGIC)) {
        return error.InvalidMagic;
    }

    // Check version at offset 40 for v3/v4 vs v0-v2
    const v3_header_version = std.mem.readInt(u32, data[40..44], .little);

    if (v3_header_version >= 3 and v3_header_version <= 4) {
        const kernel_size = std.mem.readInt(u32, data[8..12], .little);
        const ramdisk_size = std.mem.readInt(u32, data[12..16], .little);
        const version_enum: BootHeaderVersion = if (v3_header_version == 3) .V3 else .V4;

        // In v3/v4, page size is fixed to 4096.
        // Kernel starts at 4096 (1 page), ramdisk immediately follows kernel aligned to 4096.
        const page_size: u32 = 4096;
        const kernel_pages = (kernel_size + page_size - 1) / page_size;
        const ramdisk_offset: usize = @as(usize, 1 + kernel_pages) * page_size;

        return BootImageMetadata{
            .version = version_enum,
            .kernel_size = kernel_size,
            .ramdisk_size = ramdisk_size,
            .ramdisk_offset = ramdisk_offset,
            .page_size = page_size,
        };
    } else {
        // v0 - v2
        const kernel_size = std.mem.readInt(u32, data[8..12], .little);
        const ramdisk_size = std.mem.readInt(u32, data[16..20], .little);
        const page_size = std.mem.readInt(u32, data[36..40], .little);
        const safe_page_size = if (page_size == 0) 2048 else page_size;

        const header_pages: usize = 1;
        const kernel_pages = (@as(usize, kernel_size) + safe_page_size - 1) / safe_page_size;
        const ramdisk_offset = (header_pages + kernel_pages) * safe_page_size;

        const ver_enum: BootHeaderVersion = switch (v3_header_version) {
            1 => .V1,
            2 => .V2,
            else => .V0,
        };

        return BootImageMetadata{
            .version = ver_enum,
            .kernel_size = kernel_size,
            .ramdisk_size = ramdisk_size,
            .ramdisk_offset = ramdisk_offset,
            .page_size = safe_page_size,
        };
    }
}
