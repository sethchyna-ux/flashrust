const std = @import("std");

pub const IMAGE_DEF_SIZE: usize = 256;
pub const HEADER_MAGIC: u32 = 0xffffded3;
pub const FOOTER_MAGIC: u32 = 0xab123579;
pub const FLASH_VIRTUAL_BASE: u32 = 0x10000000;
pub const QSPI_SUBWINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
pub const QSPI_PAGE_ALIGNMENT: u32 = 4 * 1024; // 4 KiB

pub const CoreMode = enum(u32) {
    ArmSecure = 0x0,
    ArmNonSecure = 0x1,
    RiscVMachine = 0x2,
};

pub const Rp2350Error = error{
    BufferTooSmall,
    InvalidHeaderMagic,
    InvalidFooterMagic,
    InvalidCoreMode,
    UnalignedOffset,
    InvalidWindowIndex,
};

pub const ImageDef = struct {
    mode: CoreMode,
    entry_point: u32,
};

pub const QspiWindowConfig = struct {
    window_idx: u32,
    virtual_base: u32,
    physical_offset: u32,
    register_val: u32,
};

pub fn parseCoreMode(val: u32) Rp2350Error!CoreMode {
    return switch (val) {
        0 => .ArmSecure,
        1 => .ArmNonSecure,
        2 => .RiscVMachine,
        else => error.InvalidCoreMode,
    };
}

pub fn verifyImageDef(data: []const u8) Rp2350Error!ImageDef {
    if (data.len < IMAGE_DEF_SIZE) {
        return error.BufferTooSmall;
    }

    const header_magic = std.mem.readInt(u32, data[0..4], .little);
    if (header_magic != HEADER_MAGIC) {
        return error.InvalidHeaderMagic;
    }

    const footer_magic = std.mem.readInt(u32, data[IMAGE_DEF_SIZE - 4 .. IMAGE_DEF_SIZE], .little);
    if (footer_magic != FOOTER_MAGIC) {
        return error.InvalidFooterMagic;
    }

    const mode_raw = std.mem.readInt(u32, data[4..8], .little);
    const mode = try parseCoreMode(mode_raw);
    const entry = std.mem.readInt(u32, data[8..12], .little);

    return ImageDef{
        .mode = mode,
        .entry_point = entry,
    };
}

pub fn sealImageDef(buffer: []u8, mode: CoreMode, entry_point: u32) Rp2350Error!void {
    if (buffer.len < IMAGE_DEF_SIZE) {
        return error.BufferTooSmall;
    }

    @memset(buffer[0..IMAGE_DEF_SIZE], 0);

    std.mem.writeInt(u32, buffer[0..4], HEADER_MAGIC, .little);
    std.mem.writeInt(u32, buffer[4..8], @intFromEnum(mode), .little);
    std.mem.writeInt(u32, buffer[8..12], entry_point, .little);
    std.mem.writeInt(u32, buffer[IMAGE_DEF_SIZE - 4 .. IMAGE_DEF_SIZE], FOOTER_MAGIC, .little);
}

/// Calculate the RP2350 QSPI hardware address translation window register.
/// Maps virtual address [0x10000000 + window_idx * 4MB] to physical_offset.
pub fn calculateQspiWindow(window_idx: u32, physical_offset: u32) Rp2350Error!QspiWindowConfig {
    if (window_idx >= 4) {
        return error.InvalidWindowIndex;
    }
    if ((physical_offset & (QSPI_PAGE_ALIGNMENT - 1)) != 0) {
        return error.UnalignedOffset;
    }

    const virtual_base = FLASH_VIRTUAL_BASE + (window_idx * QSPI_SUBWINDOW_SIZE);
    // Upper 20 bits of the physical address form the translation register value
    const register_val = physical_offset >> 12;

    return QspiWindowConfig{
        .window_idx = window_idx,
        .virtual_base = virtual_base,
        .physical_offset = physical_offset,
        .register_val = register_val,
    };
}
