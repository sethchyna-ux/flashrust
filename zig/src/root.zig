const std = @import("std");

pub const cpio = @import("cpio.zig");
pub const rp2350 = @import("rp2350.zig");
pub const boot_img = @import("boot_img.zig");
pub const selinux = @import("selinux.zig");
pub const samsung_pit = @import("samsung_pit.zig");

pub const VERSION: [:0]const u8 = "0.1.0-alpha";

export fn flashrust_zig_version() [*:0]const u8 {
    return VERSION.ptr;
}

export fn flashrust_zig_parse_cpio_header(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_filesize: *u64,
    out_namesize: *u32,
) c_int {
    const ptr = data_ptr orelse return -1;
    const slice = ptr[0..data_len];
    const header = cpio.parseNewcHeader(slice) catch return -2;
    out_filesize.* = header.filesize;
    out_namesize.* = header.namesize;
    return 0;
}

export fn flashrust_zig_patch_cpio_init(
    input_ptr: ?[*]const u8,
    input_len: usize,
    inject_ptr: ?[*]const u8,
    inject_len: usize,
    out_buf_ptr: ?[*]u8,
    out_buf_cap: usize,
    out_len: *usize,
) c_int {
    const in_slice = (input_ptr orelse return -1)[0..input_len];
    const inj_slice = (inject_ptr orelse return -1)[0..inject_len];
    const out_slice = (out_buf_ptr orelse return -1)[0..out_buf_cap];

    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const written = cpio.patchInitHijack(allocator, in_slice, inj_slice, out_slice) catch |err| switch (err) {
        error.BufferTooShort => return -2,
        error.InvalidMagic => return -3,
        error.InvalidHexField => return -4,
        error.BufferOverflow => return -5,
        error.InitNotFound => return -6,
        error.OutOfMemory => return -7,
        error.InvalidArchive => return -8,
        error.InvalidAdbKey => return -9,
        error.MissingTrailer => return -10,
    };

    out_len.* = written;
    return 0;
}

export fn flashrust_zig_inject_su_binary(
    input_ptr: ?[*]const u8,
    input_len: usize,
    su_ptr: ?[*]const u8,
    su_len: usize,
    path_ptr: ?[*]const u8,
    path_len: usize,
    is_setuid: c_int,
    replace_init: c_int,
    out_buf_ptr: ?[*]u8,
    out_buf_cap: usize,
    out_len: *usize,
) c_int {
    const in_slice = (input_ptr orelse return -1)[0..input_len];
    const su_slice = (su_ptr orelse return -1)[0..su_len];
    const path_slice = (path_ptr orelse return -1)[0..path_len];
    const out_slice = (out_buf_ptr orelse return -1)[0..out_buf_cap];

    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const written = cpio.injectSuBinary(
        allocator,
        in_slice,
        su_slice,
        path_slice,
        is_setuid != 0,
        replace_init != 0,
        out_slice,
    ) catch |err| switch (err) {
        error.BufferTooShort => return -2,
        error.InvalidMagic => return -3,
        error.InvalidHexField => return -4,
        error.BufferOverflow => return -5,
        error.InitNotFound => return -6,
        error.OutOfMemory => return -7,
        error.InvalidArchive => return -8,
        error.InvalidAdbKey => return -9,
        error.MissingTrailer => return -10,
    };

    out_len.* = written;
    return 0;
}

export fn flashrust_zig_inject_adb_preauth(
    input_ptr: ?[*]const u8,
    input_len: usize,
    pubkey_ptr: ?[*]const u8,
    pubkey_len: usize,
    out_buf_ptr: ?[*]u8,
    out_buf_cap: usize,
    out_len: *usize,
) c_int {
    const in_slice = (input_ptr orelse return -1)[0..input_len];
    const key_slice = (pubkey_ptr orelse return -1)[0..pubkey_len];
    const out_slice = (out_buf_ptr orelse return -1)[0..out_buf_cap];

    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const written = cpio.injectAdbPreauth(allocator, in_slice, key_slice, out_slice) catch |err| switch (err) {
        error.BufferTooShort => return -2,
        error.InvalidMagic => return -3,
        error.InvalidHexField => return -4,
        error.BufferOverflow => return -5,
        error.InitNotFound => return -6,
        error.OutOfMemory => return -7,
        error.InvalidArchive => return -8,
        error.InvalidAdbKey => return -9,
        error.MissingTrailer => return -10,
    };

    out_len.* = written;
    return 0;
}

export fn flashrust_zig_parse_boot_image(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_version: *u32,
    out_kernel_size: *u32,
    out_ramdisk_size: *u32,
    out_ramdisk_offset: *usize,
    out_page_size: *u32,
) c_int {
    const ptr = (data_ptr orelse return -1)[0..data_len];
    const meta = boot_img.parseBootImage(ptr) catch |err| switch (err) {
        error.BufferTooSmall => return -2,
        error.InvalidMagic => return -3,
        error.UnsupportedHeaderVersion => return -4,
    };

    out_version.* = @intFromEnum(meta.version);
    out_kernel_size.* = meta.kernel_size;
    out_ramdisk_size.* = meta.ramdisk_size;
    out_ramdisk_offset.* = meta.ramdisk_offset;
    out_page_size.* = meta.page_size;
    return 0;
}

export fn flashrust_zig_inject_selinux_rules(
    policy_ptr: ?[*]const u8,
    policy_len: usize,
    out_buf_ptr: ?[*]u8,
    out_buf_cap: usize,
    out_len: *usize,
) c_int {
    const in_slice = (policy_ptr orelse return -1)[0..policy_len];
    const out_slice = (out_buf_ptr orelse return -1)[0..out_buf_cap];

    const written = selinux.injectPermissiveSuRule(in_slice, out_slice) catch |err| switch (err) {
        error.BufferOverflow => return -2,
        error.BufferTooSmall => return -3,
        error.InvalidMagic => return -4,
        error.PolicyCorrupted => return -5,
    };

    out_len.* = written;
    return 0;
}

export fn flashrust_zig_verify_rp2350_image_def(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_mode: *u32,
) c_int {
    const ptr = data_ptr orelse return -1;
    const slice = ptr[0..data_len];
    const result = rp2350.verifyImageDef(slice) catch |err| switch (err) {
        error.BufferTooSmall => return -2,
        error.InvalidHeaderMagic => return -3,
        error.InvalidFooterMagic => return -4,
        error.InvalidCoreMode => return -5,
        error.UnalignedOffset => return -6,
        error.InvalidWindowIndex => return -7,
    };
    out_mode.* = @intFromEnum(result.mode);
    return 0;
}

export fn flashrust_zig_seal_rp2350_image_def(
    buf_ptr: ?[*]u8,
    buf_len: usize,
    mode_val: u32,
    entry_point: u32,
) c_int {
    const ptr = buf_ptr orelse return -1;
    const slice = ptr[0..buf_len];
    const mode = rp2350.parseCoreMode(mode_val) catch return -2;
    rp2350.sealImageDef(slice, mode, entry_point) catch |err| switch (err) {
        error.BufferTooSmall => return -3,
        error.InvalidHeaderMagic, error.InvalidFooterMagic, error.InvalidCoreMode, error.UnalignedOffset, error.InvalidWindowIndex => return -4,
    };
    return 0;
}

export fn flashrust_zig_calculate_qspi_window(
    window_idx: u32,
    physical_offset: u32,
    out_virtual_base: *u32,
    out_register_val: *u32,
) c_int {
    const cfg = rp2350.calculateQspiWindow(window_idx, physical_offset) catch |err| switch (err) {
        error.InvalidWindowIndex => return -1,
        error.UnalignedOffset => return -2,
        else => return -3,
    };
    out_virtual_base.* = cfg.virtual_base;
    out_register_val.* = cfg.register_val;
    return 0;
}

export fn flashrust_zig_parse_pit_header(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_entry_count: *u32,
    out_gang_8: ?[*]u8,
    out_proj_8: ?[*]u8,
) c_int {
    const ptr = data_ptr orelse return -1;
    const gang_out = out_gang_8 orelse return -1;
    const proj_out = out_proj_8 orelse return -1;
    const hdr = samsung_pit.parsePitHeader(ptr[0..data_len]) catch |err| switch (err) {
        error.BufferTooSmall => return -2,
        error.InvalidPitMagic => return -3,
        error.EntryCountOverflow => return -4,
        else => return -5,
    };
    out_entry_count.* = hdr.entry_count;
    @memcpy(gang_out[0..8], &hdr.gang_name);
    @memcpy(proj_out[0..8], &hdr.project_name);
    return 0;
}

export fn flashrust_zig_parse_pit_entry(
    data_ptr: ?[*]const u8,
    data_len: usize,
    entry_index: usize,
    out_identifier: *u32,
    out_block_offset: *u32,
    out_block_count: *u32,
    out_part_name_32: ?[*]u8,
    out_flash_file_32: ?[*]u8,
) c_int {
    const ptr = data_ptr orelse return -1;
    const part_out = out_part_name_32 orelse return -1;
    const file_out = out_flash_file_32 orelse return -1;
    const entry = samsung_pit.parsePitEntry(ptr[0..data_len], entry_index) catch |err| switch (err) {
        error.BufferTooSmall => return -2,
        error.InvalidPitMagic => return -3,
        error.EntryCountOverflow => return -4,
        else => return -5,
    };
    out_identifier.* = entry.identifier;
    out_block_offset.* = entry.block_size_or_offset;
    out_block_count.* = entry.block_count;
    @memcpy(part_out[0..32], &entry.partition_name);
    @memcpy(file_out[0..32], &entry.flash_filename);
    return 0;
}

export fn flashrust_zig_inspect_frp_partition(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_marker: *u32,
    out_marker_valid: *u32,
    out_data_size: *u32,
    out_oem_unlock_enabled: *u32,
    out_has_credentials: *u32,
) c_int {
    const ptr = data_ptr orelse return -1;
    const info = samsung_pit.inspectFrpPartition(ptr[0..data_len]) catch |err| switch (err) {
        error.InvalidFrpPartitionSize => return -2,
        else => return -3,
    };
    out_marker.* = info.header_marker;
    out_marker_valid.* = if (info.marker_valid) 1 else 0;
    out_data_size.* = info.data_Block_size;
    out_oem_unlock_enabled.* = if (info.oem_unlock_enabled) 1 else 0;
    out_has_credentials.* = if (info.has_credentials) 1 else 0;
    return 0;
}
