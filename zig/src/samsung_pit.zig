const std = @import("std");

pub const PIT_MAGIC: u32 = 0x12349876;
pub const PIT_HEADER_SIZE: usize = 28;
pub const PIT_ENTRY_SIZE: usize = 132;

pub const FRP_HEADER_MARKER: u32 = 0x19901873;
pub const FRP_DIGEST_SIZE: usize = 32;
pub const FRP_MIN_PARTITION_SIZE: usize = 1040;

pub const PitError = error{
    BufferTooSmall,
    InvalidPitMagic,
    EntryCountOverflow,
    InvalidFrpPartitionSize,
    InvalidFrpHeaderMarker,
};

pub const PitHeader = struct {
    magic: u32,
    entry_count: u32,
    gang_name: [8]u8,
    project_name: [8]u8,
    reserved: u32,
};

pub const PitEntry = struct {
    binary_type: u32,
    device_type: u32,
    identifier: u32,
    attributes: u32,
    update_attributes: u32,
    block_size_or_offset: u32,
    block_count: u32,
    file_offset: u32,
    file_size: u32,
    partition_name: [32]u8,
    flash_filename: [32]u8,
    fota_filename: [32]u8,
};

pub const FrpPartitionInfo = struct {
    header_marker: u32,
    marker_valid: bool,
    data_Block_size: u32,
    oem_unlock_enabled: bool,
    has_credentials: bool,
};

/// Parses a Samsung Odin/Loke PIT (Partition Information Table) binary header in-place.
/// Uses zero heap allocations by slicing directly over the caller-supplied buffer.
pub fn parsePitHeader(data: []const u8) PitError!PitHeader {
    if (data.len < PIT_HEADER_SIZE) {
        return PitError.BufferTooSmall;
    }

    const magic = std.mem.readInt(u32, data[0..4], .little);
    if (magic != PIT_MAGIC) {
        return PitError.InvalidPitMagic;
    }

    const entry_count = std.mem.readInt(u32, data[4..8], .little);
    const required_bytes = PIT_HEADER_SIZE + (@as(usize, entry_count) * PIT_ENTRY_SIZE);
    if (entry_count > 256 or data.len < required_bytes) {
        return PitError.EntryCountOverflow;
    }

    var gang_name: [8]u8 = @splat(0);
    var project_name: [8]u8 = @splat(0);
    @memcpy(&gang_name, data[8..16]);
    @memcpy(&project_name, data[16..24]);
    const reserved = std.mem.readInt(u32, data[24..28], .little);

    return PitHeader{
        .magic = magic,
        .entry_count = entry_count,
        .gang_name = gang_name,
        .project_name = project_name,
        .reserved = reserved,
    };
}

/// Parses a single 132-byte PIT partition entry at `entry_index`.
pub fn parsePitEntry(data: []const u8, entry_index: usize) PitError!PitEntry {
    const hdr = try parsePitHeader(data);
    if (entry_index >= hdr.entry_count) {
        return PitError.EntryCountOverflow;
    }

    const base = PIT_HEADER_SIZE + (entry_index * PIT_ENTRY_SIZE);
    if (base + PIT_ENTRY_SIZE > data.len) {
        return PitError.BufferTooSmall;
    }

    const s = data[base .. base + PIT_ENTRY_SIZE];
    var part_name: [32]u8 = @splat(0);
    var flash_file: [32]u8 = @splat(0);
    var fota_file: [32]u8 = @splat(0);

    @memcpy(&part_name, s[36..68]);
    @memcpy(&flash_file, s[68..100]);
    @memcpy(&fota_file, s[100..132]);

    return PitEntry{
        .binary_type = std.mem.readInt(u32, s[0..4], .little),
        .device_type = std.mem.readInt(u32, s[4..8], .little),
        .identifier = std.mem.readInt(u32, s[8..12], .little),
        .attributes = std.mem.readInt(u32, s[12..16], .little),
        .update_attributes = std.mem.readInt(u32, s[16..20], .little),
        .block_size_or_offset = std.mem.readInt(u32, s[20..24], .little),
        .block_count = std.mem.readInt(u32, s[24..28], .little),
        .file_offset = std.mem.readInt(u32, s[28..32], .little),
        .file_size = std.mem.readInt(u32, s[32..36], .little),
        .partition_name = part_name,
        .flash_filename = flash_file,
        .fota_filename = fota_file,
    };
}

/// Inspects an Android `frp` / `persistent` partition image formatted by AOSP `PersistentDataBlockService`.
/// Layout:
/// - [0..32]: SHA-256 digest
/// - [32..36]: Big-endian magic marker `0x19901873`
/// - [36..40]: Big-endian credential payload length
/// - [len - 1]: `oem_unlock_enabled` flag (`0` = FRP Locked, `1` = Developer OEM Unlock Enabled)
pub fn inspectFrpPartition(data: []const u8) PitError!FrpPartitionInfo {
    if (data.len < FRP_MIN_PARTITION_SIZE) {
        return PitError.InvalidFrpPartitionSize;
    }

    const marker = std.mem.readInt(u32, data[32..36], .big);
    const data_size = std.mem.readInt(u32, data[36..40], .big);
    const oem_byte = data[data.len - 1];
    const marker_valid = (marker == FRP_HEADER_MARKER);

    return FrpPartitionInfo{
        .header_marker = marker,
        .marker_valid = marker_valid,
        .data_Block_size = if (marker_valid) data_size else 0,
        .oem_unlock_enabled = (oem_byte & 0x01) != 0,
        .has_credentials = marker_valid and (data_size > 0),
    };
}
