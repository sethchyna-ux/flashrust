const std = @import("std");

pub const NEWC_MAGIC = "070701";
pub const NEWC_CRC_MAGIC = "070702";
pub const HEADER_LEN: usize = 110;
pub const TRAILER_NAME = "TRAILER!!!";

pub const CpioError = error{
    BufferTooShort,
    InvalidMagic,
    InvalidHexField,
    BufferOverflow,
    InitNotFound,
    OutOfMemory,
};

pub const NewcHeader = struct {
    ino: u32 = 1,
    mode: u32 = 0o100755,
    uid: u32 = 0,
    gid: u32 = 0,
    nlink: u32 = 1,
    mtime: u32 = 0,
    filesize: u64 = 0,
    maj: u32 = 0,
    min: u32 = 0,
    rmaj: u32 = 0,
    rmin: u32 = 0,
    namesize: u32 = 0,
    check: u32 = 0,
};

pub fn align4(val: usize) usize {
    return (val + 3) & ~@as(usize, 3);
}

fn parseHex8(bytes: *const [8]u8) CpioError!u32 {
    return std.fmt.parseInt(u32, bytes, 16) catch error.InvalidHexField;
}

pub fn parseNewcHeader(data: []const u8) CpioError!NewcHeader {
    if (data.len < HEADER_LEN) {
        return error.BufferTooShort;
    }

    const magic = data[0..6];
    if (!std.mem.eql(u8, magic, NEWC_MAGIC) and !std.mem.eql(u8, magic, NEWC_CRC_MAGIC)) {
        return error.InvalidMagic;
    }

    const ino = try parseHex8(data[6..14]);
    const mode = try parseHex8(data[14..22]);
    const uid = try parseHex8(data[22..30]);
    const gid = try parseHex8(data[30..38]);
    const nlink = try parseHex8(data[38..46]);
    const mtime = try parseHex8(data[46..54]);
    const filesize = try parseHex8(data[54..62]);
    const maj = try parseHex8(data[62..70]);
    const min = try parseHex8(data[70..78]);
    const rmaj = try parseHex8(data[78..86]);
    const rmin = try parseHex8(data[86..94]);
    const namesize = try parseHex8(data[94..102]);
    const check = try parseHex8(data[102..110]);

    return NewcHeader{
        .ino = ino,
        .mode = mode,
        .uid = uid,
        .gid = gid,
        .nlink = nlink,
        .mtime = mtime,
        .filesize = filesize,
        .maj = maj,
        .min = min,
        .rmaj = rmaj,
        .rmin = rmin,
        .namesize = namesize,
        .check = check,
    };
}

pub fn formatNewcHeader(buf: *[HEADER_LEN]u8, h: NewcHeader) void {
    @memcpy(buf[0..6], NEWC_MAGIC);
    _ = std.fmt.bufPrint(buf[6..14], "{x:0>8}", .{h.ino}) catch unreachable;
    _ = std.fmt.bufPrint(buf[14..22], "{x:0>8}", .{h.mode}) catch unreachable;
    _ = std.fmt.bufPrint(buf[22..30], "{x:0>8}", .{h.uid}) catch unreachable;
    _ = std.fmt.bufPrint(buf[30..38], "{x:0>8}", .{h.gid}) catch unreachable;
    _ = std.fmt.bufPrint(buf[38..46], "{x:0>8}", .{h.nlink}) catch unreachable;
    _ = std.fmt.bufPrint(buf[46..54], "{x:0>8}", .{h.mtime}) catch unreachable;
    _ = std.fmt.bufPrint(buf[54..62], "{x:0>8}", .{@as(u32, @truncate(h.filesize))}) catch unreachable;
    _ = std.fmt.bufPrint(buf[62..70], "{x:0>8}", .{h.maj}) catch unreachable;
    _ = std.fmt.bufPrint(buf[70..78], "{x:0>8}", .{h.min}) catch unreachable;
    _ = std.fmt.bufPrint(buf[78..86], "{x:0>8}", .{h.rmaj}) catch unreachable;
    _ = std.fmt.bufPrint(buf[86..94], "{x:0>8}", .{h.rmin}) catch unreachable;
    _ = std.fmt.bufPrint(buf[94..102], "{x:0>8}", .{h.namesize}) catch unreachable;
    _ = std.fmt.bufPrint(buf[102..110], "{x:0>8}", .{h.check}) catch unreachable;
}

pub const CpioEntry = struct {
    header: NewcHeader,
    name: []const u8,
    data: []const u8,
};

/// In-memory AST patcher:
/// Scans the CPIO archive, renames "/init" or "init" to "init.real",
/// injects `injected_init_binary` as the new "init" entry (mode 0755, root:root 0:0),
/// and serializes into output_buf.
pub fn patchInitHijack(
    allocator: std.mem.Allocator,
    input_cpio: []const u8,
    injected_init_binary: []const u8,
    output_buf: []u8,
) CpioError!usize {
    var entries: std.ArrayListUnmanaged(CpioEntry) = .empty;
    defer entries.deinit(allocator);

    var offset: usize = 0;
    var found_init = false;

    while (offset + HEADER_LEN <= input_cpio.len) {
        const header = parseNewcHeader(input_cpio[offset..]) catch break;
        const name_start = offset + HEADER_LEN;
        const name_end = name_start + header.namesize;
        if (name_end > input_cpio.len) break;

        const raw_name = input_cpio[name_start..name_end];
        // Strip trailing null if present
        const clean_name = if (raw_name.len > 0 and raw_name[raw_name.len - 1] == 0)
            raw_name[0 .. raw_name.len - 1]
        else
            raw_name;

        const data_start = offset + align4(HEADER_LEN + header.namesize);
        const data_end = data_start + @as(usize, @intCast(header.filesize));
        if (data_end > input_cpio.len) break;

        const entry_data = input_cpio[data_start..data_end];

        if (std.mem.eql(u8, clean_name, "init") or std.mem.eql(u8, clean_name, "/init")) {
            found_init = true;
            // Rename to init.real
            var mod_header = header;
            const new_name = "init.real";
            mod_header.namesize = @as(u32, @intCast(new_name.len + 1));
            // Enforce root:root (0:0) and executable permissions (0o100755)
            mod_header.uid = 0;
            mod_header.gid = 0;
            mod_header.mode = 0o100755;

            entries.append(allocator, .{
                .header = mod_header,
                .name = new_name,
                .data = entry_data,
            }) catch return error.OutOfMemory;
        } else {
            entries.append(allocator, .{
                .header = header,
                .name = clean_name,
                .data = entry_data,
            }) catch return error.OutOfMemory;
        }

        if (std.mem.eql(u8, clean_name, TRAILER_NAME)) {
            break;
        }

        offset = data_start + align4(@as(usize, @intCast(header.filesize)));
    }

    if (!found_init) {
        return error.InitNotFound;
    }

    // Now inject the new "init" entry before TRAILER!!!
    var trailer_idx: usize = entries.items.len;
    for (entries.items, 0..) |item, idx| {
        if (std.mem.eql(u8, item.name, TRAILER_NAME)) {
            trailer_idx = idx;
            break;
        }
    }

    const injected_entry = CpioEntry{
        .header = NewcHeader{
            .ino = 100,
            .mode = 0o100755, // rwxr-xr-x regular file
            .uid = 0,         // root
            .gid = 0,         // root
            .nlink = 1,
            .mtime = 0,
            .filesize = injected_init_binary.len,
            .namesize = 5, // "init\x00" = 5 bytes
            .check = 0,
        },
        .name = "init",
        .data = injected_init_binary,
    };

    if (trailer_idx < entries.items.len) {
        entries.insert(allocator, trailer_idx, injected_entry) catch return error.OutOfMemory;
    } else {
        entries.append(allocator, injected_entry) catch return error.OutOfMemory;
    }

    // Direct buffer write
    var cursor: usize = 0;

    for (entries.items) |e| {
        // 1. Header
        if (cursor + HEADER_LEN > output_buf.len) return error.BufferOverflow;
        var header_bytes: [HEADER_LEN]u8 = undefined;
        formatNewcHeader(&header_bytes, e.header);
        @memcpy(output_buf[cursor .. cursor + HEADER_LEN], &header_bytes);
        cursor += HEADER_LEN;

        // 2. Name + null
        if (cursor + e.name.len + 1 > output_buf.len) return error.BufferOverflow;
        @memcpy(output_buf[cursor .. cursor + e.name.len], e.name);
        cursor += e.name.len;
        output_buf[cursor] = 0;
        cursor += 1;

        // 3. Name pad
        const name_pad = align4(HEADER_LEN + e.header.namesize) - (HEADER_LEN + e.header.namesize);
        if (cursor + name_pad > output_buf.len) return error.BufferOverflow;
        @memset(output_buf[cursor .. cursor + name_pad], 0);
        cursor += name_pad;

        // 4. Data
        if (cursor + e.data.len > output_buf.len) return error.BufferOverflow;
        @memcpy(output_buf[cursor .. cursor + e.data.len], e.data);
        cursor += e.data.len;

        // 5. Data pad
        const data_pad = align4(e.data.len) - e.data.len;
        if (cursor + data_pad > output_buf.len) return error.BufferOverflow;
        @memset(output_buf[cursor .. cursor + data_pad], 0);
        cursor += data_pad;
    }

    return cursor;
}
