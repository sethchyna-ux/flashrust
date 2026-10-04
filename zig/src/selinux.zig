const std = @import("std");

pub const SELINUX_MAGIC: u32 = 0xf97cff8c;

pub const SelinuxError = error{
    BufferTooSmall,
    InvalidMagic,
    PolicyCorrupted,
    BufferOverflow,
};

pub const KERNELSU_SELINUX_RULES =
    \\allow su * * *
    \\allow init su process transition
    \\allow init su process { siginh rlimitinh noatsecure }
    \\
;

pub fn injectPermissiveSuRule(
    input_policy: []const u8,
    output_buf: []u8,
) SelinuxError!usize {
    if (output_buf.len < input_policy.len + KERNELSU_SELINUX_RULES.len) {
        return error.BufferOverflow;
    }

    // Copy original policy
    @memcpy(output_buf[0..input_policy.len], input_policy);

    // Append KernelSU permissive rules
    const rules_len = KERNELSU_SELINUX_RULES.len;
    @memcpy(output_buf[input_policy.len .. input_policy.len + rules_len], KERNELSU_SELINUX_RULES);

    return input_policy.len + rules_len;
}
