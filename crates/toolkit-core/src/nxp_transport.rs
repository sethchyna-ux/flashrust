use crate::error::{FlashrustError, Result};
use serde::{Deserialize, Serialize};

pub const NXP_SDP_WRITE_FILE: u16 = 0x0202;
pub const NXP_SDP_JUMP_ADDRESS: u16 = 0x0b0b;
pub const NXP_SDP_READ_REGISTER: u16 = 0x0101;
pub const NXP_SDP_WRITE_REGISTER: u16 = 0x0201;

pub const DEFAULT_CHUNK_SIZE: usize = 512 * 1024; // 512 KiB chunking

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdpCommandType {
    WriteFile,
    JumpAddress,
    ReadRegister,
    WriteRegister,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpCommandPacket {
    pub cmd_type: SdpCommandType,
    pub address: u32,
    pub format: u8,
    pub byte_count: u32,
    pub data: u32,
}

impl SdpCommandPacket {
    pub fn new_write_file(address: u32, byte_count: u32) -> Self {
        Self {
            cmd_type: SdpCommandType::WriteFile,
            address,
            format: 0,
            byte_count,
            data: 0,
        }
    }

    pub fn new_jump(address: u32) -> Self {
        Self {
            cmd_type: SdpCommandType::JumpAddress,
            address,
            format: 0,
            byte_count: 0,
            data: 0,
        }
    }

    /// Serialize into a 16-byte NXP SDP HID Command Report
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let code = match self.cmd_type {
            SdpCommandType::WriteFile => NXP_SDP_WRITE_FILE,
            SdpCommandType::JumpAddress => NXP_SDP_JUMP_ADDRESS,
            SdpCommandType::ReadRegister => NXP_SDP_READ_REGISTER,
            SdpCommandType::WriteRegister => NXP_SDP_WRITE_REGISTER,
        };

        buf[0..2].copy_from_slice(&code.to_be_bytes());
        buf[2..6].copy_from_slice(&self.address.to_be_bytes());
        buf[6] = self.format;
        buf[7..11].copy_from_slice(&self.byte_count.to_be_bytes());
        buf[11..15].copy_from_slice(&self.data.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashProgress {
    pub bytes_sent: usize,
    pub total_bytes: usize,
    pub percentage: f32,
    pub chunk_index: usize,
    pub total_chunks: usize,
}

pub struct UuuTransport;

impl UuuTransport {
    /// Plan chunked transfer for a binary buffer over USB
    pub fn plan_chunks(data_len: usize, chunk_size: usize) -> Vec<(usize, usize)> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < data_len {
            let len = std::cmp::min(chunk_size, data_len - offset);
            chunks.push((offset, len));
            offset += len;
        }
        chunks
    }

    /// Simulate or execute an in-memory SDP file upload sequence
    pub fn prepare_sdp_upload_sequence(
        target_addr: u32,
        data: &[u8],
        chunk_size: usize,
    ) -> Result<(SdpCommandPacket, Vec<(usize, usize)>)> {
        if data.is_empty() {
            return Err(FlashrustError::StorageValidationError(
                "Cannot stage zero-byte payload to target".into(),
            ));
        }

        let cmd = SdpCommandPacket::new_write_file(target_addr, data.len() as u32);
        let chunks = Self::plan_chunks(data.len(), chunk_size);
        Ok((cmd, chunks))
    }

    /// Construct Fastboot download command packet
    pub fn fastboot_download_cmd(payload_len: usize) -> String {
        format!("download:{:08x}", payload_len)
    }

    /// Construct Fastboot flash command packet
    pub fn fastboot_flash_cmd(partition: &str) -> String {
        format!("flash:{}", partition)
    }
}
