use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FlashrustError {
    #[error("Storage validation failed: {0}")]
    StorageValidationError(String),

    #[error("Unknown SoC '{0}' provided for offset calculation")]
    UnknownSoc(String),

    #[error("Unknown board preset '{0}'")]
    UnknownBoardPreset(String),

    #[error("Zig engine error code: {0} ({1})")]
    ZigEngineError(i32, String),

    #[error("Invalid buffer length: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },

    #[error("USB device communication error: {0}")]
    UsbError(String),

    #[error("I/O error: {0}")]
    IoError(String),
}

pub type Result<T> = std::result::Result<T, FlashrustError>;
