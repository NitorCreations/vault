use std::io::{stdin, BufWriter, Read, Write};
use std::path::Path;
use std::{fmt, io};

use base64::Engine;

use crate::errors::VaultError;

#[derive(Debug, Clone)]
/// Vault supports storing arbitrary data that might not be valid UTF-8.
/// Handle values as either UTF-8 or binary.
pub enum Value {
    Utf8(String),
    Binary(Vec<u8>),
}

impl Value {
    #[must_use]
    /// Create a `Value` from owned raw bytes.
    ///
    /// This will check if the given bytes are valid UTF-8,
    /// and return the corresponding enum value.
    pub fn new(bytes: Vec<u8>) -> Self {
        #[allow(clippy::option_if_let_else)]
        // ^using `map_or` would require cloning buffer
        match std::str::from_utf8(&bytes) {
            Ok(valid_utf8) => Self::Utf8(valid_utf8.to_string()),
            Err(_) => Self::Binary(bytes),
        }
    }

    #[must_use]
    /// Create a `Value` from raw bytes slice.
    ///
    /// This will check if the given bytes are valid UTF-8,
    /// and return the corresponding enum value.
    pub fn from(bytes: &[u8]) -> Self {
        std::str::from_utf8(bytes).map_or_else(
            |_| Self::Binary(Vec::from(bytes)),
            |valid_utf8| Self::Utf8(valid_utf8.to_string()),
        )
    }

    /// Try to decode the value as base64 binary data,
    /// otherwise return UTF-8 string.
    pub fn from_possibly_base64_encoded(value: String) -> Self {
        base64::engine::general_purpose::STANDARD
            .decode(&value)
            .map_or(Self::Utf8(value), Value::Binary)
    }

    /// Read data from given filepath.
    ///
    /// Supports both UTF-8 and non-UTF-8 contents.
    pub fn from_path(path: String) -> Result<Self, VaultError> {
        if let Ok(content) = std::fs::read_to_string(&path) {
            Ok(Self::from_possibly_base64_encoded(content))
        } else {
            let binary_data =
                std::fs::read(&path).map_err(|e| VaultError::FileReadError(path, e))?;

            Ok(Self::Binary(binary_data))
        }
    }

    /// Read data from stdin.
    ///
    /// Supports both UTF-8 and non-UTF-8 input.
    pub fn from_stdin() -> Result<Self, VaultError> {
        let stdin = stdin();
        let mut stdin_lock = stdin.lock();

        // Read raw bytes from stdin
        let mut bytes = Vec::new();
        stdin_lock.read_to_end(&mut bytes)?;
        drop(stdin_lock);

        // Try to convert the raw bytes to a UTF-8 string
        #[allow(clippy::option_if_let_else)]
        // ^using `map_or` would require cloning buffer
        match std::str::from_utf8(&bytes) {
            Ok(valid_utf8) => Ok(Self::from_possibly_base64_encoded(valid_utf8.to_string())),
            Err(_) => Ok(Self::Binary(bytes)),
        }
    }

    /// Returns the data as a byte slice `&[u8]`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Utf8(ref string) => string.as_bytes(),
            Self::Binary(ref bytes) => bytes,
        }
    }

    /// Outputs the data directly to stdout.
    ///
    /// String data is printed.
    /// Binary data is outputted raw.
    pub fn output_to_stdout(&self) -> io::Result<()> {
        match self {
            Self::Utf8(ref string) => {
                print!("{string}");
                Ok(())
            }
            Self::Binary(ref bytes) => {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                handle.write_all(bytes)?;
                handle.flush()
            }
        }
    }

    /// Outputs the data as Base64 to stdout.
    ///
    /// String data is printed as-is.
    /// Binary data is printed as Base64-encoded.
    pub fn output_base64_to_stdout(&self) -> io::Result<()> {
        match self {
            Self::Utf8(ref string) => {
                print!("{string}");
                Ok(())
            }
            Self::Binary(ref bytes) => {
                let base64_encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                print!("{base64_encoded}");
                Ok(())
            }
        }
    }

    /// Outputs the data to the specified file path.
    pub fn output_to_file(&self, path: &Path) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(self.as_bytes())?;
        writer.flush()
    }

    /// Outputs the data as Base64 to the specified file path.
    ///
    /// String data is written as-is.
    /// Binary data is written as Base64-encoded.
    pub fn output_base64_to_file(&self, path: &Path) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        match self {
            Self::Utf8(string) => {
                writer.write_all(string.as_bytes())?;
            }
            Self::Binary(bytes) => {
                writer.write_all(
                    base64::engine::general_purpose::STANDARD
                        .encode(bytes)
                        .as_bytes(),
                )?;
            }
        }

        writer.flush()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(text) => write!(f, "{text}"),
            Self::Binary(data) => {
                for byte in data {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}
