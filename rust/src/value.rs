use std::io::{stdin, BufWriter, Read, Write};
use std::path::Path;
use std::{fmt, io};

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
    /// Create a `Value` from raw bytes.
    ///
    /// This will check if the given bytes are valid UTF-8,
    /// and return the corresponding enum value.
    pub fn new(bytes: &[u8]) -> Self {
        std::str::from_utf8(bytes).map_or_else(
            |_| Self::Binary(Vec::from(bytes)),
            |valid_utf8| Self::Utf8(valid_utf8.to_string()),
        )
    }

    /// Read data from given filepath.
    /// Supports both UTF-8 and non-UTF-8 contents.
    pub fn from_path(path: String) -> Result<Self, VaultError> {
        if let Ok(content) = std::fs::read_to_string(&path) {
            Ok(Self::Utf8(content))
        } else {
            let binary_data =
                std::fs::read(&path).map_err(|e| VaultError::FileReadError(path, e))?;

            Ok(Self::Binary(binary_data))
        }
    }

    /// Read data from stdin.
    /// Supports both UTF-8 and non-UTF-8 input.
    pub fn from_stdin() -> Result<Self, VaultError> {
        let mut buffer = Vec::new();

        let stdin = stdin();
        let mut stdin_lock = stdin.lock();

        // Read raw bytes from stdin
        stdin_lock.read_to_end(&mut buffer)?;

        drop(stdin_lock);

        // Try to convert the raw bytes to a UTF-8 string
        #[allow(clippy::option_if_let_else)]
        // ^using `map_or` would require cloning buffer
        match std::str::from_utf8(&buffer) {
            Ok(valid_utf8) => Ok(Self::Utf8(valid_utf8.to_string())),
            Err(_) => Ok(Self::Binary(buffer)),
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

    /// Outputs the data to the specified file path.
    pub fn output_to_file(&self, path: &Path) -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(self.as_bytes())?;
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
