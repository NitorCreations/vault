use std::io::{BufWriter, Write};
use std::path::Path;
use std::{fmt, io};

#[derive(Debug, Clone)]
/// Vault supports storing arbitrary data that might not be valid UTF-8.
/// Handle values as either UTF-8 or binary.
pub enum Value {
    Utf8(String),
    Binary(Vec<u8>),
}

impl Value {
    /// Returns the data as a byte slice (`&[u8]`)
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
        match self {
            Self::Utf8(ref string) => {
                writer.write_all(string.as_bytes())?;
            }
            Self::Binary(ref bytes) => {
                writer.write_all(bytes)?;
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
