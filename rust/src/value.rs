use std::fmt;
use std::io::{stdin, BufWriter, Read, Write};
use std::path::Path;

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

    /// Create a `Value` from a string,
    /// and try to decode the value as base64 binary data.
    ///
    /// If the decoded result is valid UTF-8, return `Value::Utf8`.
    /// Otherwise, return `Value::Binary`.
    #[must_use]
    pub fn from_possibly_base64_encoded(value: String) -> Self {
        #[allow(clippy::option_if_let_else)]
        // ^using `map_or` would require cloning buffer
        base64::engine::general_purpose::STANDARD
            .decode(&value)
            .map_or(
                Self::Utf8(value),
                |decoded_bytes| match std::str::from_utf8(&decoded_bytes) {
                    Ok(utf8) => Self::Utf8(utf8.to_string()),
                    Err(_) => Self::Binary(decoded_bytes),
                },
            )
    }

    /// Read data from given filepath.
    ///
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
            Ok(valid_utf8) => Ok(Self::Utf8(valid_utf8.trim().to_string())),
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
    pub fn output_to_stdout(&self) -> std::io::Result<()> {
        match self {
            Self::Utf8(ref string) => {
                print!("{string}");
                std::io::stdout().flush()?;
                Ok(())
            }
            Self::Binary(ref bytes) => {
                let stdout = std::io::stdout();
                let mut handle = stdout.lock();
                handle.write_all(bytes)?;
                handle.flush()
            }
        }
    }

    /// Outputs the data to the specified file path.
    pub fn output_to_file(&self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(self.as_bytes())?;
        writer.flush()
    }

    #[must_use]
    /// Try to decode UTF-8 string from base64.
    pub fn decode_base64(self) -> Self {
        if let Self::Utf8(string) = self {
            Self::from_possibly_base64_encoded(string)
        } else {
            self
        }
    }

    #[must_use]
    /// Encode binary data to base64.
    ///
    /// Valid UTF-8 won't be encoded.
    pub fn encode_base64(self) -> Self {
        if let Self::Binary(bytes) = self {
            Self::Utf8(base64::engine::general_purpose::STANDARD.encode(bytes))
        } else {
            self
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(text) => write!(f, "{text}"),
            Self::Binary(bytes) => {
                write!(
                    f,
                    "{}",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Value;
    use base64::Engine;

    #[test]
    fn new_valid_utf8() {
        let input = b"Hello, world!".to_vec();
        let value = Value::new(input);
        match value {
            Value::Utf8(string) => assert_eq!(string, "Hello, world!"),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn new_invalid_utf8() {
        // Invalid UTF-8 byte sequence
        let input = vec![0xff, 0xfe, 0xfd];
        let value = Value::new(input.clone());
        match value {
            Value::Utf8(_) => panic!("Expected Binary, got Utf8"),
            Value::Binary(bytes) => assert_eq!(bytes, input),
        }
    }

    #[test]
    fn from_valid_utf8() {
        let input = b"Valid UTF-8";
        let value = Value::from(input);
        match value {
            Value::Utf8(string) => assert_eq!(string, "Valid UTF-8"),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn from_invalid_utf8() {
        let input = &[0xff, 0xfe, 0xfd];
        let value = Value::from(input);
        match value {
            Value::Utf8(_) => panic!("Expected Binary, got Utf8"),
            Value::Binary(bytes) => assert_eq!(bytes, input.to_vec()),
        }
    }

    #[test]
    fn from_possibly_base64_encoded_valid_utf8() {
        // Base64-encoded valid UTF-8 string
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode("Hello, world!");
        let value = Value::from_possibly_base64_encoded(base64_encoded);
        match value {
            Value::Utf8(string) => assert_eq!(string, "Hello, world!"),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn from_possibly_base64_encoded_binary() {
        // Base64-encoded binary data
        let binary_data = vec![0xff, 0xfe, 0xfd];
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&binary_data);
        let value = Value::from_possibly_base64_encoded(base64_encoded);
        match value {
            Value::Utf8(_) => panic!("Expected Binary, got Utf8"),
            Value::Binary(bytes) => assert_eq!(bytes, binary_data),
        }
    }

    #[test]
    fn from_possibly_base64_encoded_invalid_base64() {
        // Non-base64-encoded string
        let invalid_base64 = "NotBase64Data".to_string();
        let value = Value::from_possibly_base64_encoded(invalid_base64.clone());
        match value {
            Value::Utf8(string) => assert_eq!(string, invalid_base64),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn decode_base64_valid_utf8() {
        // Base64-encoded valid UTF-8 string
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode("Hello, world!");
        let value = Value::Utf8(base64_encoded);

        let decoded_value = value.decode_base64();
        match decoded_value {
            Value::Utf8(string) => assert_eq!(string, "Hello, world!"),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn decode_base64_binary_data() {
        // Base64-encoded binary data
        let binary_data = vec![0xde, 0xad, 0xbe, 0xef];
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(&binary_data);
        let value = Value::Utf8(base64_encoded);

        let decoded_value = value.decode_base64();
        match decoded_value {
            Value::Binary(bytes) => assert_eq!(bytes, binary_data),
            Value::Utf8(_) => panic!("Expected Binary, got Utf8"),
        }
    }

    #[test]
    fn decode_base64_invalid_base64() {
        // Non-base64-encoded string
        let invalid_base64 = "InvalidBase64Data".to_string();
        let value = Value::Utf8(invalid_base64.clone());

        let decoded_value = value.decode_base64();
        match decoded_value {
            Value::Utf8(string) => assert_eq!(string, invalid_base64),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn decode_base64_binary_value() {
        // Binary data should not be decoded
        let binary_data = vec![0xde, 0xad, 0xbe, 0xef];
        let value = Value::Binary(binary_data.clone());

        let decoded_value = value.decode_base64();
        match decoded_value {
            Value::Binary(bytes) => assert_eq!(bytes, binary_data),
            Value::Utf8(_) => panic!("Expected Binary, got Utf8"),
        }
    }

    #[test]
    fn encode_base64_binary_data() {
        // Binary data to Base64
        let binary_data = vec![0xde, 0xad, 0xbe, 0xef];
        let value = Value::Binary(binary_data.clone());

        let encoded_value = value.encode_base64();
        match encoded_value {
            Value::Utf8(encoded_string) => {
                let expected_base64 =
                    base64::engine::general_purpose::STANDARD.encode(&binary_data);
                assert_eq!(encoded_string, expected_base64);
            }
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }

    #[test]
    fn encode_base64_utf8_value() {
        // UTF-8 data should not be encoded
        let utf8_string = "Hello, world!".to_string();
        let value = Value::Utf8(utf8_string.clone());

        let encoded_value = value.encode_base64();
        match encoded_value {
            Value::Utf8(string) => assert_eq!(string, utf8_string),
            Value::Binary(_) => panic!("Expected Utf8, got Binary"),
        }
    }
}
