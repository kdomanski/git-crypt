use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Read;

const KEY_NAME_MAX_LEN: usize = 128;
const FORMAT_VERSION: u32 = 2;
const HEADER_FIELD_END: u32 = 0;
const HEADER_FIELD_KEY_NAME: u32 = 1;

const HMAC_KEY_LEN: usize = 64;
const AES_KEY_LEN: usize = 32;

const MAX_FIELD_LEN: usize = 1 << 20;

const KEY_FIELD_END: u32 = 0;
const KEY_FIELD_VERSION: u32 = 1;
const KEY_FIELD_AES_KEY: u32 = 3;
const KEY_FIELD_HMAC_KEY: u32 = 5;

pub enum Error {
    Malformed(String),
    Incompatible,
    IO(std::io::Error),
}

impl std::convert::From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Malformed(s) => write!(f, "malformed data: {}", s),
            Error::Incompatible => write!(f, "incompatible format"),
            Error::IO(e) => write!(f, "I/O error: {}", e),
        }
    }
}

pub struct Entry {
    version: u32,
    pub aes_key: [u8; AES_KEY_LEN],
    pub hmac_key: [u8; HMAC_KEY_LEN],
}

impl Entry {
    fn new() -> Entry {
        Entry {
            version: 0,
            aes_key: [0; AES_KEY_LEN],
            hmac_key: [0; HMAC_KEY_LEN],
        }
    }

    pub fn from_bytes(input: &[u8]) -> Result<(Entry, usize), Error> {
        let mut index: usize = 0;
        let mut entry = Entry::new();
        loop {
            if input[index..].len() < 4 {
                return Err(Error::Malformed(
                    "not enough data left for field type".to_string(),
                ));
            }
            let field_type = as_u32_be(&input[index..index + 4])?;
            index += 4;

            if field_type == KEY_FIELD_END {
                break;
            }

            if input[index..].len() < 4 {
                return Err(Error::Malformed(
                    "not enough data left for field length".to_string(),
                ));
            }
            let field_len = as_u32_be(&input[index..index + 4])? as usize;
            index += 4;

            if field_len > MAX_FIELD_LEN {
                return Err(Error::Malformed("field is too long".to_string()));
            }

            if input[index..].len() < field_len {
                return Err(Error::Malformed(format!(
                    "not enough data left for field data - got {} but need {} more bytes",
                    input[index..].len(),
                    field_len
                )));
            }

            match field_type {
                KEY_FIELD_VERSION => {
                    if field_len != 4 {
                        return Err(Error::Malformed(
                            "key version field is not 4 bytes long".to_string(),
                        ));
                    }

                    entry.version = as_u32_be(&input[index..index + 4])?;
                }
                KEY_FIELD_AES_KEY => {
                    if field_len != AES_KEY_LEN {
                        return Err(Error::Malformed(format!(
                            "AES field must be {} bytes long",
                            AES_KEY_LEN
                        )));
                    }

                    entry
                        .aes_key
                        .copy_from_slice(&input[index..index + AES_KEY_LEN]);
                }
                KEY_FIELD_HMAC_KEY => {
                    if field_len != HMAC_KEY_LEN {
                        return Err(Error::Malformed(format!(
                            "HMAC field must be {} bytes long",
                            HMAC_KEY_LEN
                        )));
                    }

                    entry
                        .hmac_key
                        .copy_from_slice(&input[index..index + HMAC_KEY_LEN]);
                }
                _ => {
                    if field_type & (1 as u32) == 1 {
                        // unknown critical field
                        return Err(Error::Incompatible);
                    }
                    // unknown non-critical field - safe to ignore
                }
            }

            index += field_len;
        }
        Ok((entry, index))
    }

    pub fn store(&self) -> Vec<u8> {
        let mut out = Vec::<u8>::new();

        // Version
        out.extend_from_slice(u32_to_be(KEY_FIELD_VERSION).as_ref());
        out.extend_from_slice(u32_to_be(4).as_ref());
        out.extend_from_slice(u32_to_be(self.version).as_ref());

        // AES key
        out.extend_from_slice(u32_to_be(KEY_FIELD_AES_KEY).as_ref());
        out.extend_from_slice(u32_to_be(AES_KEY_LEN as u32).as_ref());
        out.extend_from_slice(self.aes_key.as_ref());

        // HMAC key
        out.extend_from_slice(u32_to_be(KEY_FIELD_HMAC_KEY).as_ref());
        out.extend_from_slice(u32_to_be(HMAC_KEY_LEN as u32).as_ref());
        out.extend_from_slice(self.hmac_key.as_ref());

        // End
        out.extend_from_slice(u32_to_be(KEY_FIELD_END).as_ref());

        out
    }
}

pub struct KeyFile {
    pub key_name: Option<String>,
    pub entries: HashMap<u32, Entry>,
}

impl KeyFile {
    fn new() -> KeyFile {
        KeyFile {
            key_name: None,
            entries: HashMap::new(),
        }
    }

    pub fn from_file(path: &str) -> Result<KeyFile, Error> {
        let mut file = std::fs::File::open(path)?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        KeyFile::from_bytes(contents.as_slice())
    }

    pub fn from_bytes(input: &[u8]) -> Result<KeyFile, Error> {
        if input.len() < 16 {
            return Err(Error::Malformed(
                "not enough data left for preamble and format".to_string(),
            ));
        }
        if std::str::from_utf8(&input[..12]).unwrap() != "\0GITCRYPTKEY" {
            return Err(Error::Malformed("incorrect preamble".to_string()));
        }
        if as_u32_be(&input[12..16])? != FORMAT_VERSION {
            return Err(Error::Incompatible);
        }

        let mut kf = KeyFile::new();
        let mut index: usize = 16;

        loop {
            if input[index..].len() < 4 {
                return Err(Error::Malformed(
                    "not enough data left for field type".to_string(),
                ));
            }

            let field_type = as_u32_be(&input[index..index + 4])?;
            index += 4;

            if field_type == HEADER_FIELD_END {
                break;
            }

            if input[index..].len() < 4 {
                return Err(Error::Malformed(
                    "not enough data left for field length".to_string(),
                ));
            }
            let field_len = as_u32_be(&input[index..index + 4])? as usize;
            index += 4;

            if field_len > MAX_FIELD_LEN {
                return Err(Error::Malformed("field is too long".to_string()));
            }

            if input[index..].len() < field_len {
                return Err(Error::Malformed(format!(
                    "not enough data left for field data - got {} but need {} more bytes",
                    input[index..].len(),
                    field_len
                )));
            }

            match field_type {
                HEADER_FIELD_KEY_NAME => {
                    kf.key_name = match String::from_utf8(input[index..index + field_len].to_vec())
                    {
                        Ok(o) => Some(o),
                        Err(_) => {
                            return Err(Error::Malformed(
                                "could not convert key name to UTF-8 string".to_string(),
                            ))
                        }
                    };
                }
                _ => {
                    if field_type & (1 as u32) == 1 {
                        // unknown critical field
                        return Err(Error::Incompatible);
                    }
                    // unknown non-critical field - safe to ignore
                }
            }

            index += field_len;
        }

        while !input[index..].is_empty() {
            let (entry, bytes_read) = Entry::from_bytes(&input[index..])?;
            kf.entries.insert(entry.version, entry);
            index += bytes_read;
        }

        return Ok(kf);
    }

    pub fn store(&self) -> Vec<u8> {
        let mut out = Vec::<u8>::new();

        out.extend_from_slice("\0GITCRYPTKEY".as_bytes());
        out.extend_from_slice(u32_to_be(FORMAT_VERSION).as_ref());

        if self.key_name.is_some() {
            let key_name = self.key_name.clone().unwrap();
            out.extend_from_slice(u32_to_be(HEADER_FIELD_KEY_NAME).as_ref());
            out.extend_from_slice(u32_to_be(key_name.len() as u32).as_ref());
            out.extend_from_slice(key_name.as_bytes());
        }

        out.extend_from_slice(u32_to_be(HEADER_FIELD_END).as_ref());

        self.entries
            .values()
            .for_each(|e| out.extend(e.store()));

        out
    }
}

pub fn validate_key_name(key_name: &str) -> std::io::Result<()> {
    if key_name.is_empty() {
        return Err(std::io::Error::new(
            ErrorKind::Other,
            "Key name may not be empty",
        ));
    }

    if key_name == "default" {
        return Err(std::io::Error::new(
            ErrorKind::Other,
            "'default' is not a legal key name",
        ));
    }

    key_name.chars().try_for_each(|c| -> std::io::Result<()> {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            return Ok(());
        } else {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "Key names may contain only A-Z, a-z, 0-9, '-', and '_'",
            ));
        }
    })?;

    if key_name.len() > KEY_NAME_MAX_LEN {
        return Err(std::io::Error::new(
            ErrorKind::Other,
            "Key name is too long",
        ));
    }

    return Ok(());
}

fn as_u32_be(b: &[u8]) -> Result<u32, Error> {
    if b.len() < 4 {
        return Err(Error::Malformed(
            "insufficient bytes for a 32-bit unsigned integer".to_string(),
        ));
    }

    Ok(((b[0] as u32) << 24) + ((b[1] as u32) << 16) + ((b[2] as u32) << 8) + ((b[3] as u32) << 0))
}

fn u32_to_be(u: u32) -> [u8; 4] {
    let bytes: [u8; 4] = unsafe { std::mem::transmute(u.to_be()) };
    bytes
}

#[cfg(test)]
mod tests {
    extern crate base64;

    use super::*;

    #[test]
    fn test_validate_key_name() {
        validate_key_name("some_key-name").expect("expected successful validation");
        validate_key_name("").expect_err("expected err on empty name");
        validate_key_name("default").expect_err("expected err on reserved name 'default'");
        validate_key_name("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").expect("expected successful validation of name at the length limit");
        validate_key_name("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0").expect_err("expected err on name 1 character over limit");
        validate_key_name("some_key+name")
            .expect_err("expected err on name with illegal character");
    }

    #[test]
    fn test_load_store_key() {
        let test_key_data_base64 = "AEdJVENSWVBUS0VZAAAAAgAAAAAAAAABAAAABAAAAAAAAAADAAAAIIp/9dSNepfSiCJY0R6oL0WZdvGOFkGZhU0smvj7RAgyAAAABQAAAEDNBuigXTPrwErydfFRgUFm6VG3Rfxoxl9kUqWIU7serT/VOmwNf92uyANWfkn+eb1MlVn31XJPBv0C3Y80YTatAAAAAA==";
        let test_key_data =
            base64::decode(test_key_data_base64.as_bytes()).expect("decoding base64 failed");

        let key = KeyFile::from_bytes(test_key_data.as_slice())
            .expect("expected the key to load successfully");
        let stored_data = key.store();

        assert!(stored_data.iter().eq(test_key_data.iter()));
    }
}
