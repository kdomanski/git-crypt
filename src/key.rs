use std::collections::HashMap;
use std::io::Read;

const KEY_NAME_MAX_LEN: usize = 128;
const FORMAT_VERSION: u32 = 2;
const HEADER_FIELD_END: u32 = 0;
const HEADER_FIELD_KEY_NAME: u32 = 1;

pub const HMAC_KEY_LEN: usize = 64;
pub const AES_KEY_LEN: usize = 32;

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

#[derive(Copy)]
pub struct Entry {
    pub version: u32,
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

    pub fn generate(version: u32) -> Entry {
        use rand::prelude::*;

        let mut rng = StdRng::from_entropy();

        let mut e = Entry {
            version: version,
            aes_key: [0; AES_KEY_LEN],
            hmac_key: [0; HMAC_KEY_LEN],
        };
        rng.fill_bytes(&mut e.aes_key[..]);
        rng.fill_bytes(&mut e.hmac_key[..]);

        e
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

impl Clone for Entry {
    fn clone(&self) -> Entry {
        Entry {
            version: self.version,
            aes_key: self.aes_key,
            hmac_key: self.hmac_key,
        }
    }
}

pub struct KeyFile {
    pub key_name: Option<String>,
    pub entries: HashMap<u32, Entry>,
}

impl KeyFile {
    pub fn new() -> KeyFile {
        KeyFile {
            key_name: None,
            entries: HashMap::new(),
        }
    }

    pub fn generate(name: Option<String>) -> KeyFile {
        let mut kf = KeyFile {
            key_name: name.clone(),
            entries: HashMap::with_capacity(1),
        };

        kf.entries.insert(0, Entry::generate(0));
        kf
    }

    pub fn from_file(path: &::std::path::Path) -> Result<KeyFile, Error> {
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
                            ));
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

        self.entries.values().for_each(|e| out.extend(e.store()));

        out
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get_latest(&self) -> Option<&Entry> {
        if self.is_empty() {
            return None;
        }

        let latest_version = self.entries.keys().into_iter().max().unwrap();
        return Some(&self.entries[latest_version]);
    }
}

pub fn validate_key_name(key_name: &str) -> Result<(), String> {
    if key_name.is_empty() {
        return Err("Key name may not be empty".to_string());
    }

    if key_name == "default" {
        return Err("'default' is not a legal key name".to_string());
    }

    key_name.chars().try_for_each(|c| -> Result<(), String> {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            return Ok(());
        } else {
            return Err("Key names may contain only A-Z, a-z, 0-9, '-', and '_'".to_string());
        }
    })?;

    if key_name.len() > KEY_NAME_MAX_LEN {
        return Err("Key name is too long".to_string());
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
    use super::*;

    const TEST_KEY_DATA: [u8; 148] = [
        0x00, 0x47, 0x49, 0x54, 0x43, 0x52, 0x59, 0x50, 0x54, 0x4b, 0x45, 0x59, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x8a, 0x7f, 0xf5, 0xd4, 0x8d,
        0x7a, 0x97, 0xd2, 0x88, 0x22, 0x58, 0xd1, 0x1e, 0xa8, 0x2f, 0x45, 0x99, 0x76, 0xf1, 0x8e,
        0x16, 0x41, 0x99, 0x85, 0x4d, 0x2c, 0x9a, 0xf8, 0xfb, 0x44, 0x08, 0x32, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x40, 0xcd, 0x06, 0xe8, 0xa0, 0x5d, 0x33, 0xeb, 0xc0, 0x4a, 0xf2,
        0x75, 0xf1, 0x51, 0x81, 0x41, 0x66, 0xe9, 0x51, 0xb7, 0x45, 0xfc, 0x68, 0xc6, 0x5f, 0x64,
        0x52, 0xa5, 0x88, 0x53, 0xbb, 0x1e, 0xad, 0x3f, 0xd5, 0x3a, 0x6c, 0x0d, 0x7f, 0xdd, 0xae,
        0xc8, 0x03, 0x56, 0x7e, 0x49, 0xfe, 0x79, 0xbd, 0x4c, 0x95, 0x59, 0xf7, 0xd5, 0x72, 0x4f,
        0x06, 0xfd, 0x02, 0xdd, 0x8f, 0x34, 0x61, 0x36, 0xad, 0x00, 0x00, 0x00, 0x00,
    ];
    const TEST_KEY_AES: [u8; AES_KEY_LEN] = [
        0x8a, 0x7f, 0xf5, 0xd4, 0x8d, 0x7a, 0x97, 0xd2, 0x88, 0x22, 0x58, 0xd1, 0x1e, 0xa8, 0x2f,
        0x45, 0x99, 0x76, 0xf1, 0x8e, 0x16, 0x41, 0x99, 0x85, 0x4d, 0x2c, 0x9a, 0xf8, 0xfb, 0x44,
        0x08, 0x32,
    ];
    const TEST_KEY_HMAC: [u8; HMAC_KEY_LEN] = [
        0xcd, 0x06, 0xe8, 0xa0, 0x5d, 0x33, 0xeb, 0xc0, 0x4a, 0xf2, 0x75, 0xf1, 0x51, 0x81, 0x41,
        0x66, 0xe9, 0x51, 0xb7, 0x45, 0xfc, 0x68, 0xc6, 0x5f, 0x64, 0x52, 0xa5, 0x88, 0x53, 0xbb,
        0x1e, 0xad, 0x3f, 0xd5, 0x3a, 0x6c, 0x0d, 0x7f, 0xdd, 0xae, 0xc8, 0x03, 0x56, 0x7e, 0x49,
        0xfe, 0x79, 0xbd, 0x4c, 0x95, 0x59, 0xf7, 0xd5, 0x72, 0x4f, 0x06, 0xfd, 0x02, 0xdd, 0x8f,
        0x34, 0x61, 0x36, 0xad,
    ];
    const TEST_KEY_VERSION: u32 = 0;

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
        let key =
            KeyFile::from_bytes(&TEST_KEY_DATA[..]).expect("expected the key to load successfully");

        assert_eq!(key.key_name, None);
        assert_eq!(key.entries.len(), 1);
        assert!(key.entries.contains_key(&0));
        assert_eq!(TEST_KEY_VERSION, key.entries[&0].version);
        assert_eq!(TEST_KEY_AES, key.entries[&0].aes_key);
        assert_eq!(TEST_KEY_HMAC[..], key.entries[&0].hmac_key[..]);

        let stored_data = key.store();

        assert!(stored_data.as_slice().eq(&TEST_KEY_DATA[..]));
    }

    #[test]
    fn test_get_latest() {
        let mut k = KeyFile::new();
        k.entries.insert(
            0,
            Entry {
                version: 0,
                aes_key: [0; AES_KEY_LEN],
                hmac_key: [0; HMAC_KEY_LEN],
            },
        );
        k.entries.insert(
            1,
            Entry {
                version: 1,
                aes_key: [0; AES_KEY_LEN],
                hmac_key: [0; HMAC_KEY_LEN],
            },
        );

        assert_eq!(k.get_latest().unwrap().version, 1);

        k.entries.insert(
            5,
            Entry {
                version: 5,
                aes_key: [0; AES_KEY_LEN],
                hmac_key: [0; HMAC_KEY_LEN],
            },
        );

        assert_eq!(k.get_latest().unwrap().version, 5);

        k.entries.insert(
            3,
            Entry {
                version: 3,
                aes_key: [0; AES_KEY_LEN],
                hmac_key: [0; HMAC_KEY_LEN],
            },
        );

        assert_eq!(k.get_latest().unwrap().version, 5);
    }

    #[test]
    fn test_generate_key() {
        let k = KeyFile::generate(Some("foobar".to_string()));
        assert_eq!(k.entries.len(), 1);
        assert!(k.entries.get(&0).is_some());
        assert_eq!(k.key_name, Some("foobar".to_string()));

        let e = k.get_latest().unwrap();
        assert_eq!(e.version, 0);
        assert_ne!(e.aes_key, [0; AES_KEY_LEN]);
        assert_ne!(&e.hmac_key[..], &[0; HMAC_KEY_LEN][..]);
    }
}
