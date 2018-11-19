use std::io::Seek;
use std::io::{Error, ErrorKind};
use std::io::{Read, Write};

extern crate crypto;
use commands::crypto::hmac::Hmac;
use commands::crypto::mac::Mac;

extern crate aes_ctr;
use commands::aes_ctr::stream_cipher::generic_array::GenericArray;
use commands::aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use commands::aes_ctr::Aes256Ctr;

const NONCE_LEN: usize = 12;
const MAX_CRYPT_BYTES: u64 = (1u64 << 32) * 16;

const MAX_INMEMORY_SIZE: u64 = 8388608;

fn parse_plumbing_options(
    args: Vec<String>,
) -> Result<(Option<String>, Option<String>, Vec<String>), getopts::Fail> {
    let mut opts = getopts::Options::new();
    opts.optopt("k", "key-name", "key name", "KEYNAME");
    opts.optopt("", "key-file", "key path", "KEY_FILE_PATH");

    let matches = opts.parse(args.clone())?;

    Ok((
        matches.opt_str("key-name"),
        matches.opt_str("key-file"),
        matches.free,
    ))
}

// Decrypt contents of stdin and write to stdout
pub fn smudge(args: Vec<String>) {
    if let Err(e) = smudge_run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn smudge_run(args: Vec<String>) -> std::io::Result<()> {
    let (key_name, key_file, _remaining_args) = match parse_plumbing_options(args) {
        Ok(o) => o,
        Err(e) => return Err(Error::new(ErrorKind::Other, format!("{}", e))),
    };

    let key = load_key(key_name, key_file)?;

    let mut header: [u8; 10 + NONCE_LEN] = [0; 10 + NONCE_LEN];
    if std::io::stdin().read(&mut header)? != header.len()
        || !header[..10].iter().eq("\0GITCRYPT\0".as_bytes())
    {
        // File not encrypted - just copy it out to stdout
        eprintln!("git-crypt: Warning: file not encrypted");
        eprintln!(
            "git-crypt: Run 'git-crypt status' to make sure all files are properly encrypted."
        );
        eprintln!("git-crypt: If 'git-crypt status' reports no problems, then an older version of");
        eprintln!("git-crypt: this file may be unencrypted in the repository's history.  If this");
        eprintln!(
            "git-crypt: file contains sensitive information, you can use 'git filter-branch'"
        );
        eprintln!("git-crypt: to remove its old versions from the history.");
        std::io::stdout().write(header.as_ref())?; // include the bytes which we already read
        std::io::copy(&mut std::io::stdin(), &mut std::io::stdout())?;
        Ok(())
    } else {
        decrypt_file_to_stream(&key, header, &mut std::io::stdin(), &mut std::io::stdout())
    }
}

pub fn diff(args: Vec<String>) {
    if let Err(e) = diff_run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn diff_run(args: Vec<String>) -> std::io::Result<()> {
    let (key_name, key_file, remaining_args) = match parse_plumbing_options(args) {
        Ok(o) => o,
        Err(e) => return Err(Error::new(ErrorKind::Other, format!("{}", e))),
    };

    if remaining_args.len() != 1 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "'git-crypt diff' requires 1 positional argument, got {}",
                remaining_args.len()
            ),
        ));
    }

    let key = load_key(key_name, key_file)?;
    let mut file = std::fs::File::open(remaining_args.first().unwrap())?;

    // Read the header to get the nonce and determine if it's actually encrypted
    let mut header: [u8; 10 + NONCE_LEN] = [0; 10 + NONCE_LEN];
    if file.read(&mut header)? != header.len() || !header[..10].iter().eq("\0GITCRYPT\0".as_bytes())
    {
        // File not encrypted - just copy it out to stdout
        std::io::stdout().write(&header[..])?;
        std::io::copy(&mut file, &mut std::io::stdout())?;
        return Ok(());
    }

    decrypt_file_to_stream(&key, header, &mut file, &mut std::io::stdout())
}

fn decrypt_file_to_stream(
    key_file: &::key::KeyFile,
    header: [u8; 10 + NONCE_LEN],
    input: &mut std::io::Read,
    output: &mut std::io::Write,
) -> std::io::Result<()> {
    let mut nonce: [u8; 16] = [0; 16];
    nonce[..12].clone_from_slice(&header[10..]);
    let key_version: u32 = 0; // TODO: get the version from the file header

    let key = if let Some(s) = key_file.entries.get(&key_version) {
        s
    } else {
        return Err(Error::new(
            ErrorKind::Other,
            format!("git-crypt: error: key version {} not available - please unlock with the latest version of the key.", key_version),
        ));
    };

    let key_slice = GenericArray::from_slice(&key.aes_key);
    let nonce_slice = GenericArray::from_slice(&nonce);
    let mut ctr = Aes256Ctr::new(&key_slice, &nonce_slice);
    let mut hmac = Hmac::new(crypto::sha1::Sha1::new(), key.hmac_key.as_ref());

    loop {
        let mut buffer: [u8; 1024] = [0; 1024];
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        ctr.apply_keystream(&mut buffer[..count]);
        hmac.input(&buffer[..count]);
        output.write(&buffer[..count])?;
    }

    if hmac.result().code()[..NONCE_LEN] != nonce[..NONCE_LEN] {
        return Err(Error::new(
            ErrorKind::Other,
            format!("git-crypt: error: encrypted file has been tampered with!"),
        ));
    }

    Ok(())
}

fn load_key(key_name: Option<String>, key_path: Option<String>) -> std::io::Result<::key::KeyFile> {
    let path = key_path.unwrap_or(::git::get_internal_key_path(
        key_name.as_ref().map(|x| x.as_str()),
    )?);

    match ::key::KeyFile::from_file(path.as_str()) {
        Ok(o) => Ok(o),
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!("cannot read key from the given path: {}", e),
        )),
    }
}

// Encrypt contents of stdin and write to stdout
pub fn clean(args: Vec<String>) {
    if let Err(e) = clean_run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn clean_run(args: Vec<String>) -> std::io::Result<()> {
    let (key_name, key_file, _remaining_args) = match parse_plumbing_options(args) {
        Ok(o) => o,
        Err(e) => return Err(Error::new(ErrorKind::Other, format!("{}", e))),
    };

    let key = load_key(key_name, key_file)?;

    encrypt_stream(&key, &mut std::io::stdin(), &mut std::io::stdout())?;
    Ok(())
}

fn encrypt_stream(
    key: &::key::KeyFile,
    input: &mut std::io::Read,
    output: &mut std::io::Write,
) -> std::io::Result<()> {
    let entry = key.get_latest().ok_or(Error::new(
        ErrorKind::Other,
        format!("git-crypt: error: key file is empty"),
    ))?;

    // Read the entire file

    let mut hmac = Hmac::new(crypto::sha1::Sha1::new(), entry.hmac_key.as_ref()); // Calculate the file's SHA1 HMAC as we go
    let mut file_size: u64 = 0; // Keep track of the length, make sure it doesn't get too big
    let mut file_contents: Vec<u8> = Vec::new(); // First 8MB or so of the file go here
    let mut temp_file: Option<std::fs::File> = None; // The rest of the file spills into a temporary file on disk

    let mut buffer: [u8; 1024] = [0; 1024];

    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hmac.input(&buffer[..bytes_read]);
        file_size += bytes_read as u64;

        if file_size <= MAX_INMEMORY_SIZE {
            file_contents.append(&mut Vec::from(&buffer[..bytes_read]));
        } else {
            // FIXME: The file's cleartext is written to tempfile here. This behavior from original
            // C++ git-crypt could possibly leave unencrypted data in temp files.
            if temp_file.is_none() {
                temp_file = Some(::tempfile::tempfile()?);
            }
            temp_file
                .as_mut()
                .unwrap()
                .write(&mut buffer[..bytes_read])?;
        }
    }

    // Make sure the file isn't so large we'll overflow the counter value (which would doom security)
    if file_size > MAX_CRYPT_BYTES {
        return Err(Error::new(
            ErrorKind::Other,
            format!("git-crypt: error: file too long to encrypt securely"),
        ));
    }

    // We use an HMAC of the file as the encryption nonce (IV) for CTR mode.
    // By using a hash of the file we ensure that the encryption is
    // deterministic so git doesn't think the file has changed when it really
    // hasn't.  CTR mode with a synthetic IV is provably semantically secure
    // under deterministic CPA as long as the synthetic IV is derived from a
    // secure PRF applied to the message.  Since HMAC-SHA1 is a secure PRF, this
    // encryption scheme is semantically secure under deterministic CPA.
    //
    // Informally, consider that if a file changes just a tiny bit, the IV will
    // be completely different, resulting in a completely different ciphertext
    // that leaks no information about the similarities of the plaintexts.  Also,
    // since we're using the output from a secure hash function plus a counter
    // as the input to our block cipher, we should never have a situation where
    // two different plaintext blocks get encrypted with the same CTR value.  A
    // nonce will be reused only if the entire file is the same, which leaks no
    // information except that the files are the same.
    //
    // To prevent an attacker from building a dictionary of hash values and then
    // looking up the nonce (which must be stored in the clear to allow for
    // decryption), we use an HMAC as opposed to a straight hash.

    // Note: Hmac_sha1_state::LEN >= Aes_ctr_encryptor::NONCE_LEN

    let digest = hmac.result();
    let mut nonce: [u8; 16] = [0; 16];
    nonce[..12].clone_from_slice(&digest.code()[..12]);

    // Write a header that...
    output.write("\0GITCRYPT\0".as_bytes())?; // ...identifies this as an encrypted file
    output.write(&digest.code()[..NONCE_LEN])?; // ...includes the nonce

    let key_slice = GenericArray::from_slice(&entry.aes_key);
    let nonce_slice = GenericArray::from_slice(&nonce);

    let mut ctr = Aes256Ctr::new(key_slice, nonce_slice);

    ctr.apply_keystream(file_contents.as_mut_slice());
    output.write(file_contents.as_slice())?;

    // Then read from the temporary file if applicable
    if let Some(f) = temp_file.as_mut() {
        f.seek(std::io::SeekFrom::Start(0))?;
        loop {
            let count = f.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            ctr.apply_keystream(&mut buffer[..count]);
            output.write(&buffer[..count])?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commands::crypto::digest::Digest;
    use commands::crypto::md5::Md5;

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
    const TEST_CIPHERTEXT: [u8; 67] = [
        0x00, 0x47, 0x49, 0x54, 0x43, 0x52, 0x59, 0x50, 0x54, 0x00, 0x9f, 0xcb, 0xb5, 0x05, 0xf7,
        0x0a, 0x42, 0x07, 0x42, 0x47, 0xb9, 0x77, 0x7d, 0x51, 0x28, 0xac, 0xda, 0x78, 0x27, 0x31,
        0xfe, 0x5f, 0x2c, 0xe0, 0x26, 0xe3, 0x7d, 0x88, 0xd2, 0x46, 0x1f, 0x9e, 0x40, 0x95, 0x4e,
        0x65, 0xcb, 0x83, 0xa2, 0x8c, 0xc7, 0x57, 0x2e, 0xe6, 0x86, 0x63, 0x25, 0xe2, 0x20, 0x04,
        0x6a, 0x37, 0x89, 0x70, 0xdb, 0x6d, 0x47,
    ];
    const TEST_CLEARTEXT: [u8; 45] = [
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72,
        0x20, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x0a, 0x4e, 0x6f, 0x77, 0x20, 0x77, 0x69, 0x74, 0x68,
        0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x0a,
    ];
    const TEST_LARGE_FILE_PART: &str= "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ";

    #[test]
    fn test_smudge() {
        let key = ::key::KeyFile::from_bytes(&TEST_KEY_DATA[..])
            .expect("expected the key to load successfully");

        let mut header: [u8; 10 + NONCE_LEN] = [0; 10 + NONCE_LEN];
        header.clone_from_slice(&TEST_CIPHERTEXT[..10 + NONCE_LEN]);

        let mut output: Vec<u8> = Vec::new();
        assert!(
            decrypt_file_to_stream(
                &key,
                header,
                &mut &TEST_CIPHERTEXT[10 + NONCE_LEN..],
                &mut output
            ).is_ok()
        );
        assert!(output.as_slice().eq(TEST_CLEARTEXT.as_ref()));
    }

    #[test]
    fn test_encrypt() {
        let key = ::key::KeyFile::from_bytes(&TEST_KEY_DATA[..])
            .expect("expected the key to load successfully");

        let mut output: Vec<u8> = Vec::new();
        assert!(encrypt_stream(&key, &mut &TEST_CLEARTEXT[..], &mut output).is_ok());
        assert!(output.as_slice().eq(TEST_CIPHERTEXT.as_ref()));
    }

    #[test]
    fn test_encrypt_large_file() {
        let key = ::key::KeyFile::from_bytes(&TEST_KEY_DATA[..])
            .expect("expected the key to load successfully");

        let large_file_cleartext = TEST_LARGE_FILE_PART.repeat(18867);

        assert!(large_file_cleartext.len() as u64 > MAX_INMEMORY_SIZE);

        let mut output: Vec<u8> = Vec::new();
        assert!(encrypt_stream(&key, &mut large_file_cleartext.as_bytes(), &mut output).is_ok());

        let mut md5: Md5 = Md5::new();
        md5.input_str(&TEST_LARGE_FILE_PART);
        assert_eq!(
            md5.result_str(),
            "b5f46108920dd7929e2aa44ea2510146".to_string()
        );

        md5 = Md5::new();
        md5.input_str(large_file_cleartext.as_str());
        assert_eq!(
            md5.result_str(),
            "2e2a70aa940169bb89511b57aaf510db".to_string()
        );

        md5 = Md5::new();
        md5.input(output.as_slice());
        assert_eq!(
            md5.result_str(),
            "0a1bb190f005be6a1dd005dc355d1b9c".to_string()
        );
    }
}
