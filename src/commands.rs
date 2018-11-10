use std::io::{Error, ErrorKind};
use std::io::{Read, Write};

extern crate crypto;
use commands::crypto::mac::Mac;

extern crate aes_ctr;
use commands::aes_ctr::stream_cipher::generic_array::GenericArray;
use commands::aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use commands::aes_ctr::Aes256Ctr;

const NONCE_LEN: usize = 12;

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
        decrypt_file_to_stdout(&key, header, &mut std::io::stdin())
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

    decrypt_file_to_stdout(&key, header, &mut file)
}

fn decrypt_file_to_stdout(
    key_file: &::key::KeyFile,
    header: [u8; 10 + NONCE_LEN],
    input: &mut std::io::Read,
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
    let mut hmac = crypto::hmac::Hmac::new(crypto::sha1::Sha1::new(), key.hmac_key.as_ref());

    loop {
        let mut buffer: [u8; 1024] = [0; 1024];
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        ctr.apply_keystream(&mut buffer[..count]);
        hmac.input(&buffer[..count]);
        std::io::stdout().write(&buffer[..count])?;
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
