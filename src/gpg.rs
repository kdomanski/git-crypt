use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::path::Path;

fn gpg_get_executable(repo: &Path) -> String {
    match ::git::get_git_config(repo, "gpg.program") {
        Ok(o) => o.trim().to_string(),
        Err(_) => String::from("gpg".to_string()),
    }
}

pub fn gpg_list_secret_keys(repo: &Path) -> Result<Vec<String>, String> {
    // gpg --batch --with-colons --list-secret-keys --fingerprint
    let output = std::process::Command::new(gpg_get_executable(repo))
        .arg("--batch")
        .arg("--with-colons")
        .arg("--list-secret-keys")
        .arg("--fingerprint")
        .current_dir(repo) // not really needed, but whatever
        .output()
        .map_err(|e| {
            format!(
                "failed to run gpg --batch --with-colons --list-secret-keys --fingerprint: {}",
                e
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "gpg --batch --with-colons --list-secret-keys --fingerprint failed"
        ));
    }

    let b: BufReader<&[u8]> = std::io::BufReader::new(&output.stdout[..]);

    let fpr_lines: Vec<String> = b
        .lines()
        .filter_map(Result::ok)
        .filter(|x| x.starts_with("fpr:"))
        .collect();
    let fpr_splits = fpr_lines
        .iter()
        .map(|x: &String| x.split(":").collect::<Vec<&str>>());
    Ok(fpr_splits
        .filter_map(|x| x.get(9).map(|x| x.to_string()))
        .collect())
}

pub fn gpg_decrypt_from_file(repo: &Path, filename: &str) -> std::io::Result<Vec<u8>> {
    // gpg -q -d FILENAME
    let output = std::process::Command::new(gpg_get_executable(repo))
        .arg("-q")
        .arg("-d")
        .arg(filename)
        .current_dir(repo)
        .output()?;
    if !output.status.success() {
        let stderr_string = String::from_utf8(output.stderr).unwrap();
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to decrypt: {}", stderr_string),
        ));
    }

    Ok(output.stdout)
}

pub fn gpg_lookup_key(repo: &Path, query: &str) -> Result<Vec<String>, String> {
    // gpg --batch --with-colons --fingerprint --list-keys jsmith@example.com
    let output = std::process::Command::new(gpg_get_executable(repo))
        .arg("--batch")
        .arg("--with-colons")
        .arg("--fingerprint")
        .arg("--list-keys")
        .arg(query)
        .current_dir(repo) // not really needed, but whatever
        .output()
        .map_err(|e| {
            format!(
                "failed to run gpg --batch --with-colons --fingerprint --list-keys {}: {}",
                query, e
            )
        })?;
    if !output.status.success() {
        return Err("gpg --batch --with-colons --fingerprint --list-keys".to_string());
    }

    let mut is_pubkey = false;
    let mut fingerprints: Vec<String> = Vec::new();

    BufReader::new(&output.stdout[..])
        .lines()
        .filter_map(Result::ok)
        .for_each(|line| {
            let columns: Vec<&str> = line.split(":").collect();
            match columns[0] {
                "pub" => {
                    is_pubkey = true;
                }
                "sub" => {
                    is_pubkey = false;
                }
                "fpr" => {
                    if is_pubkey {
                        fingerprints.push(columns[9].to_string());
                    }
                }
                _ => {}
            };
        });

    Ok(fingerprints)
}

pub fn get_key_uid(repo: &Path, fingerprint: &str) -> Result<String, String> {
    // gpg --batch --with-colons --fixed-list-mode --list-keys 0x7A399B2DB06D039020CD1CE1D0F3702D61489532
    let output = std::process::Command::new(gpg_get_executable(repo))
        .arg("--batch")
        .arg("--with-colons")
        .arg("--fingerprint")
        .arg("--list-keys")
        .arg(format!("0x{}", fingerprint))
        .output()
        .map_err(|e| {
            format!(
                "failed to run gpg --batch --with-colons --fingerprint --list-keys 0x{}: {}",
                fingerprint, e
            )
        })?;
    if !output.status.success() {
        return Err("gpg --batch --with-colons --fixed-list-mode --list-keys".to_string());
    }

    for line in BufReader::new(&output.stdout[..])
        .lines()
        .filter_map(Result::ok)
    {
        let columns: Vec<&str> = line.split(":").collect();
        if columns[0] == "uid" {
            return Ok(columns[9].to_string());
        }
    }

    Ok(String::new())
}

pub fn encrypt_to_file(
    repo: &Path,
    filename: &Path,
    recipient_fingerprint: &str,
    key_is_trusted: bool,
    data_to_encrypt: &[u8],
) -> Result<(), String> {
    // gpg --batch -o FILENAME -r RECIPIENT -e
    let mut cmd = std::process::Command::new(gpg_get_executable(repo));

    let mut process = if key_is_trusted {
        cmd.arg("--trust-model").arg("always")
    } else {
        &mut cmd
    }
    .arg("-o")
    .arg(filename.to_str().unwrap())
    .arg("-r")
    .arg(format!("0x{}", recipient_fingerprint))
    .arg("-e")
    .stdin(::std::process::Stdio::piped())
    .current_dir(repo) // not really needed, but whatever
    .spawn()
    .map_err(|e| {
        format!(
            "failed to run gpg --batch -o {} -r 0x{} -e: {}",
            filename.to_str().unwrap_or("FILENAME"),
            recipient_fingerprint,
            e
        )
    })?;

    {
        let mut stdin = process.stdin.as_mut().unwrap();
        let mut writer = ::std::io::BufWriter::new(&mut stdin);

        writer
            .write_all(data_to_encrypt)
            .map_err(|e| format!("failed to feed data to GPG encryption: {}", e))?;
    }

    if !process
        .wait()
        .map_err(|e| format!("failed to wait for GPG encryption: {}", e))?
        .success()
    {
        return Err("GPG encryption failed".to_string());
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    extern crate crypto;
    use gpg::tests::crypto::digest::Digest;
    use gpg::tests::crypto::md5::Md5;

    const TEST_LOREM_IPSUM: &str= "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ";
    pub const TEST_KEY_FINGERPRINT: &str = "26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F";

    #[test]
    fn test_gpg_lookup_key() {
        let dir = ::tempfile::tempdir().unwrap();

        let fingerprints = gpg_lookup_key(dir.path(), "Test Identity <test@example.com>").unwrap();

        assert_eq!(fingerprints.len(), 1);
        assert_eq!(
            fingerprints[0],
            "26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F".to_string()
        );
    }

    #[test]
    fn test_encrypt_to_file() {
        let mut md5: Md5 = Md5::new();
        md5.input_str(&TEST_LOREM_IPSUM);
        assert_eq!(
            md5.result_str(),
            "b5f46108920dd7929e2aa44ea2510146".to_string()
        );

        let dir = ::tempfile::tempdir().unwrap();
        let outfilepath = dir.path().join("somefile");
        encrypt_to_file(
            dir.path(),
            outfilepath.as_path(),
            TEST_KEY_FINGERPRINT,
            true,
            TEST_LOREM_IPSUM.as_bytes(),
        )
        .unwrap();
    }
}
