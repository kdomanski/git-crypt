use std::io::BufRead;
use std::io::{Error, ErrorKind};

fn get_internal_state_path() -> std::io::Result<String> {
    // git rev-parse --git-dir
    // git config --get NAME
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--git-dir")
        .output()?;
    if output.status.success() {
        let mut b = std::io::BufReader::new(&output.stdout[..]);
        let mut buf = String::new();
        b.read_line(&mut buf)?;
        Ok(format!("{}/git-crypt", buf.trim()))
    } else {
        Err(Error::new(
            ErrorKind::Other,
            format!("'git rev-parse --git-dir' failed - is this a Git repository?"),
        ))
    }
}

fn get_internal_keys_path(internal_state_path: Option<&str>) -> std::io::Result<String> {
    Ok(format!(
        "{}/keys",
        internal_state_path.unwrap_or(get_internal_state_path()?.as_str())
    ))
}

pub fn get_internal_key_path(key_name: Option<&str>) -> std::io::Result<String> {
    Ok(format!(
        "{}/{}",
        get_internal_keys_path(None)?,
        key_name.unwrap_or("default")
    ))
}
