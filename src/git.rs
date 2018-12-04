use std::io::BufRead;
use std::io::{Error, ErrorKind};

pub fn get_git_config(repo: &::std::path::Path, name: String) -> std::io::Result<String> {
    // git config --get NAME
    let output = std::process::Command::new("git")
        .arg("config")
        .arg("--get")
        .arg(&name)
        .current_dir(repo)
        .output()?;
    if output.status.success() {
        let mut b = std::io::BufReader::new(&output.stdout[..]);
        let mut buf = String::new();
        b.read_line(&mut buf)?;
        Ok(buf.trim().to_string())
    } else {
        Err(Error::new(
            ErrorKind::Other,
            format!("'git config' missing value for key '{}'", name),
        ))
    }
}

fn get_internal_state_path(repo: &std::path::Path) -> std::io::Result<::std::path::PathBuf> {
    // git rev-parse --git-dir
    // git config --get NAME
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--git-dir")
        .current_dir(repo)
        .output()?;
    if output.status.success() {
        let mut b = std::io::BufReader::new(&output.stdout[..]);
        let mut buf = String::new();
        b.read_line(&mut buf)?;
        Ok(repo.join(buf.trim()).join("git-crypt"))
    } else {
        Err(Error::new(
            ErrorKind::Other,
            format!("'git rev-parse --git-dir' failed - is this a Git repository?"),
        ))
    }
}

fn get_internal_keys_path(
    repo: &::std::path::Path,
    internal_state_path: Option<&std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    let mut isp: std::path::PathBuf = internal_state_path
        .map(|x: &std::path::Path| x.to_path_buf())
        .unwrap_or(get_internal_state_path(repo)?);
    isp.push("keys");
    Ok(isp)
}

pub fn get_internal_key_path(
    repo: &::std::path::Path,
    key_name: Option<&str>,
) -> std::io::Result<std::path::PathBuf> {
    let mut ikp = get_internal_keys_path(repo, None)?;
    ikp.push(key_name.unwrap_or("default"));
    Ok(ikp)
}

pub fn git_config(repo: &::std::path::Path, name: &str, value: &str) -> std::io::Result<()> {
    let output = std::process::Command::new("git")
        .arg("config")
        .arg(name)
        .arg(value)
        .current_dir(repo)
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, format!("'git config' failed")))
    }
}
