use std::io::BufRead;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

pub fn get_git_config(repo: &Path, name: String) -> std::io::Result<String> {
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

fn git_has_config(repo: &Path, name: String) -> Result<bool, String> {
    match std::process::Command::new("git")
        .arg("config")
        .arg("--get")
        .arg(&name)
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git config --get` failed: {}", e))?
        .status
        .code()
        .unwrap()
    {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err("'git config' failed".to_string()),
    }
}

pub fn get_repo_state_path(repo: &Path) -> Result<PathBuf, String> {
    // git rev-parse --show-toplevel
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git status -uno --porcelain` failed: {}", e))?;;

    if !output.status.success() {
        return Err(
            "'git rev-parse --show-toplevel' failed - is this a Git repository?".to_string(),
        );
    }

    let mut b = std::io::BufReader::new(&output.stdout[..]);
    let mut path_string = String::new();
    b.read_line(&mut path_string).map_err(|e| {
        format!(
            "failed to parse output of `git rev-parse --show-toplevel`: {}",
            e
        )
    })?;

    path_string = path_string.trim().to_string();
    if path_string.is_empty() {
        // could happen for a bare repo
        return Err("Could not determine Git working tree - is this a non-bare repo?".to_string());
    }

    let path = Path::new(&path_string);

    // Check if the repo state dir has been explicitly configured. If so, use that in path construction.
    if git_has_config(repo, "git-crypt.repo_state_dir".to_string())? {
        let repo_state_dir_str = get_git_config(repo, "git-crypt.repo_state_dir".to_string())
            .map_err(|e| format!("get_repo_state_path->git_has_config: {}", e))?;
        let repo_state_dir = Path::new(&repo_state_dir_str);

        // The repo_state_dir value must always be relative to git work tree to ensure the repo_state_dir can be committed
        // along with the remainder of the repository.
        Ok(path.join(repo_state_dir))
    } else {
        // There is no explicitly configured repo state dir configured, so use the default.
        Ok(path.join(".git-crypt"))
    }
}

fn get_internal_state_path(repo: &std::path::Path) -> std::io::Result<::std::path::PathBuf> {
    // git rev-parse --git-dir
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
    repo: &Path,
    internal_state_path: Option<&std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    let mut isp: std::path::PathBuf = internal_state_path
        .map(|x: &std::path::Path| x.to_path_buf())
        .unwrap_or(get_internal_state_path(repo)?);
    isp.push("keys");
    Ok(isp)
}

pub fn get_internal_key_path(
    repo: &Path,
    key_name: Option<&str>,
) -> std::io::Result<std::path::PathBuf> {
    let mut ikp = get_internal_keys_path(repo, None)?;
    ikp.push(key_name.unwrap_or("default"));
    Ok(ikp)
}

pub fn git_config(repo: &Path, name: &str, value: &str) -> std::io::Result<()> {
    let output = std::process::Command::new("git")
        .arg("config")
        .arg("--local")
        .arg(name)
        .arg(value)
        .current_dir(repo)
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Other,
            format!("'git config --local' failed"),
        ))
    }
}
