use std::io::BufRead;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

pub fn get_git_config(repo: &Path, name: &str) -> std::io::Result<String> {
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

pub fn git_has_config(repo: &Path, name: &str) -> Result<bool, String> {
    match std::process::Command::new("git")
        .arg("config")
        .arg("--get")
        .arg(name)
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git config --get` failed: {}", e))?
        .status
        .code()
        .unwrap()
    {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err("'git config --get' failed".to_string()),
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
    if git_has_config(repo, "git-crypt.repo_state_dir")? {
        let repo_state_dir_str = get_git_config(repo, "git-crypt.repo_state_dir")
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

pub fn get_internal_keys_path(
    repo: &Path,
    internal_state_path: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, String> {
    let mut isp: std::path::PathBuf = internal_state_path
        .map(|x: &std::path::Path| x.to_path_buf())
        .unwrap_or(
            get_internal_state_path(repo)
                .map_err(|e| format!("failed to get internal keys path: {}", e))?,
        );
    isp.push("keys");
    Ok(isp)
}

pub fn get_internal_key_path(
    repo: &Path,
    key_name: Option<&str>,
) -> Result<std::path::PathBuf, String> {
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

pub fn git_deconfig_section(repo: &Path, name: &str) -> Result<(), String> {
    let output = std::process::Command::new("git")
        .arg("config")
        .arg("--local")
        .arg("--remove-section")
        .arg(name)
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git config --local --remove-section {}` : {}", name, e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!("`git config --local --remove-section {}`", name))
    }
}

pub fn git_checkout(repo: &Path, names: Vec<&str>) -> Result<(), String> {
    let output = std::process::Command::new("git")
        .arg("checkout")
        .arg("--")
        .args(&names)
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git checkout` failed : {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err("`git checkout` failed".to_string())
    }
}

pub fn get_version() -> Result<i32, String> {
    let output = std::process::Command::new("git")
        .arg("version")
        .output()
        .map_err(|e| format!("`git version` failed: {}", e))?;

    let lines: Vec<String> = std::io::BufReader::new(&output.stdout[..])
        .lines()
        .filter_map(Result::ok)
        .collect();
    //let numbers: Vec<&str> = lines[0].split(".").collect();
    let words: Vec<&str> = lines[0].split(" ").collect();
    if words.len() != 3 || words[0] != "git" || words[1] != "version" {
        return Err(format!(
            "get_version expected `git version A.B.C`, got `{}`",
            lines[0]
        ));
    }
    let numbers: Result<Vec<i32>, <i32 as std::str::FromStr>::Err> = words[2]
        .split(".")
        .into_iter()
        .map(|s| s.parse::<i32>())
        .collect();
    let n = numbers.map_err(|e| format!("get version failed to parse numbers: {}", e))?;

    let major = *n.get(0).unwrap_or(&0);
    let minor = *n.get(1).unwrap_or(&0);
    let patch = *n.get(2).unwrap_or(&0);
    Ok((10000 * major) + (100 * minor) + patch)
}

pub fn get_git_status(repo: &Path, out: &mut std::io::Write) -> Result<bool, String> {
    // git status -uno --porcelain
    let output = std::process::Command::new("git")
        .arg("status")
        .arg("-uno")
        .arg("--porcelain")
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git status -uno --porcelain` failed: {}", e))?;

    out.write(&output.stdout).unwrap();
    out.write(&output.stderr).unwrap();

    if output.status.success() {
        Ok(output.stdout.is_empty() && output.stderr.is_empty())
    } else {
        Err("'git status' failed - is this a Git repository?".to_string())
    }
}

pub fn get_path_to_top(repo: &Path) -> Result<PathBuf, String> {
    // git rev-parse --show-cdup
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--show-cdup")
        .current_dir(repo)
        .output()
        .map_err(|e| {
            format!(
                "`git rev-parse --show-cdup` failed to run - is this a Git repository? : {}",
                e
            )
        })?;

    if !output.status.success() {
        return Err(format!(
            "`git rev-parse --show-cdup` failed - is this a Git repository?"
        ));
    }

    let mut b = std::io::BufReader::new(&output.stdout[..]);
    let mut s = String::new();
    b.read_line(&mut s)
        .map_err(|e| format!("failed to read output line: {}", e))?;
    s = s.trim().to_string();

    let path = if s.is_empty() {
        repo.to_path_buf()
    } else {
        repo.join(s)
    };

    path.canonicalize()
        .map_err(|e| format!("failed to canonicalize {:?}: {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_create_test_git_repo() -> Result<::tempfile::TempDir, std::io::Error> {
        let dir = ::tempfile::tempdir()?;

        assert!(::std::process::Command::new("git")
            .arg("init")
            .current_dir(dir.path())
            .output()?
            .status
            .success());

        let pack_dir_path = dir.path().join(Path::new(".git/objects/pack"));
        assert!(pack_dir_path.is_dir());

        Ok(dir)
    }

    #[test]
    fn test_get_git_status() {
        let tempdir = test_create_test_git_repo().unwrap();

        // not a repo
        let not_a_git_repo = ::tempfile::tempdir().unwrap();
        let status = get_git_status(not_a_git_repo.path(), &mut ::std::io::sink());
        assert!(status.is_err());

        // create a first file and commit it
        let mut f = ::std::fs::File::create(tempdir.path().join("somefile")).unwrap();
        f.write_all("some data".as_bytes()).unwrap();
        f.sync_all().unwrap();
        std::process::Command::new("git")
            .arg("add")
            .arg("somefile")
            .current_dir(tempdir.path())
            .output()
            .unwrap();
        std::process::Command::new("git")
            .arg("commit")
            .arg("--no-gpg-sign")
            .arg("-m")
            .arg("test commit please ignore")
            .current_dir(tempdir.path())
            .output()
            .unwrap();

        // should be clean
        let mut status = get_git_status(tempdir.path(), &mut ::std::io::sink());
        assert!(status.is_ok());
        assert_eq!(status.unwrap(), true);

        // change the file
        f.write_all("some data".as_bytes()).unwrap();
        f.sync_all().unwrap();

        // should be dirty
        status = get_git_status(tempdir.path(), &mut ::std::io::sink());
        assert!(status.is_ok());
        assert_eq!(status.unwrap(), false);
    }

    #[test]
    fn test_get_version() {
        let ver = get_version().unwrap();
        assert!(ver > 10805);
    }

    #[test]
    fn test_get_path_to_top() {
        let tempdir = test_create_test_git_repo().unwrap();
        let somedir = tempdir.path().join("somedir");

        ::std::fs::create_dir(&somedir).unwrap();

        assert_eq!(
            tempdir.path().canonicalize().unwrap(),
            get_path_to_top(tempdir.path()).unwrap()
        );
        assert_eq!(
            tempdir.path().canonicalize().unwrap(),
            get_path_to_top(&somedir).unwrap()
        );
    }

    #[test]
    fn test_git_config() {
        let tempdir = test_create_test_git_repo().unwrap();
        let repo = tempdir.path();

        assert_eq!(git_has_config(repo, "foo.bar").unwrap(), false);
        assert!(get_git_config(repo, "foo.bar").is_err());

        git_config(repo, "foo.bar", "somevalue").unwrap();

        assert_eq!(git_has_config(repo, "foo.bar").unwrap(), true);
        assert_eq!(get_git_config(repo, "foo.bar").unwrap(), "somevalue");

        git_deconfig_section(repo, "foo").unwrap();

        assert_eq!(git_has_config(repo, "foo.bar").unwrap(), false);
        assert!(get_git_config(repo, "foo.bar").is_err());
    }
}
