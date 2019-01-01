use std::io::BufRead;
use std::io::Seek;
use std::io::{BufReader, Read, Write};
use std::io::{Error, ErrorKind};
use std::path::Path;

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

pub fn status(args: Vec<String>, repo: &Path) -> Result<(), String> {
    // Usage:
    //  git-crypt status -r [-z]			Show repo status
    //  git-crypt status [-e | -u] [-z] [FILE ...]	Show encrypted status of files
    //  git-crypt status -f				Fix unencrypted blobs
    let mut opts = getopts::Options::new();
    opts.optflag("r", "", "");
    opts.optflag("e", "", "");
    opts.optflag("u", "", "");
    opts.optflag("f", "fix", "");
    opts.optflag("z", "", "");

    let matches = opts.parse(args.clone()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        ::help_status();
        std::process::exit(2);
    });

    let repo_status_only = matches.opt_present("r"); // -r show repo status only
    let show_encrypted_only = matches.opt_present("e"); // -e show encrypted files only
    let show_unencrypted_only = matches.opt_present("u"); // -u show unencrypted files only
    let fix_problems = matches.opt_present("fix"); // -f fix problems
    let machine_output = matches.opt_present("z"); // -z machine-parseable output

    if repo_status_only {
        if show_encrypted_only || show_unencrypted_only {
            eprintln!("Error: -e and -u options cannot be used with -r");
            ::help_status();
            ::std::process::exit(2);
        }
        if fix_problems {
            eprintln!("Error: -f option cannot be used with -r");
            ::help_status();
            ::std::process::exit(2);
        }
        if !matches.free.is_empty() {
            eprintln!("Error: filenames cannot be specified when -r is used");
            ::help_status();
            ::std::process::exit(2);
        }
    }

    if show_encrypted_only && show_unencrypted_only {
        eprintln!("Error: -e and -u options are mutually exclusive");
        ::help_status();
        ::std::process::exit(2);
    }

    if fix_problems && (show_encrypted_only || show_unencrypted_only) {
        eprintln!("Error: -e and -u options cannot be used with -f");
        ::help_status();
        ::std::process::exit(2);
    }

    if machine_output {
        // TODO: implement machine-parseable output
        unimplemented!("Sorry, machine-parseable output is not yet implemented");
    }

    if matches.free.is_empty() {
        // TODO: check repo status:
        //	is it set up for git-crypt?
        //	which keys are unlocked?
        //	--> check for filter config (see configure_git_filters()) and corresponding internal key
        if repo_status_only {
            return Ok(());
        }
    }

    status_run(
        repo,
        matches.free,
        fix_problems,
        show_encrypted_only,
        show_unencrypted_only,
    )
}

fn blob_is_encrypted(repo: &Path, name: &str) -> Result<bool, String> {
    // git cat-file blob object_id
    let output = std::process::Command::new("git")
        .arg("cat-file")
        .arg("blob")
        .arg(name)
        .current_dir(repo)
        .output()
        .map_err(|e| {
            format!(
                "`git cat-file blob object_id {}` failed to run: {}",
                name, e
            )
        })?;;

    if output.status.success() {
        Ok(&output.stdout[..10] == "\0GITCRYPT\0".as_bytes())
    } else {
        Err(format!("'`git cat-file blob object_id {}` failed", name))
    }
}

fn file_is_encrypted(repo: &Path, name: &str) -> Result<bool, String> {
    // git ls-files -sz filename
    let output = std::process::Command::new("git")
        .arg("ls-files")
        .arg("-sz")
        .arg("--")
        .arg(name)
        .current_dir(repo)
        .output()
        .map_err(|e| format!("`git ls-files -sz {}` failed to run: {}", name, e))?;

    if output.status.success() {
        let mut b = std::io::BufReader::new(&output.stdout[..]);
        let mut buf = String::new();
        b.read_line(&mut buf)
            .map_err(|e| format!("file_is_encrypted(): failed to read output line: {}", e))?;
        let split = buf.split_whitespace().collect::<Vec<&str>>();
        let object_id = split[1];
        blob_is_encrypted(repo, object_id)
    } else {
        Err(format!("'`git cat-file blob object_id {}` failed", name))
    }
}

fn status_run(
    repo: &Path,
    args: Vec<String>,
    fix_problems: bool,
    show_encrypted_only: bool,
    show_unencrypted_only: bool,
) -> Result<(), String> {
    // git ls-files -cotsz --exclude-standard ...
    let mut cmd = std::process::Command::new("git");
    let o1 = cmd
        .arg("ls-files")
        .arg("-cotsz")
        .arg("--exclude-standard")
        .arg("--");
    let output = if args.is_empty() {
        let path_to_top = ::git::get_path_to_top(repo)?;
        o1.arg(path_to_top.to_str().unwrap())
    } else {
        o1.args(args)
    }
    .current_dir(repo)
    .output()
    .map_err(|e| format!("`git ls-files -cotsz --exclude-standard ...` failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "`git ls-files -cotsz --exclude-standard ...` failed"
        ));
    }

    // Output looks like (w/o newlines):
    // ? .gitignore\0
    // H 100644 06ec22e5ed0de9280731ef000a10f9c3fbc26338 0     afile\0

    let mut output_buffered: BufReader<&[u8]> = std::io::BufReader::new(&output.stdout[..]);

    let mut nbr_of_fixed_blobs: u32 = 0;
    let mut nbr_of_fix_errors: u32 = 0;
    let mut attribute_errors: bool = false;
    let mut unencrypted_blob_errors: bool = false;

    let mut chkattr = start_chkattr(repo)?;
    // FIXME extra scope to drop stdin/stdout mut references before wait()
    {
        let mut chkattrstdin = chkattr.stdin.as_mut().unwrap();
        let chkattrstdout = chkattr.stdout.as_mut().unwrap();
        let mut chkattrstdout_buffered = std::io::BufReader::new(chkattrstdout);

        loop {
            let mut data: Vec<u8> = Vec::new();
            let n = output_buffered
                .read_until(b'\0', &mut data)
                .map_err(|e| format!("failed to read `git ls-files ...` output: {}", e))?;
            if n == 0 {
                break;
            }

            let line = std::str::from_utf8(&data[..])
                .map_err(|e| format!("failed to convert command output to UTF-8: {}", e))?
                .trim_matches(char::from(0))
                .to_string();
            let split: Vec<&str> = line.split_whitespace().collect();

            let mut object_id: Option<&str> = None;
            let tag = split[0];
            let filename = match tag {
                "?" => split[1],
                _ => {
                    let mode = split[1]
                        .parse::<u32>()
                        .map_err(|e| format!("failed to parse mode '{}': {}", split[0], e))?;
                    object_id = Some(split[2]);
                    if !is_git_file_mode(mode) {
                        continue;
                    }
                    split[4]
                }
            };

            let (filter_attr, diff_attr) =
                get_file_attributes(&mut chkattrstdout_buffered, &mut chkattrstdin, filename)?;

            let is_encrypted = match filter_attr.as_ref().map(String::as_str) {
                None => false,
                Some("git-crypt") => true,
                Some(s) => s.starts_with("git-crypt-"),
            };

            if is_encrypted {
                // File is encrypted
                let blob_is_unencrypted =
                    object_id.is_some() && !blob_is_encrypted(repo, object_id.unwrap())?;

                if fix_problems && blob_is_unencrypted {
                    if !Path::new(filename).exists() {
                        eprintln!("Error: {}: cannot stage encrypted version because not present in working tree - please 'git rm' or 'git checkout' it", filename);
                        nbr_of_fix_errors = nbr_of_fix_errors + 1;
                    } else {
                        touch_file(Path::new(filename))?;

                        let add_output = std::process::Command::new("git")
                            .arg("add")
                            .arg("--")
                            .arg(filename)
                            .current_dir(repo)
                            .output()
                            .map_err(|e| format!("failed to run `git add`: {}", e))?;

                        if !add_output.status.success() {
                            let stderr_string = String::from_utf8(add_output.stderr).unwrap();
                            return Err(format!("failed to git add: {}", stderr_string));
                        }

                        if file_is_encrypted(repo, filename)? {
                            eprintln!("{}: staged encrypted version", filename);
                            nbr_of_fixed_blobs = nbr_of_fixed_blobs + 1;
                        } else {
                            eprintln!("Error: {}: still unencrypted even after staging", filename);
                            nbr_of_fix_errors = nbr_of_fix_errors + 1;
                        }
                    }
                } else if !fix_problems && !show_unencrypted_only {
                    // TODO: output the key name used to encrypt this file
                    eprintln!("    encrypted: {}", filename);
                    if diff_attr != filter_attr {
                        // but diff filter is not properly set
                        eprintln!(
                            " *** WARNING: diff={} attribute not set ***",
                            filter_attr.unwrap_or("LOGIC_ERROR".to_string())
                        );
                        attribute_errors = true;
                    }
                    if blob_is_unencrypted {
                        // File not actually encrypted
                        eprintln!(" *** WARNING: staged/committed version is NOT ENCRYPTED! ***");
                        unencrypted_blob_errors = true;
                    }
                }
            } else {
                // File not encrypted
                if !fix_problems && !show_encrypted_only {
                    eprintln!("not encrypted: {}", filename);
                }
            }
        }
    }

    let status = chkattr.wait().map_err(|e| {
        format!(
            "`git check-attr --stdin -z filter diff` failed to terminate: {}",
            e
        )
    })?;
    if !status.success() {
        return Err(format!(
            "`git check-attr --stdin -z filter diff` returned non-zero status"
        ));
    }

    if attribute_errors {
        eprintln!(
            "
Warning: one or more files has a git-crypt filter attribute but not a\
corresponding git-crypt diff attribute.  For proper 'git diff' operation
you should fix the .gitattributes file to specify the correct diff attribute.
Consult the git-crypt documentation for help."
        );
    }

    if unencrypted_blob_errors {
        eprintln!(
            "
Warning: one or more files is marked for encryption via .gitattributes but
was staged and/or committed before the .gitattributes file was in effect.
Run 'git-crypt status' with the '-f' option to stage an encrypted version."
        );
    }

    if nbr_of_fixed_blobs != 0 {
        let s = if nbr_of_fixed_blobs == 1 { "" } else { "s" };
        eprintln!("Staged {} encrypted file{}.", nbr_of_fixed_blobs, s);
        eprintln!("Warning: if these files were previously committed, unencrypted versions still exist in the repository's history.");
    }

    if nbr_of_fix_errors != 0 {
        let s = if nbr_of_fix_errors == 1 { "" } else { "s" };
        eprintln!("Unable to stage {} file{}.", nbr_of_fix_errors, s);
    }

    if attribute_errors || unencrypted_blob_errors || nbr_of_fix_errors != 0 {
        Err(String::new())
    } else {
        Ok(())
    }
}

pub fn export_key(args: Vec<String>, repo: &Path) -> Result<(), String> {
    let mut opts = getopts::Options::new();
    opts.optopt("k", "key-name", "key name", "KEYNAME");

    let matches = opts.parse(args.clone()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        ::help_export_key();
        std::process::exit(2);
    });

    let key_name = matches.opt_str("key-name");

    if matches.free.len() != 1 {
        eprintln!("Error: no filename specified");
        ::help_export_key();
        std::process::exit(2);
    }

    let target_filename = &matches.free[0];

    export_key_run(
        key_name.as_ref().map(String::as_str),
        repo,
        &target_filename,
    )
}

fn export_key_run(
    key_name: Option<&str>,
    repo: &Path,
    target_filename: &str,
) -> Result<(), String> {
    let key = load_key_from_repo(key_name, repo)?;
    let data = key.store();

    if target_filename == "-" {
        ::std::io::stdout().write_all(&data)
    } else {
        let mut f = ::std::fs::File::create(target_filename)
            .map_err(|e| format!("failed to create file '{:?}': {}", target_filename, e))?;
        f.write_all(&data)
    }
    .map_err(|e| format!("failed to write key data: {}", e))?;

    Ok(())
}

// unlock will decrypt the keys, set up the filters and then decrypt the files.
//
// 'filter_binary' allows to force another binary path to be used as the filter.
// This is necessary for testing, since cargo test binaries have their own parameters and functionality.
// Without the overwrite, the filters would just write the test summary to target files.
pub fn unlock(args: Vec<String>, working_dir: &Path, filter_binary: &Path) -> Result<(), String> {
    // 1. Make sure working directory is clean (ignoring untracked files)
    // We do this because we check out files later, and we don't want the
    // user to lose any changes.  (TODO: only care if encrypted files are
    // modified, since we only check out encrypted files)

    // Running 'git status' also serves as a check that the Git repo is accessible.
    let clean = ::git::get_git_status(working_dir, &mut std::io::stderr())?;
    if !clean {
        return Err(format!(
            "Error: Working directory not clean.\
             Please commit your changes or 'git stash' them before running 'git-crypt unlock'."
        ));
    }

    let mut key_files: Vec<::key::KeyFile> = Vec::new();

    // 2. Load the key(s)
    if !args.is_empty() {
        // Read from the symmetric key file(s)
        for arg in args {
            let keyfile = if &arg == "-" {
                ::key::KeyFile::from_stream(&mut std::io::stdin())
            } else {
                let pp = Path::new(&arg);
                let file_path = if pp.is_absolute() {
                    pp.to_path_buf()
                } else {
                    working_dir.join(pp)
                };

                ::key::KeyFile::from_file(&file_path)
            }
            .map_err(|e| format!("failed to load key from '{:?}': {}", &arg, e))?;

            key_files.push(keyfile);
        }
    } else {
        let repo_keys_path: std::path::PathBuf = get_repo_keys_path(working_dir)?;
        let gpg_secret_keys: Vec<String> = ::gpg::gpg_list_secret_keys(working_dir)?;

        // TODO: command-line option to specify the precise secret key to use
        // TODO: don't hard code key version 0 here - instead, determine the most recent version and try to decrypt that, or decrypt all versions if command-line option specified
        // TODO: command line option to only unlock specific key instead of all of them
        // TODO: avoid decrypting repo keys which are already unlocked in the .git directory
        key_files = decrypt_repo_keys(working_dir, 0, gpg_secret_keys.as_slice(), &repo_keys_path)
            .map_err(|e| format!("Failed to decrypt repo keys: {}", e))?;
    }

    // 3. Install the key(s) and configure the git filters
    let mut encrypted_files: Vec<String> = Vec::new();
    for key in key_files {
        let kn = key.key_name.as_ref().map(|x| x.as_str());

        let internal_key_path = ::git::get_internal_key_path(working_dir, kn)?;

        // TODO: croak if internal_key_path already exists???
        let key_path_parent = Path::new(&internal_key_path).parent();
        std::fs::create_dir_all(key_path_parent.map(Path::to_str).unwrap().unwrap())
            .unwrap_or_else(|e| {
                eprintln!("failed create internal key path: {}", e);
                std::process::exit(1);
            });

        let mut file = std::fs::File::create(&internal_key_path).map_err(|e| {
            format!(
                "failed create file {:?} for the key: {}",
                &internal_key_path, e
            )
        })?;

        file.write_all(key.store().as_slice())
            .map_err(|e| format!("failed write key data: {}", e))?;

        configure_git_filters(working_dir, kn, filter_binary)
            .map_err(|e| format!("failed to configure git filters: {}", e))?;
        let mut additional_encrypted_files = get_encrypted_files(working_dir, kn)?;
        encrypted_files.append(&mut additional_encrypted_files);
    }

    // 4. Check out the files that are currently encrypted.
    // Git won't check out a file if its mtime hasn't changed, so touch every file first.
    encrypted_files
        .iter()
        .try_for_each(|f| touch_file(&working_dir.join(f)))?;
    if let Err(e) = ::git::git_checkout(
        working_dir,
        encrypted_files.iter().map(String::as_str).collect(),
    ) {
        eprintln!("Error: 'git checkout' failed");
        eprintln!("git-crypt has been set up but existing encrypted files have not been decrypted");
        return Err(e);
    }

    Ok(())
}

fn get_repo_keys_path(repo: &Path) -> Result<std::path::PathBuf, String> {
    ::git::get_repo_state_path(repo).map(|p| p.join("keys"))
}

fn decrypt_repo_keys(
    repo: &Path,
    key_version: u32,
    secret_keys: &[String],
    keys_path: &Path,
) -> Result<Vec<::key::KeyFile>, String> {
    let dirents =
        std::fs::read_dir(keys_path).map_err(|e| format!("read_dir {:?}: {}", keys_path, e))?;

    let foo: Result<Vec<Option<::key::KeyFile>>, String> = dirents
        .map(|d| -> Result<Option<::key::KeyFile>, String> {
            let os_file_name = d.unwrap().file_name();
            let file_name: &str = if let Some(o) = os_file_name.to_str() {
                o
            } else {
                return Err(format!("Failed to convert directory name to str"));
            };
            let key_name = if file_name == "default" {
                None
            } else {
                if ::key::validate_key_name(file_name).is_err() {
                    return Ok(None);
                }

                Some(file_name)
            };

            decrypt_repo_key(repo, key_name, key_version, secret_keys, keys_path)
        })
        .collect();

    let r: Result<Vec<::key::KeyFile>, String> = foo.map(|x| x.into_iter().flatten().collect());
    r
}

fn decrypt_repo_key(
    repo: &Path,
    key_name: Option<&str>,
    key_version: u32,
    secret_keys: &[String],
    keys_path: &Path,
) -> Result<Option<::key::KeyFile>, String> {
    for key in secret_keys {
        let path = keys_path
            .join(key_name.unwrap_or("default"))
            .join(key_version.to_string())
            .join(format!("{}.gpg", key));
        let decrypted_contents = match ::gpg::gpg_decrypt_from_file(repo, path.to_str().unwrap()) {
            Ok(o) => o,
            Err(_) => continue,
        };

        let k = ::key::KeyFile::from_bytes(decrypted_contents.as_slice())
            .map_err(|e| format!("failed to read key from bytes: {:?}", e))?;

        if !k.entries.contains_key(&key_version) {
            return Err( "GPG-encrypted keyfile is malformed because it does not contain expected key version".to_string());
        }

        if k.key_name != key_name.map(|x| x.to_string()) {
            return Err(
                "GPG-encrypted keyfile is malformed because it does not contain expected key name"
                    .to_string(),
            );
        }

        return Ok(Some(k));
    }

    Ok(None)
}

pub fn lock(args: Vec<String>, repo: &Path) -> Result<(), String> {
    let mut opts = getopts::Options::new();
    opts.optopt("k", "key-name", "key name", "KEYNAME");
    opts.optflag("a", "all", "lock all keys");
    opts.optflag("f", "force", "");

    let matches = opts.parse(args.clone()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        ::help_lock();
        std::process::exit(2);
    });

    if !matches.free.is_empty() {
        eprintln!("git-crypt lock takes no arguments");
        ::help_lock();
        std::process::exit(2);
    }

    let key_name = matches.opt_str("key-name");
    let all_keys = matches.opt_present("all");
    let force = matches.opt_present("force");

    if all_keys && key_name.is_some() {
        eprintln!("-k and --all options are mutually exclusive");
        ::help_lock();
        std::process::exit(2);
    }

    lock_run(repo, key_name.as_ref().map(String::as_ref), all_keys, force)
}

fn lock_run(
    repo: &Path,
    key_name: Option<&str>,
    all_keys: bool,
    force: bool,
) -> Result<(), String> {
    // 1. Make sure working directory is clean (ignoring untracked files)
    // We do this because we check out files later, and we don't want the
    // user to lose any changes.  (TODO: only care if encrypted files are
    // modified, since we only check out encrypted files)

    // Running 'git status' also serves as a check that the Git repo is accessible.

    let is_clean = ::git::get_git_status(repo, &mut std::io::stderr())?;
    if !force && !is_clean {
        return Err("Error: Working directory not clean.
Please commit your changes or 'git stash' them before running 'git-crypt lock'.
Or, use 'git-crypt lock --force' and possibly lose uncommitted changes."
            .to_string());
    }

    // 2. deconfigure the git filters and remove decrypted keys
    let mut encrypted: Vec<String> = Vec::new();
    if all_keys {
        // deconfigure for all keys
        let internal_keys_path = ::git::get_internal_keys_path(repo, None)?;
        ::std::fs::read_dir(internal_keys_path)
            .map_err(|e| format!("failed to get directory contents: {}", e))?
            .try_for_each(|d| -> Result<(), String> {
                let dirent: ::std::fs::DirEntry = d.map_err(|e: std::io::Error| -> String {
                    format!("failed to resolve directory entry: {}", e)
                })?;

                // safety check
                if !dirent.path().starts_with(repo) {
                    panic!(
                        "DANGER: tried to remove path '{:?}' which is not under the repo path!",
                        dirent
                    );
                }

                ::std::fs::remove_file(dirent.path()).map_err(|e| {
                    format!(
                        "failed to remove key '{}': {}",
                        dirent.path().to_str().unwrap(),
                        e
                    )
                })?;

                let key_name = dirent
                    .file_name()
                    .to_str()
                    .ok_or(format!(
                        "couldn't convert file name to string for key file '{:?}'",
                        dirent.path()
                    ))?
                    .to_string();
                let key_name_opt = match key_name.as_str() {
                    "default" => None,
                    _ => Some(key_name.as_str()),
                };
                deconfigure_git_filters(repo, key_name_opt)?;
                let mut additional_encrypted_files = get_encrypted_files(repo, key_name_opt)?;
                encrypted.append(&mut additional_encrypted_files);

                Ok(())
            })?;
    } else {
        let internal_key_path: std::path::PathBuf = ::git::get_internal_key_path(repo, key_name)?;
        if !internal_key_path.exists() {
            let withkey = if let Some(kn) = key_name {
                format!(" with key '{}'", kn)
            } else {
                "".to_string()
            };
            return Err(format!("This repository is already locked{}.", withkey));
        }

        ::std::fs::remove_file(&internal_key_path).map_err(|e| {
            format!(
                "failed to remove key '{}': {}",
                internal_key_path.to_str().unwrap(),
                e
            )
        })?;
        deconfigure_git_filters(repo, key_name)?;
        encrypted = get_encrypted_files(repo, key_name)?;
    }

    // 3. Check out the files that are currently decrypted but should be encrypted.
    // Git won't check out a file if its mtime hasn't changed, so touch every file first.
    encrypted
        .iter()
        .try_for_each(|f| touch_file(&repo.join(f)))?;
    if let Err(e) = ::git::git_checkout(repo, encrypted.iter().map(String::as_str).collect()) {
        eprintln!("Error: 'git checkout' failed");
        eprintln!(
            "git-crypt has been locked but up but existing decrypted files have not been encrypted"
        );
        return Err(e);
    }

    Ok(())
}

fn touch_file(p: &Path) -> Result<(), String> {
    let t = ::filetime::FileTime::from_system_time(::std::time::SystemTime::now());
    ::filetime::set_file_times(p, t, t)
        .map_err(|e| format!("failed to set file atime/mtime: {}", e))
}

fn start_chkattr(repo: &Path) -> Result<::std::process::Child, String> {
    if ::git::get_version()? < 10805 {
        return Err("git older than 1.8.5 is not supported".to_string());
    }
    // In Git 1.8.5 (released 27 Nov 2013) and higher, we use a single `git check-attr` process
    // to get the attributes of all files at once.  In prior versions, we had to fork and exec
    // a separate `git check-attr` process for each file, since -z and --stdin aren't supported.
    // In a repository with thousands of files, this results in an almost 100x speedup.
    std::process::Command::new("git")
        .arg("check-attr")
        .arg("--stdin")
        .arg("-z")
        .arg("filter")
        .arg("diff")
        .current_dir(repo)
        .stdin(::std::process::Stdio::piped())
        .stdout(::std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run git check-attr --stdin -z filter diff: {}", e))
}

fn get_encrypted_files(repo: &Path, key_name: Option<&str>) -> Result<Vec<String>, String> {
    let path_to_top = ::git::get_path_to_top(repo)?;
    // git ls-files -cz -- path_to_top
    let mut lsfiles = std::process::Command::new("git")
        .arg("ls-files")
        .arg("-csz")
        .arg("--")
        .arg(&path_to_top)
        .current_dir(repo)
        .stdout(::std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "failed to run git ls-files -csz -- {:?}: {}",
                &path_to_top, e
            )
        })?;

    let lsfilesout = lsfiles.stdout.as_mut().unwrap();
    let mut lsfilesout_buffered = std::io::BufReader::new(lsfilesout);

    let mut chkattr = start_chkattr(repo)?;

    let mut files: Vec<String> = Vec::new();

    {
        // FIXME extra scope to drop stdin/stdout mut references before wait()
        let mut chkattrstdin = chkattr.stdin.as_mut().unwrap();
        let chkattrstdout = chkattr.stdout.as_mut().unwrap();
        let mut chkattrstdout_buffered = std::io::BufReader::new(chkattrstdout);

        loop {
            let mut data: Vec<u8> = Vec::new();
            let n = lsfilesout_buffered
                .read_until(b'\0', &mut data)
                .map_err(|e| format!("failed to read ls-files output: {}", e))?;
            if n == 0 {
                break;
            }

            let line = std::str::from_utf8(&data[..])
                .map_err(|e| format!("failed to convert command output to UTF-8: {}", e))?
                .trim_matches(char::from(0))
                .to_string();
            let split: Vec<&str> = line.split_whitespace().collect();

            let mode = split[0]
                .parse::<u32>()
                .map_err(|e| format!("failed to parse mode '{}': {}", split[0], e))?;

            if is_git_file_mode(mode) {
                let filename = split[split.len() - 1];
                let (filter_attr, _diff_attr) =
                    get_file_attributes(&mut chkattrstdout_buffered, &mut chkattrstdin, filename)?;
                if filter_attr == Some(attribute_name(key_name)) {
                    files.push(filename.to_string());
                }
            }
        }
    }

    let status = chkattr.wait().map_err(|e| {
        format!(
            "`git check-attr --stdin -z filter diff` failed to terminate: {}",
            e
        )
    })?;
    if !status.success() {
        return Err(format!(
            "`git check-attr --stdin -z filter diff` returned non-zero status"
        ));
    }

    Ok(files)
}

fn attribute_name(key_name: Option<&str>) -> String {
    match key_name {
        None => "git-crypt".to_string(),
        Some(kn) => format!("git-crypt-{}", kn),
    }
}

fn get_file_attributes(
    output: &mut std::io::BufRead,
    input: &mut std::io::Write,
    filename: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let mut payload = filename.as_bytes().to_vec();
    payload.push(0);
    input
        .write_all(&payload)
        .map_err(|e| format!("failed to write to git check-attr pipe: {}", e))?;

    let mut filter: Option<String> = None;
    let mut diff: Option<String> = None;

    // Example output:
    // filename\0filter\0git-crypt\0filename\0diff\0git-crypt\0
    for _i in 0..2 {
        let mut filename_data: Vec<u8> = Vec::new(); // this gets discarded
        let mut attrname_data: Vec<u8> = Vec::new();
        let mut attrval_data: Vec<u8> = Vec::new();

        // filename
        output
            .read_until(b'\0', &mut filename_data)
            .map_err(|e| format!("failed to read check-attr output: {}", e))?;

        // attribute name
        output
            .read_until(b'\0', &mut attrname_data)
            .map_err(|e| format!("failed to read check-attr output: {}", e))?;

        // attribute value
        output
            .read_until(b'\0', &mut attrval_data)
            .map_err(|e| format!("failed to read check-attr output: {}", e))?;

        let attrname: &str = std::str::from_utf8(&attrname_data[..])
            .map_err(|e| format!("failed to convert command output to UTF-8: {}", e))?
            .trim_matches(char::from(0));

        let attrval: &str = std::str::from_utf8(&attrval_data[..])
            .map_err(|e| format!("failed to convert command output to UTF-8: {}", e))?
            .trim_matches(char::from(0));

        if attrval != "unspecified" && attrval != "unset" && attrval != "set" {
            if attrname == "filter" {
                filter = Some(attrval.to_string());
            } else if attrname == "diff" {
                diff = Some(attrval.to_string());
            }
        }
    }

    Ok((filter, diff))
}

fn configure_git_filters(
    repo: &Path,
    key_name: Option<&str>,
    filter_binary: &Path,
) -> std::io::Result<()> {
    let escaped_git_crypt_path = ::util::escape_shell_arg(filter_binary.to_str().unwrap());

    if let Some(kn) = key_name {
        ::git::git_config(
            repo,
            &format!("filter.git-crypt-{}.smudge", kn),
            &format!("{} smudge --key-name={}", escaped_git_crypt_path, kn),
        )?;
        ::git::git_config(
            repo,
            &format!("filter.git-crypt-{}.clean", kn),
            &format!("{} clean --key-name={}", escaped_git_crypt_path, kn),
        )?;
        ::git::git_config(repo, &format!("filter.git-crypt-{}.required", kn), "true")?;
        ::git::git_config(
            repo,
            &format!("diff.git-crypt-{}.textconv", kn),
            &format!("{} diff --key-name={}", escaped_git_crypt_path, kn),
        )?;
    } else {
        ::git::git_config(
            repo,
            &format!("filter.git-crypt.smudge"),
            &format!("{} smudge", escaped_git_crypt_path),
        )?;
        ::git::git_config(
            repo,
            &format!("filter.git-crypt.clean"),
            &format!("{} clean", escaped_git_crypt_path),
        )?;
        ::git::git_config(repo, &format!("filter.git-crypt.required"), "true")?;
        ::git::git_config(
            repo,
            &format!("diff.git-crypt.textconv"),
            &format!("{} diff", escaped_git_crypt_path),
        )?;
    }

    Ok(())
}

fn deconfigure_git_filters(repo: &Path, key_name: Option<&str>) -> Result<(), String> {
    let attr = attribute_name(key_name);

    if ::git::git_has_config(repo, &format!("filter.{}.smudge", attr))?
        || ::git::git_has_config(repo, &format!("filter.{}.clean", attr))?
        || ::git::git_has_config(repo, &format!("filter.{}.required", attr))?
    {
        ::git::git_deconfig_section(repo, &format!("filter.{}", attr))?;
    }

    if ::git::git_has_config(repo, &format!("diff.{}.textconv", attr))? {
        ::git::git_deconfig_section(repo, &format!("diff.{}", attr))?;
    }

    Ok(())
}

fn parse_plumbing_options(
    args: Vec<String>,
) -> Result<(Option<String>, Option<String>, Vec<String>), String> {
    let mut opts = getopts::Options::new();
    opts.optopt("k", "key-name", "key name", "KEYNAME");
    opts.optopt("", "key-file", "key path", "KEY_FILE_PATH");

    let matches = opts
        .parse(args.clone())
        .map_err(|e| format!("failed to parse plumbing options: {}", e))?;

    Ok((
        matches.opt_str("key-name"),
        matches.opt_str("key-file"),
        matches.free,
    ))
}

// Decrypt contents of stdin and write to stdout
pub fn smudge(args: Vec<String>, repo: &Path) -> Result<(), String> {
    smudge_run(args, repo).map_err(|e| format!("{}", e))
}

fn smudge_run(args: Vec<String>, repo: &Path) -> std::io::Result<()> {
    let (key_name, key_file, _remaining_args) =
        parse_plumbing_options(args).map_err(|e| Error::new(ErrorKind::Other, format!("{}", e)))?;

    let key = if let Some(kf) = key_file {
        load_key_from_path(&Path::new(kf.as_str()))
    } else {
        load_key_from_repo(key_name.as_ref().map(String::as_str), repo)
    }
    .map_err(|e| Error::new(ErrorKind::Other, e))?;

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

pub fn diff(args: Vec<String>, repo: &Path) -> Result<(), String> {
    diff_run(args, repo).map_err(|e| format!("{}", e))
}

fn diff_run(args: Vec<String>, repo: &Path) -> std::io::Result<()> {
    let (key_name, key_file, remaining_args) =
        parse_plumbing_options(args).map_err(|e| Error::new(ErrorKind::Other, format!("{}", e)))?;

    if remaining_args.len() != 1 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "'git-crypt diff' requires 1 positional argument, got {}",
                remaining_args.len()
            ),
        ));
    }

    let key = if let Some(kf) = key_file {
        load_key_from_path(&Path::new(kf.as_str()))
    } else {
        load_key_from_repo(key_name.as_ref().map(String::as_str), repo)
    }
    .map_err(|e| Error::new(ErrorKind::Other, e))?;
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

fn load_key_from_path(key_path: &Path) -> Result<::key::KeyFile, String> {
    match ::key::KeyFile::from_file(key_path) {
        Ok(o) => Ok(o),
        Err(e) => Err(format!("cannot read key from the given path: {}", e)),
    }
}

fn load_key_from_repo(key_name: Option<&str>, repo: &Path) -> Result<::key::KeyFile, String> {
    let path = ::git::get_internal_key_path(repo, key_name)?;

    match ::key::KeyFile::from_file(&path.as_path()) {
        Ok(o) => Ok(o),
        Err(e) => Err(format!("cannot read key from the given path: {}", e)),
    }
}

// Encrypt contents of stdin and write to stdout
pub fn clean(args: Vec<String>, repo: &Path) -> Result<(), String> {
    clean_run(args, repo).map_err(|e| format!("{}", e))
}

fn clean_run(args: Vec<String>, repo: &Path) -> Result<(), String> {
    let (key_name, key_file, _remaining_args) = parse_plumbing_options(args)?;

    let key = if let Some(kf) = key_file {
        load_key_from_path(&Path::new(kf.as_str()))
    } else {
        load_key_from_repo(key_name.as_ref().map(String::as_str), repo)
    }?;

    encrypt_stream(&key, &mut std::io::stdin(), &mut std::io::stdout())
        .map_err(|e| format!("failed to encrypt stream: {}", e))?;
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

pub fn refresh(_args: Vec<String>) -> Result<(), String> {
    unimplemented!("refresh");
}

pub fn rm_gpg_user(_args: Vec<String>) -> Result<(), String> {
    unimplemented!("rm-gpg-user");
}

pub fn run_init(args: Vec<String>, repo: &Path) -> Result<(), String> {
    let mut opts = getopts::Options::new();
    opts.optopt("k", "key-name", "key name", "KEYNAME");

    let matches = opts.parse(args.clone()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        ::help_init();
        std::process::exit(2);
    });

    let key_name = matches.opt_str("key-name");

    init(
        key_name.as_ref().map(String::as_str),
        repo,
        &::std::env::current_exe().unwrap(),
    )
}

fn init(key_name: Option<&str>, repo: &Path, filter_binary: &Path) -> Result<(), String> {
    if let Some(s) = key_name.as_ref() {
        ::key::validate_key_name(s)?;
    }

    let internal_key_path: ::std::path::PathBuf = ::git::get_internal_key_path(repo, key_name)?;

    if Path::new(&internal_key_path).exists() {
        // TODO: add a -f option to reinitialize the repo anyways (this should probably imply a refresh)
        // TODO: include key_name in error message
        return Err(
            "Error: this repository has already been initialized with git-crypt.".to_string(),
        );
    }

    // 1. Generate a key and install it
    eprintln!("Generating key...");
    let key = ::key::KeyFile::generate(key_name.map(&str::to_string));

    let parent = internal_key_path.parent().unwrap();
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create key directory: {}", e))?;
    let key_data = key.store();
    let mut f = std::fs::File::create(&internal_key_path)
        .map_err(|e| format!("failed to create key file: {}", e))?;

    f.write_all(key_data.as_slice())
        .map_err(|e| format!("failed to write key file: {}", e))?;

    f.flush()
        .map_err(|e| format!("failed to write key file: {}", e))?;

    // 2. Configure git for git-crypt
    configure_git_filters(repo, key_name, filter_binary)
        .map_err(|e| format!("failed to configure git filters: {}", e))?;

    eprintln!("Done.");

    Ok(())
}

pub fn ls_gpg_users(_args: Vec<String>) -> Result<(), String> {
    // Sketch:
    // Scan the sub-directories in .git-crypt/keys, outputting something like this:
    // ====
    // Key version 0:
    //  0x143DE9B3F7316900 Andrew Ayer <andrew@example.com>
    //  0x4E386D9C9C61702F ???
    // Key version 1:
    //  0x143DE9B3F7316900 Andrew Ayer <andrew@example.com>
    //  0x1727274463D27F40 John Smith <smith@example.com>
    //  0x4E386D9C9C61702F ???
    // ====
    // To resolve a long hex ID, use a command like this:
    //  gpg --options /dev/null --fixed-list-mode --batch --with-colons --list-keys 0x143DE9B3F7316900

    unimplemented!("ls-gpg-users");
}

pub fn add_gpg_user(args: Vec<String>, repo: &Path) -> Result<(), String> {
    let mut opts = getopts::Options::new();
    opts.optopt("k", "key-name", "key name", "KEYNAME");
    opts.optflag("n", "no-commit", "don't commit");
    opts.optflag("", "trusted", "trusted");

    let matches = opts.parse(args.clone()).unwrap_or_else(|e| {
        eprintln!("{}", e);
        ::help_add_gpg_user();
        std::process::exit(2);
    });

    add_gpg_user_run(
        repo,
        matches.opt_str("key-name").as_ref().map(String::as_ref),
        matches.opt_present("no-commit"),
        matches.opt_present("trusted"),
        matches.free,
    )
}

pub fn add_gpg_user_run(
    repo: &Path,
    key_name: Option<&str>,
    no_commit: bool,
    trusted: bool,
    args: Vec<String>,
) -> Result<(), String> {
    if args.is_empty() {
        return Err("Error: no GPG user ID specified".to_string());
    }

    // build a list of key fingerprints, and whether the key is trusted, for every collaborator specified on the command line
    let mut collab_keys: Vec<(String, bool)> = Vec::new();

    for q in args {
        let fingerprints = ::gpg::gpg_lookup_key(repo, &q)?;

        if fingerprints.is_empty() {
            return Err(format!(
                "Error: public key for '{}' not found in your GPG keyring",
                q
            ));
        }

        if fingerprints.len() > 1 {
            return Err(format!(
                "Error: more than one public key matches '{}' - please be more specific",
                q
            ));
        }

        let is_full_fingerprint = q.starts_with("0x") && q.len() == 42;
        collab_keys.push((fingerprints[0].clone(), trusted || is_full_fingerprint));
    }

    // TODO: have a retroactive option to grant access to all key versions, not just the most recent
    let key_file =
        load_key_from_repo(key_name, repo).map_err(|e| format!("failed to load key: {}", e))?;
    let key = key_file.get_latest().ok_or("Error: key file is empty")?;

    // FIXME do we really need to disassemble the key and put it back in encrypt_repo_key?
    // FIXME do we really need to get the state path separately, since we're already passing the repo path?
    let mut new_files = encrypt_repo_key(key_name, key, &collab_keys, repo)?;

    // FIXME why is this in add_gpg_user?
    let gitattrpath = ::git::get_repo_state_path(repo)?.join(".gitattributes");
    if !gitattrpath.exists() {
        let mut f = ::std::fs::File::create(&gitattrpath)
            .map_err(|e| format!("failed to create .gitattributes file: {}", e))?;

        const GITATTR_CONTENT: &str =
            "# Do not edit this file.  To specify the files to encrypt, create your own
# .gitattributes file in the directory where your files are.
* !filter !diff
*.gpg binary
";
        f.write_all(GITATTR_CONTENT.as_bytes())
            .map_err(|e| format!("failed to write to .gitattributes file: {}", e))?;
        new_files.push(gitattrpath);
    }

    // add/commit the new files
    if !new_files.is_empty() {
        // git add NEW_FILE ...
        let add_output = std::process::Command::new("git")
            .arg("add")
            .arg("--")
            .args(&new_files)
            .current_dir(repo)
            .output()
            .map_err(|e| format!("failed to run `git add`: {}", e))?;

        if !add_output.status.success() {
            let stderr_string = String::from_utf8(add_output.stderr).unwrap();
            return Err(format!("failed to git add: {}", stderr_string));
        }

        // git commit ...
        if !no_commit {
            // TODO: include key_name in commit message
            let mut commit_message = format!(
                "Add {} git-crypt collaborator{}\n\nNew collaborators:\n\n",
                collab_keys.len(),
                if collab_keys.len() != 1 { "s" } else { "" }
            );
            for (fingerprint, _trusted) in &collab_keys {
                commit_message += &format!(
                    "\t{} {}\n",
                    shorten_gpg_fingerprint(&fingerprint),
                    ::gpg::get_key_uid(repo, &fingerprint)?
                );
            }

            // git commit -m MESSAGE NEW_FILE ...
            let commit_output = std::process::Command::new("git")
                .arg("commit")
                .arg("-m")
                .arg(commit_message)
                .arg("--")
                .args(&new_files)
                .current_dir(repo)
                .output()
                .map_err(|e| format!("failed to run `git add`: {}", e))?;

            if !commit_output.status.success() {
                let stderr_string = String::from_utf8(commit_output.stderr).unwrap();
                return Err(format!("failed to git commit: {}", stderr_string));
            }
        }
    }

    Ok(())
}

fn shorten_gpg_fingerprint(fingerprint: &str) -> &str {
    if fingerprint.len() == 40 {
        &fingerprint[32..]
    } else {
        fingerprint
    }
}

fn encrypt_repo_key(
    key_name: Option<&str>,
    key: &::key::Entry,
    collab_keys: &Vec<(String, bool)>,
    repo: &Path,
) -> Result<Vec<::std::path::PathBuf>, String> {
    let mut this_version_key_file = ::key::KeyFile::new();
    this_version_key_file.key_name = key_name.map(str::to_string);
    this_version_key_file
        .entries
        .insert(key.version, key.clone());
    let key_data = this_version_key_file.store();

    let mut new_files: Vec<std::path::PathBuf> = Vec::new();
    let keys_path = get_repo_keys_path(repo)?;

    for (fingerprint, trusted) in collab_keys {
        let this_key_path = keys_path
            .join(key_name.unwrap_or("default"))
            .join(key.version.to_string())
            .join(format!("{}.gpg", fingerprint));

        ::std::fs::create_dir_all(this_key_path.parent().unwrap())
            .map_err(|e| format!("creating directory {:?}: {}", this_key_path.parent(), e))?;
        ::gpg::encrypt_to_file(repo, &this_key_path, &fingerprint, *trusted, &key_data)?;
        new_files.push(this_key_path)
    }

    Ok(new_files)
}

fn is_git_file_mode(mode: u32) -> bool {
    (mode & 0o0170000) == 0o0100000
}

pub fn keygen(args: Vec<String>) -> Result<(), String> {
    if args.len() != 1 {
        eprintln!("Error: no filename specified");
        ::help_keygen();
        std::process::exit(2);
    }

    let filename = Path::new(&args[0]);

    if filename.exists() {
        return Err("'{}': file already exists".to_string());
    }

    eprintln!("Generating key...");
    let key_data = ::key::KeyFile::generate(None).store();

    let target_name = args[0].as_str();
    let mut target: Box<std::io::Write> = if target_name == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(
            std::fs::File::create(target_name)
                .map_err(|e| format!("failed to create file '{}': {}", target_name, e))?,
        )
    };

    target
        .write_all(&key_data)
        .map_err(|e| format!("failed to write key data: {}", e))?;

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
        assert!(decrypt_file_to_stream(
            &key,
            header,
            &mut &TEST_CIPHERTEXT[10 + NONCE_LEN..],
            &mut output
        )
        .is_ok());
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

    fn test_create_test_repo() -> Result<::tempfile::TempDir, std::io::Error> {
        let dir = ::tempfile::tempdir()?;
        let bin = ::std::env::current_dir()
            .unwrap()
            .join("target/debug/git-crypt");

        if !bin.exists() {
            panic!("target/debug/git-crypt must be built for the tests to work. The filters require a clean git-crypt binary.");
        }

        assert!(::std::process::Command::new("git")
            .arg("init")
            .current_dir(dir.path())
            .output()?
            .status
            .success());

        let pack_dir_path = dir.path().join(Path::new(".git/objects/pack"));
        assert!(pack_dir_path.is_dir());

        init(None, dir.path(), &bin).unwrap();
        init(Some("fookey"), dir.path(), &bin).unwrap();

        // create .gitattributes file and commit it
        let mut f = ::std::fs::File::create(dir.path().join(".gitattributes")).unwrap();
        f.write_all(
            "*.* filter=git-crypt diff=git-crypt
* filter=git-crypt diff=git-crypt
.gitattributes !filter !diff
*.nocrypt !filter !diff"
                .as_bytes(),
        )
        .unwrap();
        f.sync_all().unwrap();

        std::process::Command::new("git")
            .arg("add")
            .arg(".gitattributes")
            .current_dir(dir.path())
            .output()
            .unwrap();
        std::process::Command::new("git")
            .arg("commit")
            .arg("--no-gpg-sign")
            .arg("-m")
            .arg(".gitattributes")
            .current_dir(dir.path())
            .output()
            .unwrap();

        Ok(dir)
    }

    #[test]
    fn test_init_repo() {
        let tempdir = test_create_test_repo().unwrap();

        let key_path = tempdir.path().join(".git/git-crypt/keys/default");
        let key_file_result = ::key::KeyFile::from_file(&key_path);
        if let Err(e) = key_file_result {
            panic!("{:?}: {}", key_path, e);
        }

        let bin_name = ::std::env::current_dir()
            .unwrap()
            .join("target/debug/git-crypt");

        assert_eq!(
            ::git::get_git_config(tempdir.path(), "filter.git-crypt.smudge").unwrap(),
            format!("\"{}\" smudge", bin_name.to_str().unwrap())
        );
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "filter.git-crypt.clean").unwrap(),
            format!("\"{}\" clean", bin_name.to_str().unwrap())
        );
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "filter.git-crypt.required").unwrap(),
            "true".to_string()
        );
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "diff.git-crypt.textconv").unwrap(),
            format!("\"{}\" diff", bin_name.to_str().unwrap())
        );
    }

    #[test]
    fn test_encrypt_repo_key() {
        let tempdir = test_create_test_repo().unwrap();

        let key_path = tempdir.path().join(".git/git-crypt/keys/default");
        let key_file = ::key::KeyFile::from_file(&key_path).unwrap();

        let collab_keys: Vec<(String, bool)> =
            vec![(::gpg::tests::TEST_KEY_FINGERPRINT.to_string(), true)];
        let entry = key_file.get_latest().unwrap();
        let new_files = encrypt_repo_key(None, &entry, &collab_keys, tempdir.path()).unwrap();

        let encrypted_key_path = tempdir
            .path()
            .join(".git-crypt/keys/default/0/26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F.gpg");

        assert_eq!(1, new_files.len());
        assert_eq!(new_files[0], encrypted_key_path.canonicalize().unwrap());

        let output = std::process::Command::new("gpg")
            .arg("--decrypt")
            .arg(encrypted_key_path.to_str().unwrap())
            .current_dir(tempdir.path())
            .output()
            .unwrap();

        let decrypted_key = ::key::KeyFile::from_bytes(&output.stdout).unwrap();

        assert_eq!(decrypted_key, key_file);
    }

    #[test]
    fn test_dencrypt_repo_keys() {
        let tempdir = test_create_test_repo().unwrap();

        let key_path_default = tempdir.path().join(".git/git-crypt/keys/default");
        let key_path_fookey = tempdir.path().join(".git/git-crypt/keys/fookey");
        let key_file_default = ::key::KeyFile::from_file(&key_path_default).unwrap();
        let key_file_fookey = ::key::KeyFile::from_file(&key_path_fookey).unwrap();

        let collab_keys: Vec<(String, bool)> =
            vec![(::gpg::tests::TEST_KEY_FINGERPRINT.to_string(), true)];
        let entry_default = key_file_default.get_latest().unwrap();
        let entry_fookey = key_file_fookey.get_latest().unwrap();

        let new_files =
            encrypt_repo_key(None, &entry_default, &collab_keys, tempdir.path()).unwrap();
        let encrypted_key_path = tempdir
            .path()
            .join(".git-crypt/keys/default/0/26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F.gpg");
        assert_eq!(1, new_files.len());
        assert_eq!(new_files[0], encrypted_key_path.canonicalize().unwrap());

        let new_files =
            encrypt_repo_key(Some("fookey"), &entry_fookey, &collab_keys, tempdir.path()).unwrap();
        let encrypted_key_path = tempdir
            .path()
            .join(".git-crypt/keys/fookey/0/26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F.gpg");
        assert_eq!(1, new_files.len());
        assert_eq!(new_files[0], encrypted_key_path.canonicalize().unwrap());

        ::std::fs::remove_file(&key_path_default).unwrap();
        ::std::fs::remove_file(&key_path_fookey).unwrap();

        let repo_keys_path = get_repo_keys_path(tempdir.path()).unwrap();
        let secret_keys = vec!["26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F".to_string()];
        let mut decrypted_keys =
            decrypt_repo_keys(tempdir.path(), 0, &secret_keys, &repo_keys_path).unwrap();

        assert_eq!(decrypted_keys.len(), 2);
        decrypted_keys.sort_by(|a, b| a.key_name.cmp(&b.key_name));

        assert_eq!(decrypted_keys[0], key_file_default);
        assert_eq!(decrypted_keys[1], key_file_fookey);
        assert_ne!(decrypted_keys[1], key_file_default);
        assert_ne!(decrypted_keys[0], key_file_fookey);
    }

    #[test]
    fn test_add_gpg_user() {
        let tempdir = test_create_test_repo().unwrap();

        ::git::git_config(tempdir.path(), "commit.gpgsign", "false").unwrap();

        add_gpg_user_run(
            tempdir.path(),
            None,
            false,
            true,
            vec!["Test Identity <test@example.com>".to_string()],
        )
        .unwrap();

        let key_path = tempdir.path().join(".git/git-crypt/keys/default");
        let key_file = ::key::KeyFile::from_file(&key_path).unwrap();

        let encrypted_key_path = tempdir
            .path()
            .join(".git-crypt/keys/default/0/26AC6DD34577BEDD4A47A38A2343E74AB0BDF29F.gpg");

        let output = std::process::Command::new("gpg")
            .arg("--decrypt")
            .arg(encrypted_key_path.to_str().unwrap())
            .current_dir(tempdir.path())
            .output()
            .unwrap();

        let decrypted_key = ::key::KeyFile::from_bytes(&output.stdout).unwrap();

        assert_eq!(decrypted_key, key_file);

        let git_log_out = std::process::Command::new("git")
            .arg("log")
            .arg("-1")
            .arg("--oneline")
            .current_dir(tempdir.path())
            .output()
            .unwrap();
        let lines: Vec<String> = std::io::BufReader::new(&git_log_out.stdout[..])
            .lines()
            .filter_map(Result::ok)
            .collect();
        assert!(lines[0].contains("Add 1 git-crypt collaborator"));
    }

    #[test]
    fn test_get_file_attributes() {
        let tempdir = test_create_test_repo().unwrap();

        let mut chkattr = std::process::Command::new("git")
            .arg("check-attr")
            .arg("--stdin")
            .arg("-z")
            .arg("filter")
            .arg("diff")
            .current_dir(tempdir.path())
            .stdin(::std::process::Stdio::piped())
            .stdout(::std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdin = chkattr.stdin.as_mut().unwrap();
        let stdout = chkattr.stdout.as_mut().unwrap();
        let mut stdout_buf = std::io::BufReader::new(stdout);

        let (filter, diff) =
            get_file_attributes(&mut stdout_buf, &mut stdin, "somefile.txt").unwrap();
        assert_eq!(filter, Some("git-crypt".to_string()));
        assert_eq!(diff, Some("git-crypt".to_string()));

        let (filter, diff) = get_file_attributes(
            &mut stdout_buf,
            &mut stdin,
            "some dir/somefile whitespace.txt",
        )
        .unwrap();
        assert_eq!(filter, Some("git-crypt".to_string()));
        assert_eq!(diff, Some("git-crypt".to_string()));

        let (filter, diff) =
            get_file_attributes(&mut stdout_buf, &mut stdin, "some dir/somefile.nocrypt").unwrap();
        assert_eq!(filter, None);
        assert_eq!(diff, None);
    }

    #[test]
    fn test_get_encrypted_files() {
        let tempdir = test_create_test_repo().unwrap();

        // create a first file and commit it
        let mut f = ::std::fs::File::create(tempdir.path().join("somefile.txt")).unwrap();
        f.write_all("some data".as_bytes()).unwrap();
        f.sync_all().unwrap();
        f = ::std::fs::File::create(tempdir.path().join("somefile.nocrypt")).unwrap();
        f.write_all("some more data".as_bytes()).unwrap();
        f.sync_all().unwrap();
        f = ::std::fs::File::create(tempdir.path().join("somefile.nocommit")).unwrap();
        f.write_all("some more data".as_bytes()).unwrap();
        f.sync_all().unwrap();

        std::process::Command::new("git")
            .arg("add")
            .arg("somefile.txt")
            .arg("somefile.nocrypt")
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

        let res = get_encrypted_files(tempdir.path(), None).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], "somefile.txt".to_string());
    }

    #[test]
    fn test_configure_git_filters() {
        let tempdir = test_create_test_repo().unwrap();
        let repo = tempdir.path();
        let bin = Path::new("/bin/no-such-binary");

        // default key
        configure_git_filters(repo, None, bin).unwrap();
        assert_eq!(
            ::git::get_git_config(repo, "filter.git-crypt.smudge").unwrap(),
            "\"/bin/no-such-binary\" smudge"
        );
        assert_eq!(
            ::git::get_git_config(repo, "filter.git-crypt.clean").unwrap(),
            "\"/bin/no-such-binary\" clean"
        );
        assert_eq!(
            ::git::get_git_config(repo, "filter.git-crypt.required").unwrap(),
            "true"
        );
        assert_eq!(
            ::git::get_git_config(repo, "diff.git-crypt.textconv").unwrap(),
            "\"/bin/no-such-binary\" diff"
        );

        // remove
        deconfigure_git_filters(repo, None).unwrap();
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt.smudge").unwrap(),
            false
        );
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt.clean").unwrap(),
            false
        );
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt.required").unwrap(),
            false
        );
        assert_eq!(
            ::git::git_has_config(repo, "diff.git-crypt.textconv").unwrap(),
            false
        );

        // key named 'abc'
        configure_git_filters(repo, Some("abc"), bin).unwrap();
        assert_eq!(
            ::git::get_git_config(repo, "filter.git-crypt-abc.smudge").unwrap(),
            "\"/bin/no-such-binary\" smudge --key-name=abc"
        );
        assert_eq!(
            ::git::get_git_config(repo, "filter.git-crypt-abc.clean").unwrap(),
            "\"/bin/no-such-binary\" clean --key-name=abc"
        );
        assert_eq!(
            ::git::get_git_config(repo, "filter.git-crypt-abc.required").unwrap(),
            "true"
        );
        assert_eq!(
            ::git::get_git_config(repo, "diff.git-crypt-abc.textconv").unwrap(),
            "\"/bin/no-such-binary\" diff --key-name=abc"
        );

        // remove for key 'abc'
        deconfigure_git_filters(repo, Some("abc")).unwrap();
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt-abc.smudge").unwrap(),
            false
        );
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt-abc.clean").unwrap(),
            false
        );
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt-abc.required").unwrap(),
            false
        );
        assert_eq!(
            ::git::git_has_config(repo, "diff.git-crypt-abc.textconv").unwrap(),
            false
        );
    }

    #[test]
    fn test_lock_default() {
        let tempdir = test_create_test_repo().unwrap();
        let repo = tempdir.path();

        // create a first file and commit it
        let mut f = ::std::fs::File::create(repo.join("somefile.txt")).unwrap();
        f.write_all("some data".as_bytes()).unwrap();
        f.sync_all().unwrap();
        f = ::std::fs::File::create(repo.join("somefile.nocrypt")).unwrap();
        f.write_all("some more data".as_bytes()).unwrap();
        f.sync_all().unwrap();

        std::process::Command::new("git")
            .arg("add")
            .arg("somefile.txt")
            .arg("somefile.nocrypt")
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

        let key_path = repo.join(".git/git-crypt/keys/default");

        // before
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt.smudge").unwrap(),
            true
        );
        assert_eq!(key_path.exists(), true);

        lock_run(tempdir.path(), None, false, false).unwrap();

        // after
        assert_eq!(
            ::git::git_has_config(repo, "filter.git-crypt.smudge").unwrap(),
            false
        );
        assert_eq!(key_path.exists(), false);

        let mut data_crypt: Vec<u8> = Vec::new();
        let mut data_nocrypt: Vec<u8> = Vec::new();

        std::fs::File::open(repo.join("somefile.txt"))
            .unwrap()
            .read_to_end(&mut data_crypt)
            .unwrap();
        std::fs::File::open(repo.join("somefile.nocrypt"))
            .unwrap()
            .read_to_end(&mut data_nocrypt)
            .unwrap();

        assert_eq!(data_nocrypt.as_slice(), "some more data".as_bytes());
        assert_ne!(data_nocrypt.as_slice(), "some data".as_bytes());
        assert_eq!(data_crypt.len(), 31);
    }

    #[test]
    fn test_lock_unlock_default() {
        let tempdir = test_create_test_repo().unwrap();
        let binary = ::std::env::current_dir()
            .unwrap()
            .join("target/debug/git-crypt");

        // create some files and commit them
        let mut f = ::std::fs::File::create(tempdir.path().join("somefile.txt")).unwrap();
        f.write_all("some data".as_bytes()).unwrap();
        f.sync_all().unwrap();
        f = ::std::fs::File::create(tempdir.path().join("somefile.nocrypt")).unwrap();
        f.write_all("some more data".as_bytes()).unwrap();
        f.sync_all().unwrap();

        std::process::Command::new("git")
            .arg("add")
            .arg("somefile.txt")
            .arg("somefile.nocrypt")
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

        // we need to add a user, so that we can unlock the repo later
        ::git::git_config(tempdir.path(), "commit.gpgsign", "false").unwrap();
        add_gpg_user_run(
            tempdir.path(),
            None,
            false,
            true,
            vec!["Test Identity <test@example.com>".to_string()],
        )
        .unwrap();

        lock_run(tempdir.path(), None, false, false).unwrap();
        // the lock is already tested by test_lock_default()

        unlock(Vec::new(), tempdir.path(), &binary).unwrap();

        // check the filters
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "filter.git-crypt.smudge").unwrap(),
            format!("\"{}\" smudge", binary.to_str().unwrap())
        );
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "filter.git-crypt.clean").unwrap(),
            format!("\"{}\" clean", binary.to_str().unwrap())
        );
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "filter.git-crypt.required").unwrap(),
            "true"
        );
        assert_eq!(
            ::git::get_git_config(tempdir.path(), "diff.git-crypt.textconv").unwrap(),
            format!("\"{}\" diff", binary.to_str().unwrap())
        );

        // now we're interested in whether 'somefile.txt' is cleartext again
        let mut data_crypt: Vec<u8> = Vec::new();
        let mut data_nocrypt: Vec<u8> = Vec::new();

        std::fs::File::open(tempdir.path().join("somefile.txt"))
            .unwrap()
            .read_to_end(&mut data_crypt)
            .unwrap();
        std::fs::File::open(tempdir.path().join("somefile.nocrypt"))
            .unwrap()
            .read_to_end(&mut data_nocrypt)
            .unwrap();

        assert!(data_nocrypt.as_slice().eq("some more data".as_bytes()));
        assert_eq!(data_crypt.as_slice(), "some data".as_bytes());
    }

    #[test]
    fn test_keygen() {
        let dir = ::tempfile::tempdir().unwrap();
        let target = dir.path().join("keyfile");

        let args: Vec<String> = vec![target.to_str().unwrap().to_string()];
        keygen(args).unwrap();

        let mut data: Vec<u8> = Vec::new();
        let mut f = std::fs::File::open(target).unwrap();
        f.read_to_end(&mut data).unwrap();
        assert_eq!(&data[..12], "\0GITCRYPTKEY".as_bytes());

        let key = ::key::KeyFile::from_bytes(&data).unwrap();
        assert_eq!(key.key_name, None);
        assert_eq!(key.entries.len(), 1);
        assert!(key.entries.contains_key(&0));
        let entry = key.entries.get(&0).unwrap();
        assert_eq!(entry.version, 0);
        assert_ne!(&entry.aes_key[..], [0; ::key::AES_KEY_LEN]);
        assert_ne!(&entry.hmac_key[..], &[0; ::key::HMAC_KEY_LEN][..]);
    }

    #[test]
    fn test_export_key() {
        let tempdir = test_create_test_repo().unwrap();

        let key_path = tempdir.path().join(".git/git-crypt/keys/default");
        let key_file = ::key::KeyFile::from_file(&key_path).unwrap();

        let target_path = tempdir.path().join("export");
        export_key_run(None, tempdir.path(), target_path.to_str().unwrap()).unwrap();
        let exported_key = ::key::KeyFile::from_file(&target_path).unwrap();

        assert_eq!(exported_key, key_file);
    }
}
