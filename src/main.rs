extern crate libc;
use libc::{c_char, c_int};

extern crate getopts;
extern crate rand;
extern crate tempfile;

mod commands;
mod git;
mod key;
mod util;

use std::env;
use std::ffi::CString;

#[link(name = "crypto", kind = "static")]
#[link(name = "ssl", kind = "static")]
#[link(name = "gitcrypt")]
extern "C" {
    fn cpp_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

fn print_usage(out: &mut std::io::Write, arg0: String) {
    let mut s: String;
    s = format!("Usage: {} COMMAND [ARGS ...]\n", arg0);
    s += "\n";
    //     |--------------------------------------------------------------------------------| 80 characters
    s += "Common commands:\n";
    s += "  init                 generate a key and prepare repo to use git-crypt\n";
    s += "  status               display which files are encrypted\n";
    //s += "  refresh              ensure all files in the repo are properly decrypted\n";
    s += "  lock                 de-configure git-crypt and re-encrypt files in work tree\n";
    s += "\n";
    s += "GPG commands:\n";
    s += "  add-gpg-user USERID  add the user with the given GPG user ID as a collaborator\n";
    //s += "  rm-gpg-user USERID   revoke collaborator status from the given GPG user ID\n";
    //s += "  ls-gpg-users         list the GPG key IDs of collaborators\n";
    s += "  unlock               decrypt this repo using the in-repo GPG-encrypted key\n";
    s += "\n";
    s += "Symmetric key commands:\n";
    s += "  export-key FILE      export this repo's symmetric key to the given file\n";
    s += "  unlock KEYFILE       decrypt this repo using the given symmetric key\n";
    s += "\n";
    s += "Legacy commands:\n";
    s += "  init KEYFILE         alias for 'unlock KEYFILE'\n";
    s += "  keygen KEYFILE       generate a git-crypt key in the given file\n";
    /*
	s += std::endl;
	s += "Plumbing commands (not to be used directly):\n";
	s += "   clean [LEGACY-KEYFILE]\n";
	s += "   smudge [LEGACY-KEYFILE]\n";
	s += "   diff [LEGACY-KEYFILE] FILE\n";
	*/
    s += "\n";
    s += "See 'git-crypt help COMMAND' for more information on a specific command.\n";
    out.write(s.as_bytes()).unwrap();
}

fn print_version(out: &mut std::io::Write) -> Result<(), String> {
    let ver: String = format!("git-crypt {}\n", env!("CARGO_PKG_VERSION"));
    out.write(ver.as_bytes()).unwrap();
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut opts = getopts::Options::new();
    opts.optflag("", "version", "print version");
    opts.optflag("", "help", "print the help menu");
    // Skip first arg, because its the executable name. Then take only the ones tarting with -
    let matches = match opts.parse(args.iter().skip(1).take_while(|s| s.starts_with("-"))) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("{}", f);
            print_usage(&mut std::io::stderr(), std::env::args().nth(0).unwrap());
            std::process::exit(2);
        }
    };

    if matches.opt_present("help") {
        print_usage(&mut std::io::stderr(), std::env::args().nth(0).unwrap());
        std::process::exit(0);
    }

    if matches.opt_present("version") {
        print_version(&mut std::io::stderr()).unwrap();
        std::process::exit(0);
    }

    let mut remaining_args = args.iter().skip(1).skip_while(|s| s.starts_with("-"));
    let cmd = match remaining_args.next() {
        Some(s) => s,
        None => {
            print_usage(&mut std::io::stderr(), std::env::args().nth(0).unwrap());
            std::process::exit(2);
        }
    };
    let cmd_args = remaining_args.map(|a| a.clone()).collect();
    let working_dir = ::std::env::current_dir().unwrap_or_else(|e| {
        eprintln!("Failed to get working directory: {}", e);
        std::process::exit(1);
    });

    if let Err(msg) = match cmd.as_ref() {
        "version" => print_version(&mut std::io::stderr()),
        "help" => help(cmd_args),
        "smudge" => commands::smudge(cmd_args),
        "diff" => commands::diff(cmd_args),
        "clean" => commands::clean(cmd_args),
        "refresh" => commands::refresh(cmd_args),
        "rm-gpg-user" => commands::rm_gpg_user(cmd_args),
        "ls-gpg-users" => commands::ls_gpg_users(cmd_args),
        "init" => commands::run_init(cmd_args, working_dir.as_path()),
        //"lock" => commands::lock(cmd_args)
        //"unlock" => commands::unlock(cmd_args, working_dir.as_path()),
        _ => {
            run_c_with_args(cpp_main, cmd, cmd_args);
            Ok(())
        }
    } {
        eprintln!("{}", msg);
        std::process::exit(1);
    }

    // catch (const Option_error& e) {
    // 	std::clog << "git-crypt: Error: " << e.option_name << ": " << e.message << std::endl;
    // 	help_for_command(command, std::clog);
    // 	return 2;
    // }
}

fn run_c_with_args(
    f: unsafe extern "C" fn(argc: c_int, argv: *const *const c_char) -> i32,
    cmd: &str,
    mut cmd_args: Vec<String>,
) {
    let mut args: Vec<String> = vec![std::env::args().nth(0).unwrap(), cmd.to_string()];
    args.append(&mut cmd_args);

    let cs_args = args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).unwrap())
        .collect::<Vec<CString>>();
    let c_args = cs_args
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const c_char>>();

    unsafe {
        let return_code = f(args.len() as c_int, c_args.as_ptr());
        std::process::exit(return_code);
    }
}

fn help(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        print_usage(&mut std::io::stdout(), std::env::args().nth(0).unwrap());
        return Ok(());
    }

    if !help_for_command(args[0].clone()) {
        Err(format!(
            "Error: '{}' is not a git-crypt command. See 'git-crypt help'.",
            args[0]
        ))
    } else {
        Ok(())
    }
}

fn help_for_command(command: String) -> bool {
    match command.as_ref() {
        "init" => help_init(),
        "unlock" => help_unlock(),
        "lock" => help_lock(),
        "add-gpg-user" => help_add_gpg_user(),
        "rm-gpg-user" => help_rm_gpg_user(),
        "ls-gpg-users" => help_ls_gpg_users(),
        "export-key" => help_export_key(),
        "keygen" => help_keygen(),
        "refresh" => help_refresh(),
        "status" => help_status(),
        _ => return false,
    }

    return true;
}

#[no_mangle]
pub extern "C" fn help_init() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt init [OPTIONS]\n");
    eprint!("\n");
    eprint!("    -k, --key-name KEYNAME      Initialize the given key, instead of the default\n");
    eprint!("\n");
}

#[no_mangle]
pub extern "C" fn help_unlock() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt unlock\n");
    eprint!("   or: git-crypt unlock KEY_FILE ...\n");
}

#[no_mangle]
pub extern "C" fn help_lock() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt lock [OPTIONS]\n");
    eprint!("\n");
    eprint!("    -a, --all                Lock all keys, instead of just the default\n");
    eprint!("    -k, --key-name KEYNAME   Lock the given key, instead of the default\n");
    eprint!("    -f, --force              Lock even if unclean (you may lose uncommited work)\n");
    eprint!("\n");
}

#[no_mangle]
pub extern "C" fn help_add_gpg_user() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt add-gpg-user [OPTIONS] GPG_USER_ID ...\n");
    eprint!("\n");
    eprint!("    -k, --key-name KEYNAME      Add GPG user to given key, instead of default\n");
    eprint!("    -n, --no-commit             Don't automatically commit\n");
    eprint!("    --trusted                   Assume the GPG user IDs are trusted\n");
    eprint!("\n");
}

#[no_mangle]
pub extern "C" fn help_rm_gpg_user() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt rm-gpg-user [OPTIONS] GPG_USER_ID ...\n");
    eprint!("\n");
    eprint!("    -k, --key-name KEYNAME      Remove user from given key, instead of default\n");
    eprint!("    -n, --no-commit             Don't automatically commit\n");
    eprint!("\n");
}

#[no_mangle]
pub extern "C" fn help_ls_gpg_users() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt ls-gpg-users\n");
}

#[no_mangle]
pub extern "C" fn help_export_key() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt export-key [OPTIONS] FILENAME\n");
    eprint!("\n");
    eprint!("    -k, --key-name KEYNAME      Export the given key, instead of the default\n");
    eprint!("\n");
    eprint!("When FILENAME is -, export to standard out.\n");
}

#[no_mangle]
pub extern "C" fn help_keygen() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt keygen FILENAME\n");
    eprint!("\n");
    eprint!("When FILENAME is -, write to standard out.\n");
}

#[no_mangle]
pub extern "C" fn help_refresh() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt refresh\n");
}

#[no_mangle]
pub extern "C" fn help_status() {
    //     |--------------------------------------------------------------------------------| 80 chars
    eprint!("Usage: git-crypt status [OPTIONS] [FILE ...]\n");
    //eprint!("   or: git-crypt status -r [OPTIONS]\n");
    //eprint!("   or: git-crypt status -f\n");
    eprint!("\n");
    eprint!("    -e             Show encrypted files only\n");
    eprint!("    -u             Show unencrypted files only\n");
    //eprint!("    -r             Show repository status only\n");
    eprint!("    -f, --fix      Fix problems with the repository\n");
    //eprint!("    -z             Machine-parseable output\n");
    eprint!("\n");
}
