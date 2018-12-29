extern crate cc;

fn main() {
    cc::Build::new()
        .file("git-crypt.cpp")
        .file("commands.cpp")
        .file("gpg.cpp")
        .file("key.cpp")
        .file("util.cpp")
        .file("coprocess.cpp")
        .file("parse_options.cpp")
        .file("fhstream.cpp")
        .cpp(true)
        .compile("libgitcrypt.a");
}
