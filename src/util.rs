pub fn escape_shell_arg(s: &str) -> String {
    let replaced_s = s
        .clone()
        .replace("\"", "\\\"")
        .replace("\\", "\\\\")
        .replace("$", "\\$")
        .replace("`", "\\`");
    format!("\"{}\"", replaced_s)
}
