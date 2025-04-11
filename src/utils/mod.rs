use anyhow::Result;
use std::path::PathBuf;
use std::fs;

#[allow(dead_code)]
pub fn ensure_directory(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

#[allow(dead_code)]
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

#[allow(dead_code)]
pub fn format_command_output(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .map(|line| format!("> {}", line))
        .collect::<Vec<String>>()
        .join("\n")
}

#[allow(dead_code)]
pub fn parse_scope_file(path: &PathBuf) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    let lines = content.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(String::from)
        .collect();
    Ok(lines)
} 