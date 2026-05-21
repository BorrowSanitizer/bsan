use std::fs;
use std::path::Path;

use anyhow::Result;

pub(crate) fn count_rs(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let mut cnt = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            cnt += count_rs(&p)?;
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            cnt += 1;
        }
    }
    Ok(cnt)
}

pub(crate) fn print_tree(dir: &Path, prefix: &str) -> Result<()> {
    let mut dirs: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for (i, p) in dirs.iter().enumerate() {
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string_lossy().into_owned());
        let is_last = i + 1 == dirs.len();
        let connector = if is_last { "└─" } else { "├─" };
        println!("{}{} {}: {}", prefix, connector, name, count_rs(p)?);
        let child_prefix =
            if is_last { format!("{}   ", prefix) } else { format!("{}│  ", prefix) };
        print_tree(p, &child_prefix)?;
    }
    Ok(())
}

pub(crate) fn fmt_percent(value: usize, total: usize) -> String {
    if total == 0 {
        "N/A".to_string()
    } else {
        format!("{:.2}%", value as f64 / total as f64 * 100.0)
    }
}
