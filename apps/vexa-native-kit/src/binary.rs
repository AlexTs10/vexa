//! Where a native Vexa process's binary is: one lookup for every process the
//! daemon starts (stt, credential broker, mcp).

use std::path::{Path, PathBuf};

/// The binary `name` (also its crate directory under `apps/`): the path in
/// `env_var` when it is set (used as given), else the first file of: beside the
/// running executable, then `<source>/apps/<name>/target/release/<name>`, then
/// `.../target/debug/<name>`.
pub fn find(source: &Path, name: &str, env_var: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(env_var) {
        return Some(PathBuf::from(path));
    }
    let beside = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.join(name)));
    let crate_dir = source.join("apps").join(name).join("target");
    [beside, Some(crate_dir.join("release").join(name)), Some(crate_dir.join("debug").join(name))]
        .into_iter()
        .flatten()
        .find(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    #[test]
    fn env_wins_and_missing_is_none() {
        let dir = std::env::temp_dir().join(format!("kit-binary-{}", std::process::id()));
        let built = dir.join("apps/kit-probe/target/debug/kit-probe");
        std::fs::create_dir_all(built.parent().unwrap()).unwrap();
        assert_eq!(super::find(&dir, "kit-probe", "KIT_PROBE_BIN_UNSET"), None);
        std::fs::write(&built, b"").unwrap();
        assert_eq!(super::find(&dir, "kit-probe", "KIT_PROBE_BIN_UNSET"), Some(built));
        std::env::set_var("KIT_PROBE_BIN_SET", "/x/y");
        assert_eq!(super::find(&dir, "kit-probe", "KIT_PROBE_BIN_SET"), Some("/x/y".into()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
