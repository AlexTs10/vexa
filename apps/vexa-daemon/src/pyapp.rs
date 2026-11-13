//! Python services on the host, with the same file layout as their images.
//!
//! Each service image copies parts of the checkout into `/app`. The daemon
//! builds the same tree below `runtime/apps/<name>` from the `COPY` lines of
//! the service's Dockerfile, with symlinks to the checkout. Code that finds
//! its contracts by path then works as in the container, and a source change
//! needs only a restart. Each project gets its locked environment from
//! `uv sync`, as its Dockerfile does.

use std::path::{Path, PathBuf};
use std::process::Command;

/// One `COPY` instruction, resolved against the build context and `/app`.
#[derive(Debug, PartialEq)]
pub struct CopyLink {
    /// Source, relative to the build context.
    pub source: String,
    /// Destination, relative to the image root `/`.
    pub dest: String,
}

fn join_image_path(workdir: &str, dest: &str) -> String {
    let full = if dest.starts_with('/') {
        dest.to_owned()
    } else {
        format!("{}/{}", workdir.trim_end_matches('/'), dest)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// Read the `COPY` lines of a Dockerfile. `COPY --from=...` (another build
/// stage) is ignored: those files are build output, not checkout files.
pub fn copy_links(dockerfile: &str) -> Vec<CopyLink> {
    let mut workdir = "/".to_owned();
    let mut links = Vec::new();
    for raw in dockerfile.lines() {
        let line = raw.trim();
        let mut words = line.split_whitespace();
        match words.next() {
            Some("WORKDIR") => {
                if let Some(dir) = words.next() {
                    workdir = format!("/{}", join_image_path(&workdir, dir));
                }
            }
            Some("COPY") => {
                let args: Vec<&str> = words.collect();
                if args.iter().any(|arg| arg.starts_with("--from")) {
                    continue;
                }
                let args: Vec<&str> = args.into_iter().filter(|arg| !arg.starts_with("--")).collect();
                if args.len() < 2 {
                    continue;
                }
                let (dest, sources) = args.split_last().expect("two or more words");
                let into_dir = dest.ends_with('/') || *dest == "." || dest.ends_with("/.") || sources.len() > 1;
                for source in sources {
                    let source = source.trim_end_matches('/');
                    let target = if into_dir {
                        let name = Path::new(source).file_name().map_or(source.to_owned(), |n| n.to_string_lossy().into_owned());
                        join_image_path(&workdir, &format!("{}/{name}", dest.trim_end_matches('/')))
                    } else {
                        join_image_path(&workdir, dest)
                    };
                    links.push(CopyLink {
                        source: source.to_owned(),
                        dest: target,
                    });
                }
            }
            _ => {}
        }
    }
    links
}

/// Build the image tree for one service: `<app_root>/<image path>` links to
/// `<context>/<source>`. The tree is rebuilt on each start.
pub fn assemble(context: &Path, dockerfile: &Path, app_root: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(dockerfile)
        .map_err(|error| format!("cannot read {}: {error}", dockerfile.display()))?;
    if app_root.exists() {
        std::fs::remove_dir_all(app_root).map_err(|error| format!("cannot reset {}: {error}", app_root.display()))?;
    }
    std::fs::create_dir_all(app_root).map_err(|error| error.to_string())?;
    for link in copy_links(&text) {
        let source = context.join(&link.source);
        if !source.exists() {
            // The image build would fail on a missing source; a host run can
            // still start without an optional file (for example uv.lock).
            continue;
        }
        let target = app_root.join(&link.dest);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        if target.symlink_metadata().is_ok() {
            continue;
        }
        std::os::unix::fs::symlink(&source, &target)
            .map_err(|error| format!("cannot link {}: {error}", target.display()))?;
    }
    Ok(())
}

fn lock_stamp(project: &Path, args: &[&str]) -> String {
    let meta = |name: &str| {
        std::fs::metadata(project.join(name))
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    };
    format!("{}:{}:{}", meta("uv.lock"), meta("pyproject.toml"), args.join(" "))
}

/// Create or update the locked environment of a uv project. It runs only
/// when `uv.lock`, `pyproject.toml` or the sync arguments change.
pub fn ensure_venv(uv: &Path, project: &Path, venv: &Path, args: &[&str], path_env: &str) -> Result<(), String> {
    let stamp_file = venv.join(".vexa-sync-stamp");
    let stamp = lock_stamp(project, args);
    if std::fs::read_to_string(&stamp_file).is_ok_and(|old| old == stamp) && venv.join("bin/python").exists() {
        return Ok(());
    }
    println!("vexa-daemon: syncing Python environment {}", venv.display());
    let output = Command::new(uv)
        .args(["sync", "--frozen", "--no-install-project", "--python", "3.12"])
        .args(args)
        .current_dir(project)
        .env("UV_PROJECT_ENVIRONMENT", venv)
        .env("PATH", path_env)
        .env_remove("VIRTUAL_ENV")
        .output()
        .map_err(|error| format!("cannot run uv: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "uv sync failed for {}: {}",
            project.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    std::fs::write(&stamp_file, stamp).map_err(|error| error.to_string())
}

/// A Python service described by its Compose build.
#[derive(Clone, Debug)]
pub struct PyApp {
    pub name: &'static str,
    /// Build context, relative to the checkout.
    pub context: &'static str,
    /// Dockerfile, relative to the checkout.
    pub dockerfile: &'static str,
    /// The uv project (pyproject.toml + uv.lock), relative to the checkout.
    pub project: &'static str,
    /// `uv sync` arguments from the Dockerfile.
    pub sync: &'static [&'static str],
    /// The image's PYTHONPATH, relative to the image root.
    pub pythonpath: &'static str,
    /// The image's working directory, relative to the image root.
    pub workdir: &'static str,
}

impl PyApp {
    pub fn venv(&self, runtime: &Path) -> PathBuf {
        runtime.join("venvs").join(self.name)
    }

    pub fn root(&self, runtime: &Path) -> PathBuf {
        runtime.join("apps").join(self.name)
    }

    /// Only the locked environment (for a process group, which has no image).
    pub fn prepare_env(&self, source: &Path, runtime: &Path, uv: &Path, path_env: &str) -> Result<(), String> {
        ensure_venv(uv, &source.join(self.project), &self.venv(runtime), self.sync, path_env)
    }

    pub fn prepare(&self, source: &Path, runtime: &Path, uv: &Path, path_env: &str) -> Result<(), String> {
        assemble(&source.join(self.context), &source.join(self.dockerfile), &self.root(runtime))?;
        ensure_venv(uv, &source.join(self.project), &self.venv(runtime), self.sync, path_env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_copy_destinations_like_docker() {
        let text = "FROM python\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nCOPY src ./src\n\
                    COPY --from=build /x /y\nCOPY core/a/b.json ./meetings/contracts/b.json\n\
                    COPY behavior /behavior\nWORKDIR /app/src\nCOPY extra.txt .\n";
        let links = copy_links(text);
        let pairs: Vec<(&str, &str)> = links.iter().map(|l| (l.source.as_str(), l.dest.as_str())).collect();
        assert_eq!(
            pairs,
            vec![
                ("pyproject.toml", "app/pyproject.toml"),
                ("uv.lock", "app/uv.lock"),
                ("src", "app/src"),
                ("core/a/b.json", "app/meetings/contracts/b.json"),
                ("behavior", "behavior"),
                ("extra.txt", "app/src/extra.txt"),
            ]
        );
    }

    #[test]
    fn assembles_a_symlink_tree() {
        let base = std::env::temp_dir().join(format!("vexa-pyapp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let context = base.join("ctx");
        std::fs::create_dir_all(context.join("src/pkg")).unwrap();
        std::fs::write(context.join("src/pkg/__init__.py"), "").unwrap();
        std::fs::write(context.join("Dockerfile"), "WORKDIR /app\nCOPY src ./src\nCOPY missing ./missing\n").unwrap();
        let root = base.join("root");
        assemble(&context, &context.join("Dockerfile"), &root).unwrap();
        assert!(root.join("app/src/pkg/__init__.py").is_file());
        assert!(!root.join("app/missing").exists());
        // A second run rebuilds the tree without error.
        assemble(&context, &context.join("Dockerfile"), &root).unwrap();
    }
}
