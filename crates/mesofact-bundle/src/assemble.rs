//! Assemble a built mesofact app into a W272 **bundle** — the content-addressed
//! unit the store publishes and a node materializes.
//!
//! Part of R599-F2, moved here from `mesofact-build` under R599-T5. It lived in
//! the mesofact-build subcamp originally, but that crate pulls rolldown +
//! lightningcss + deno_core (V8), so anything linking it inherits the whole
//! build toolchain. The operator driver (`yah cloud bundle`) needs to *emit* a
//! bundle without being able to *build* one, and the yah CLI is deliberately
//! V8-less (R490-F2). Assembly is pure `std::fs` + blake3 + toml, so it belongs
//! next to the manifest types it writes; `mesofact-build` re-exports from here
//! so there is exactly one implementation and no drift.
//!
//! A vanilla bundle's tree (W272 §1):
//!
//! ```text
//! <bundle>/
//!   manifest.toml
//!   app/
//!     mesofact.routes.ts        # routes/config
//!     dist/…                    # built TS + rendered assets (the build out_dir)
//! ```
//!
//! A custom (`runtime = "self"`) bundle additionally carries
//! `bins/<triple>/serve`. The only shape difference between the two is whether
//! `bins/` is present and what `runtime` names — there is one format.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{BundleError, BundleHash, BundleManifest, BundleRuntime, SCHEMA_VERSION};

/// Wrap an I/O failure with the path that caused it. Bare `io::Error` loses the
/// filename, which is the only thing that makes an assembly failure actionable.
fn io(context: impl AsRef<str>, e: std::io::Error) -> BundleError {
    BundleError::Io(format!("{}: {e}", context.as_ref()))
}

/// One file destined for a bundle: `(path within the bundle, source on disk)`.
/// The bundle path is always relative and forward-slashed, e.g.
/// `"app/dist/index.html"` or `"bins/x86_64-unknown-linux-musl/serve"`.
pub type BundleFile = (String, PathBuf);

/// Recursively enumerate the regular files under `dir`, mapping each to a
/// bundle path `"<prefix>/<relative-path>"`. Results are sorted for determinism.
pub fn collect_dir(prefix: &str, dir: &Path) -> Result<Vec<BundleFile>, BundleError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = fs::read_dir(&d).map_err(|e| io(format!("reading {}", d.display()), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io(format!("reading {}", d.display()), e))?;
            let ft = entry
                .file_type()
                .map_err(|e| io(format!("stat {}", entry.path().display()), e))?;
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let rel = p.strip_prefix(dir).expect("walker yields paths under dir");
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                out.push((format!("{prefix}/{rel_str}"), p));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Assemble a bundle tree at `dest` from `files`, returning the [`BundleManifest`].
///
/// Copies each source file to `<dest>/<bundle-path>`, hashes it (BLAKE3) into the
/// manifest `content` map, and writes `<dest>/manifest.toml` last. Files under
/// `bins/` are made executable (0755) — they are serve binaries. Re-assembling
/// over an existing `dest` overwrites in place (idempotent). `dest` MUST NOT sit
/// inside any of the source dirs being collected, or the copy would recurse into
/// its own output.
pub fn assemble_bundle(
    dest: &Path,
    name: &str,
    runtime: BundleRuntime,
    files: &[BundleFile],
) -> Result<BundleManifest, BundleError> {
    fs::create_dir_all(dest).map_err(|e| io(format!("creating bundle dir {}", dest.display()), e))?;

    let mut content = BTreeMap::new();
    for (bundle_path, src) in files {
        let bytes = fs::read(src).map_err(|e| io(format!("reading {}", src.display()), e))?;
        let hash = BundleHash::of(&bytes);
        let out = dest.join(bundle_path);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| io(format!("creating {}", parent.display()), e))?;
        }
        fs::write(&out, &bytes).map_err(|e| io(format!("writing {}", out.display()), e))?;

        // Serve binaries must stay executable after the copy.
        #[cfg(unix)]
        if bundle_path.starts_with("bins/") {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = fs::metadata(&out)
                .map_err(|e| io(format!("stat {}", out.display()), e))?
                .permissions();
            perm.set_mode(0o755);
            fs::set_permissions(&out, perm)
                .map_err(|e| io(format!("chmod +x {}", out.display()), e))?;
        }

        content.insert(bundle_path.clone(), hash);
    }

    let manifest = BundleManifest {
        schema_version: SCHEMA_VERSION,
        name: name.to_string(),
        runtime,
        content,
    };
    let toml = manifest.to_toml_string()?;
    fs::write(dest.join("manifest.toml"), toml).map_err(|e| {
        io(
            format!("writing {}", dest.join("manifest.toml").display()),
            e,
        )
    })?;
    Ok(manifest)
}

/// Assemble a **vanilla** bundle from a finished mesofact build: `app/` holds the
/// routes file plus the built `dist/` tree, no `bins/`, and `runtime =
/// "mesofact/<runtime_version>"` so the node resolves the stock serve runtime.
///
/// `out_dir` is the build's dist directory; `runtime_version` is the version of
/// `mesofact serve` that should serve this bundle (e.g. the framework version
/// the app was built against).
///
/// NOTE: nothing currently stages `runtimes/<runtime>/<triple>/serve` on a node,
/// so a vanilla bundle will fail serve-binary resolution at deploy time. Until
/// that staging path exists, prefer [`assemble_self_bundle`].
pub fn assemble_vanilla_bundle(
    dest: &Path,
    name: &str,
    runtime_version: &str,
    project_root: &Path,
    out_dir: &Path,
) -> Result<BundleManifest, BundleError> {
    let mut files = collect_dir("app/dist", out_dir)?;
    let routes = project_root.join("mesofact.routes.ts");
    if routes.exists() {
        files.push(("app/mesofact.routes.ts".to_string(), routes));
    }
    files.sort();
    assemble_bundle(
        dest,
        name,
        BundleRuntime::Mesofact {
            version: runtime_version.to_string(),
        },
        &files,
    )
}

/// Assemble a **self-contained** (`runtime = "self"`) bundle: the vanilla tree
/// plus `bins/<triple>/serve`, so the node serves it with the binary the bundle
/// carries and resolves no runtime asset at all.
///
/// This is the shape to reach for today. A vanilla bundle depends on a node-side
/// runtime cache that nothing populates yet, whereas a self-contained bundle is
/// closed over its own serve binary and works against a stock node.
pub fn assemble_self_bundle(
    dest: &Path,
    name: &str,
    project_root: &Path,
    out_dir: &Path,
    serve_bins: &[(String, PathBuf)],
) -> Result<BundleManifest, BundleError> {
    let mut files = collect_dir("app/dist", out_dir)?;
    let routes = project_root.join("mesofact.routes.ts");
    if routes.exists() {
        files.push(("app/mesofact.routes.ts".to_string(), routes));
    }
    for (triple, bin) in serve_bins {
        files.push((format!("bins/{triple}/serve"), bin.clone()));
    }
    files.sort();
    assemble_bundle(dest, name, BundleRuntime::SelfContained, &files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn collect_dir_walks_recursively_and_prefixes() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("index.html"), b"a");
        write(&dir.path().join("assets/main.js"), b"b");
        write(&dir.path().join("assets/nested/x.css"), b"c");

        let files = collect_dir("app/dist", dir.path()).unwrap();
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "app/dist/assets/main.js",
                "app/dist/assets/nested/x.css",
                "app/dist/index.html",
            ]
        );
    }

    #[test]
    fn assemble_bundle_copies_files_hashes_and_writes_manifest() {
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        write(&src.path().join("index.html"), b"<html>home</html>");

        let files = vec![("app/index.html".to_string(), src.path().join("index.html"))];
        let manifest = assemble_bundle(
            dest.path(),
            "yah-marketing",
            BundleRuntime::Mesofact {
                version: "0.8.20".into(),
            },
            &files,
        )
        .unwrap();

        // Manifest content matches the copied bytes' hash.
        assert_eq!(
            manifest.content.get("app/index.html").unwrap(),
            &BundleHash::of(b"<html>home</html>")
        );
        // The file was copied into the bundle tree.
        assert_eq!(
            fs::read(dest.path().join("app/index.html")).unwrap(),
            b"<html>home</html>"
        );
        // manifest.toml on disk round-trips back to the returned manifest.
        let text = fs::read_to_string(dest.path().join("manifest.toml")).unwrap();
        assert_eq!(BundleManifest::from_toml_str(&text).unwrap(), manifest);
    }

    #[test]
    fn assemble_vanilla_bundle_stages_routes_and_dist() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(
            &project.path().join("mesofact.routes.ts"),
            b"export default {}",
        );
        write(&out_dir.join("index.html"), b"<html>");
        write(&out_dir.join("hydrate/app.hash.js"), b"hydrate");

        let manifest =
            assemble_vanilla_bundle(dest.path(), "yah-marketing", "0.8.20", project.path(), &out_dir)
                .unwrap();

        assert!(matches!(manifest.runtime, BundleRuntime::Mesofact { .. }));
        assert!(manifest.content.contains_key("app/mesofact.routes.ts"));
        assert!(manifest.content.contains_key("app/dist/index.html"));
        assert!(manifest.content.contains_key("app/dist/hydrate/app.hash.js"));
        // A vanilla bundle carries no serve binaries.
        assert!(!manifest.content.keys().any(|k| k.starts_with("bins/")));
        assert!(dest.path().join("app/mesofact.routes.ts").exists());
    }

    #[test]
    fn assemble_self_bundle_carries_its_serve_binary() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        let bin = project.path().join("serve");
        write(&out_dir.join("index.html"), b"<html>");
        write(&bin, b"\x7fELF-ish");

        let manifest = assemble_self_bundle(
            dest.path(),
            "yah-marketing",
            project.path(),
            &out_dir,
            &[("x86_64-unknown-linux-musl".to_string(), bin)],
        )
        .unwrap();

        assert!(matches!(manifest.runtime, BundleRuntime::SelfContained));
        assert!(manifest
            .content
            .contains_key("bins/x86_64-unknown-linux-musl/serve"));
        assert!(manifest.content.contains_key("app/dist/index.html"));
        // The wire form is what kamaji matches on to skip runtime resolution.
        assert_eq!(manifest.runtime.as_wire(), "self");
    }

    #[test]
    #[cfg(unix)]
    fn bins_are_made_executable() {
        use std::os::unix::fs::PermissionsExt;
        let src = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        write(&src.path().join("serve"), b"\x7fELF-ish");

        let files = vec![(
            "bins/x86_64-unknown-linux-musl/serve".to_string(),
            src.path().join("serve"),
        )];
        assemble_bundle(dest.path(), "app", BundleRuntime::SelfContained, &files).unwrap();

        let mode = fs::metadata(dest.path().join("bins/x86_64-unknown-linux-musl/serve"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "serve binary should be executable");
    }
}
