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
//!     mesofact.config.toml      # [publish] block for a --revalidate receiver (if present)
//!     src/data/…                # each route's declared `data_inputs` (see below)
//!     dist/…                    # built TS + rendered assets (the build out_dir)
//! ```
//!
//! `data_inputs` are staged because a `--revalidate` receiver **re-reads them
//! at poke time** — `mesofact-render`'s `read_data_inputs` resolves each
//! declared path against the workload root (`<bundle>/app`), not against the
//! machine that ran the build. A bundle carrying only `dist/` renders fine as
//! static but fails the moment it is poked, which is the one failure mode a
//! receiver deploy exists to avoid (R330-F12).
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
    stage_app_config(project_root, &mut files);
    stage_data_inputs(project_root, out_dir, &mut files)?;
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
    assemble_self_bundle_with(dest, name, project_root, out_dir, serve_bins, &[])
}

/// [`assemble_self_bundle`] plus **sidecar binaries** — extra executables the
/// node forks alongside `serve`, staged at `bins/<triple>/<name>` (R330-F31).
///
/// The motivating case is `almanac-feed`, the feed-fetch tier: a bundle whose
/// routes render from a live feed needs something on the node to refresh that
/// feed's artifact, and the node has no package manager. Shipping the fetcher
/// inside the bundle keeps a served bundle closed over everything it needs, the
/// same property that makes `runtime = "self"` the shape to reach for.
///
/// `sidecar_bins` entries are `(binary name, target triple, source path)`.
pub fn assemble_self_bundle_with(
    dest: &Path,
    name: &str,
    project_root: &Path,
    out_dir: &Path,
    serve_bins: &[(String, PathBuf)],
    sidecar_bins: &[(String, String, PathBuf)],
) -> Result<BundleManifest, BundleError> {
    let mut files = collect_dir("app/dist", out_dir)?;
    stage_app_config(project_root, &mut files);
    stage_data_inputs(project_root, out_dir, &mut files)?;
    for (triple, bin) in serve_bins {
        files.push((format!("bins/{triple}/serve"), bin.clone()));
    }
    for (bin_name, triple, bin) in sidecar_bins {
        // `serve` is the runtime's own reserved name — a sidecar claiming it
        // would silently replace the server with something that isn't one.
        if bin_name == "serve" {
            return Err(BundleError::Io(format!(
                "sidecar bin for {triple} is named \"serve\", which is the runtime's own \
                 binary — pick a distinct name"
            )));
        }
        files.push((format!("bins/{triple}/{bin_name}"), bin.clone()));
    }
    files.sort();
    assemble_bundle(dest, name, BundleRuntime::SelfContained, &files)
}

/// Stage the project-root config files a served bundle carries alongside its
/// `dist/` tree, when present: `mesofact.routes.ts` (routes/config the runtime
/// reads) and `mesofact.config.toml` (the `[publish]` block a `mesofact serve
/// --revalidate` receiver needs, R330-F12 — creds still resolve from env, so
/// only the non-secret bucket/prefix/endpoint/zone travels here). Both land
/// under `app/` so a receiver pointed at `<bundle>/app` finds them at the same
/// relative paths a source workload uses.
fn stage_app_config(project_root: &Path, files: &mut Vec<BundleFile>) {
    for name in ["mesofact.routes.ts", "mesofact.config.toml"] {
        let src = project_root.join(name);
        if src.exists() {
            files.push((format!("app/{name}"), src));
        }
    }
}

/// Stage every `data_inputs` file the built manifest declares, so a
/// `--revalidate` receiver can re-read them on the node (see the module docs).
///
/// Paths come from `<out_dir>/manifest.json` and are relative to
/// `project_root`, which is exactly how `mesofact-render` resolves them against
/// the workload root — so staging them at `app/<rel>` reproduces the build-time
/// layout on the node.
///
/// A missing `manifest.json` is not an error: `assemble_bundle` is also driven
/// directly (`yah cloud bundle build` over a pre-built tree, tests) where there
/// is nothing to read. A manifest that *declares* an input we cannot stage IS
/// an error — silently dropping it turns a deploy-time failure into a
/// poke-time one, months later, on the node.
fn stage_data_inputs(
    project_root: &Path,
    out_dir: &Path,
    files: &mut Vec<BundleFile>,
) -> Result<(), BundleError> {
    /// The sliver of the mesofact build manifest this crate needs. Deliberately
    /// not `mesofact_core::manifest::Manifest` — that type lives in the
    /// mesofact subcamp and pulls the render-side vocabulary with it, and this
    /// crate is the V8-less assembly half (see the module docs).
    #[derive(serde::Deserialize)]
    struct ManifestSliver {
        #[serde(default)]
        routes: Vec<RouteSliver>,
    }
    #[derive(serde::Deserialize)]
    struct RouteSliver {
        #[serde(default)]
        data_inputs: Vec<String>,
    }

    let manifest_path = out_dir.join("manifest.json");
    let Ok(raw) = fs::read_to_string(&manifest_path) else {
        return Ok(());
    };
    let manifest: ManifestSliver = serde_json::from_str(&raw)
        .map_err(|e| BundleError::Io(format!("parsing {}: {e}", manifest_path.display())))?;

    let mut seen = std::collections::BTreeSet::new();
    for rel in manifest.routes.into_iter().flat_map(|r| r.data_inputs) {
        // A declared input must stay inside `app/`. `..` would land the copy
        // outside the bundle root and, worse, resolve to something different on
        // the node than it did at build time.
        if Path::new(&rel)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
            || Path::new(&rel).is_absolute()
        {
            return Err(BundleError::Io(format!(
                "data_inputs entry {rel:?} escapes the app root; declare it as a path under the project"
            )));
        }
        if !seen.insert(rel.clone()) {
            continue; // routes commonly share one data file
        }
        let src = project_root.join(&rel);
        if !src.is_file() {
            return Err(BundleError::Io(format!(
                "manifest declares data_inputs {rel:?} but {} is not a file — a --revalidate receiver would fail to re-render this route on the node",
                src.display()
            )));
        }
        files.push((format!("app/{}", rel.replace('\\', "/")), src));
    }
    Ok(())
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

    /// A `mesofact.config.toml` at the project root is staged into the bundle so
    /// a `mesofact serve --revalidate` receiver on the node finds its `[publish]`
    /// block at `<bundle>/app/mesofact.config.toml` (R330-F12). Absent → no key,
    /// which is why the existing digest-shaped tests stay unaffected.
    #[test]
    fn assemble_stages_mesofact_config_when_present() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(&out_dir.join("index.html"), b"<html>");
        write(
            &project.path().join("mesofact.config.toml"),
            b"[publish]\nbucket = \"yah-dev\"\nprefix = \"yah-marketing/cloud\"\n",
        );

        let manifest =
            assemble_vanilla_bundle(dest.path(), "yah-marketing", "0.8.20", project.path(), &out_dir)
                .unwrap();

        assert!(manifest.content.contains_key("app/mesofact.config.toml"));
        assert_eq!(
            fs::read_to_string(dest.path().join("app/mesofact.config.toml")).unwrap(),
            "[publish]\nbucket = \"yah-dev\"\nprefix = \"yah-marketing/cloud\"\n"
        );
    }

    /// No config at the project root → no `app/mesofact.config.toml` key. Guards
    /// the invariant that the staging is purely additive when the file is absent.
    #[test]
    fn assemble_omits_config_when_absent() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(&out_dir.join("index.html"), b"<html>");

        let manifest =
            assemble_vanilla_bundle(dest.path(), "yah-marketing", "0.8.20", project.path(), &out_dir)
                .unwrap();

        assert!(!manifest.content.contains_key("app/mesofact.config.toml"));
    }

    /// R330-F12: the build manifest's declared `data_inputs` are staged at
    /// `app/<rel>` — the same path the receiver re-reads them from on the node.
    /// Two routes sharing one file stage it once.
    #[test]
    fn assemble_stages_declared_data_inputs_once_each() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(&out_dir.join("index.html"), b"<html>");
        write(
            &out_dir.join("manifest.json"),
            br#"{"routes":[
                 {"route":"/releases","data_inputs":["src/data/releases.json"]},
                 {"route":"/issues","data_inputs":["src/data/issues.json"]},
                 {"route":"/issues/:id","data_inputs":["src/data/issues.json"]},
                 {"route":"/"}
               ]}"#,
        );
        write(
            &project.path().join("src/data/releases.json"),
            br#"{"releases":[]}"#,
        );
        write(&project.path().join("src/data/issues.json"), br#"{"items":[]}"#);

        let manifest =
            assemble_vanilla_bundle(dest.path(), "yah-marketing", "0.8.20", project.path(), &out_dir)
                .unwrap();

        assert!(manifest.content.contains_key("app/src/data/releases.json"));
        assert!(manifest.content.contains_key("app/src/data/issues.json"));
        assert_eq!(
            fs::read_to_string(dest.path().join("app/src/data/releases.json")).unwrap(),
            r#"{"releases":[]}"#
        );
        // Deduped: the shared issues.json appears exactly once in `content`
        // (a BTreeMap would hide a duplicate — count the staged keys instead).
        assert_eq!(
            manifest
                .content
                .keys()
                .filter(|k| k.as_str() == "app/src/data/issues.json")
                .count(),
            1
        );
    }

    /// A declared-but-missing `data_inputs` file fails the *assembly*, not the
    /// first poke months later on the node. This is the whole point of staging
    /// them from the manifest rather than best-effort globbing `src/data`.
    #[test]
    fn assemble_rejects_declared_data_input_that_is_not_on_disk() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(&out_dir.join("index.html"), b"<html>");
        write(
            &out_dir.join("manifest.json"),
            br#"{"routes":[{"route":"/releases","data_inputs":["src/data/releases.json"]}]}"#,
        );

        let err = assemble_vanilla_bundle(
            dest.path(),
            "yah-marketing",
            "0.8.20",
            project.path(),
            &out_dir,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("src/data/releases.json"), "got {msg}");
        assert!(msg.contains("revalidate"), "got {msg}");
    }

    /// A `data_inputs` path that climbs out of the project root is rejected —
    /// it would copy to a bundle path outside `app/` and resolve differently on
    /// the node than it did at build time.
    #[test]
    fn assemble_rejects_data_input_escaping_the_app_root() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(&out_dir.join("index.html"), b"<html>");
        write(
            &out_dir.join("manifest.json"),
            br#"{"routes":[{"route":"/x","data_inputs":["../secrets.json"]}]}"#,
        );

        let err = assemble_vanilla_bundle(
            dest.path(),
            "yah-marketing",
            "0.8.20",
            project.path(),
            &out_dir,
        )
        .unwrap_err();
        assert!(err.to_string().contains("escapes the app root"), "got {err}");
    }

    /// No `manifest.json` in the out dir (assembly driven over a pre-built tree,
    /// or the existing fixtures) → staging is a no-op, not a failure.
    #[test]
    fn assemble_without_a_build_manifest_stages_no_data_inputs() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        write(&out_dir.join("index.html"), b"<html>");

        let manifest =
            assemble_vanilla_bundle(dest.path(), "yah-marketing", "0.8.20", project.path(), &out_dir)
                .unwrap();

        assert!(!manifest.content.keys().any(|k| k.starts_with("app/src/")));
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

    /// R330-F31: a sidecar bin lands at `bins/<triple>/<name>` next to `serve`,
    /// so a bundle that renders from a live feed carries the fetcher that keeps
    /// that feed fresh on the node.
    #[test]
    fn assemble_self_bundle_with_carries_sidecar_bins() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        let serve = project.path().join("serve");
        let feed = project.path().join("almanac-feed");
        write(&out_dir.join("index.html"), b"<html>");
        write(&serve, b"\x7fELF-serve");
        write(&feed, b"\x7fELF-feed");

        let manifest = assemble_self_bundle_with(
            dest.path(),
            "yah-marketing",
            project.path(),
            &out_dir,
            &[("x86_64-unknown-linux-musl".to_string(), serve)],
            &[(
                "almanac-feed".to_string(),
                "x86_64-unknown-linux-musl".to_string(),
                feed,
            )],
        )
        .unwrap();

        assert!(manifest
            .content
            .contains_key("bins/x86_64-unknown-linux-musl/serve"));
        assert!(manifest
            .content
            .contains_key("bins/x86_64-unknown-linux-musl/almanac-feed"));
    }

    /// A sidecar may not be called `serve` — it would land on the runtime's own
    /// path and the node would fork it as the server.
    #[test]
    fn assemble_rejects_a_sidecar_named_serve() {
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        let bin = project.path().join("bin");
        write(&out_dir.join("index.html"), b"<html>");
        write(&bin, b"\x7fELF-ish");

        let err = assemble_self_bundle_with(
            dest.path(),
            "yah-marketing",
            project.path(),
            &out_dir,
            &[],
            &[(
                "serve".to_string(),
                "x86_64-unknown-linux-musl".to_string(),
                bin,
            )],
        )
        .unwrap_err();
        assert!(err.to_string().contains("runtime's own"), "got {err}");
    }

    /// Sidecars are executables too — a staged fetcher the node cannot exec is
    /// a deploy that looks fine and never refreshes anything.
    #[test]
    #[cfg(unix)]
    fn sidecar_bins_are_executable() {
        use std::os::unix::fs::PermissionsExt;
        let project = TempDir::new().unwrap();
        let out_dir = project.path().join("dist");
        let dest = TempDir::new().unwrap();
        let feed = project.path().join("almanac-feed");
        write(&out_dir.join("index.html"), b"<html>");
        write(&feed, b"\x7fELF-feed");

        assemble_self_bundle_with(
            dest.path(),
            "yah-marketing",
            project.path(),
            &out_dir,
            &[],
            &[(
                "almanac-feed".to_string(),
                "x86_64-unknown-linux-musl".to_string(),
                feed,
            )],
        )
        .unwrap();

        let mode = fs::metadata(dest.path().join("bins/x86_64-unknown-linux-musl/almanac-feed"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "sidecar must stay executable");
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
