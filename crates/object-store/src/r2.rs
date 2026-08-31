//! Cloudflare R2 implementation of [`ObjectStore`] over S3-compat SigV4.
//!
//! Uses `local_driver::s3_sign` helpers for signature computation and
//! `reqwest::blocking` for HTTP so the [`ObjectStore`] trait stays synchronous.
//! Async consumers wrap calls in `tokio::task::spawn_blocking`.
//!
//! ## Endpoint
//!
//! R2's S3-compat endpoint is `https://<account_id>.r2.cloudflarestorage.com`.
//! Region is always `"auto"`. Bucket lives in the URL path:
//! `https://<account_id>.r2.cloudflarestorage.com/<bucket>/<key>`.
//!
//! ## list_prefix
//!
//! Issues `GET /<bucket>?list-type=2&prefix=<encoded>` (ListObjectsV2) and
//! parses the `<Key>…</Key>` elements out of the XML body. Continues with
//! `&continuation-token=<…>` while `<IsTruncated>true</IsTruncated>` so
//! prefixes larger than the 1000-key page size return complete.
//!
//! @yah:relay(R630, "Object-store correctness + tooling gaps surfaced by standing up the cr.yah.dev registry")
//! @yah:at(2026-07-23T03:06:57Z)
//! @yah:status(open)
//! @yah:next("Both children were found while building yah-cr (the R2-backed OCI registry) on 2026-07-22 and are independent of that work — they are latent defects in shared object-store code that any caller can hit.")
//! @yah:next("Start with the SigV4 child: it is a correctness bug that fails closed but silently constrains every key namespace we can use. The bucket-delete child is additive and can follow.")
//! @yah:gotcha("The SigV4 defect is why cr.yah.dev stores OCI digests as sha256/<hex> instead of the natural sha256:<hex>. That workaround is load-bearing in two files that must stay in lockstep (app/yah/cli/src/cr.rs digest_key, app/yah/workers/yah-cr/src/index.ts digestKey). If the signing bug is fixed, those can be simplified — but only together, and only with a migration for keys already written.")
//! @arch:see(.yah/docs/working/W175-per-publisher-prefix.md)
//! @yah:handoff("Both children fixed and in review. Along the way two further latent defects in the same shared object-store code were found and fixed in-pass, both invisible to every existing test: (1) ObjectStore::delete signed DELETE with sign_s3_empty_body and so 403'd against R2 from the day it landed — which also means `yah cloud service prune` (static_asset_prune.rs) has never reclaimed anything; (2) the ListObjectsV2 parser returned raw XML text, so a key holding & came back as &amp; — harmless before, because such keys couldn't be written, and a broken round-trip the moment B1 made them writable.")
//! @yah:gotcha("2026-08-25: the SigV4 defect is FIXED (R630-B1, in review), so the sha256/<hex> constraint this gotcha describes is lifted — but the workaround was deliberately left in place. Simplifying digest_key / digestKey to the natural sha256:<hex> means rewriting every blob key already in yah-cr-cache: a live-data migration on a running registry, operator-gated, not a drive-by. The two files still must stay in lockstep.")

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, ETAG, IF_MATCH, IF_NONE_MATCH};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};

use local_driver::s3_sign::{
    sign_s3_get_with_query, sign_s3_no_body, sign_s3_put_object, sign_s3_put_object_with,
    uri_encode_key, S3PutOptions,
};

use crate::{Error, ObjectStore, Precondition};

/// R2's S3-compat region. The endpoint always accepts `"auto"`.
const R2_REGION: &str = "auto";

/// Keystore slot for the R2 S3 access key id.
pub const R2_ACCESS_KEY_SLOT: &str = "cloudflare-r2-access-key-id";
/// Keystore slot for the R2 S3 secret key.
pub const R2_SECRET_KEY_SLOT: &str = "cloudflare-r2-secret-key";
/// Env var fallback for the R2 access key id.
pub const R2_ACCESS_KEY_ENV: &str = "CF_R2_ACCESS_KEY_ID";
/// Env var fallback for the R2 secret key.
pub const R2_SECRET_KEY_ENV: &str = "CF_R2_SECRET_KEY";

/// Percent-encoding set for query-string values. SigV4 requires
/// unreserved characters (A-Z a-z 0-9 - _ . ~) to remain literal;
/// everything else gets percent-encoded.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Default content-type for keys with no recognized extension.
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Content-type for an object key, inferred from its file extension.
///
/// R2 stores whatever Content-Type we send on PUT and serves it back verbatim
/// (the CDN custom domain does no extension sniffing). An octet-stream default
/// makes browsers *download* html shells instead of rendering them, so we set
/// an explicit type for the extensions a static site actually ships. Unknown
/// or extensionless keys (pointers, the `_yah-manifest.json` sidecar is `.json`
/// and handled) fall back to [`DEFAULT_CONTENT_TYPE`].
fn content_type_for_key(key: &str) -> &'static str {
    let ext = match key.rsplit_once('.') {
        // A `.` in a directory segment is not an extension.
        Some((_, e)) if !e.contains('/') => e,
        _ => "",
    };
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "xml" => "application/xml",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        _ => DEFAULT_CONTENT_TYPE,
    }
}

/// R2-backed [`ObjectStore`].
///
/// Construct with [`R2ObjectStore::new`] when keys are already in hand,
/// or [`R2ObjectStore::from_vault`] to pull them from the yah keystore
/// (with env-var fallback).
pub struct R2ObjectStore {
    account_id: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    /// Overrides the derived `https://<account_id>.r2.cloudflarestorage.com`.
    /// See [`R2ObjectStore::with_endpoint`].
    endpoint: Option<String>,
    client: Option<Client>,
}

impl Drop for R2ObjectStore {
    fn drop(&mut self) {
        // `reqwest::blocking::Client` owns a background tokio runtime whose
        // Drop panics with "Cannot drop a runtime in a context where blocking
        // is not allowed" when the drop happens inside an async context. This
        // fires when an `Arc<R2ObjectStore>` reaches zero from inside an
        // awaited future (e.g. publish_to_r2). Detach the shutdown onto a
        // fresh OS thread which has no tokio runtime context, so the client's
        // Drop can shut its internal runtime down cleanly. Dep-neutral — this
        // crate keeps its sync/tokio-free profile.
        let Some(client) = self.client.take() else { return };
        std::thread::spawn(move || drop(client));
    }
}

impl R2ObjectStore {
    /// Construct with explicit keys.
    ///
    /// `account_id` is the Cloudflare account id (the subdomain in
    /// `<account_id>.r2.cloudflarestorage.com`).
    pub fn new(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| Error::Backend(format!("reqwest client: {e}")))?;
        Ok(Self {
            account_id: account_id.into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            endpoint: None,
            client: Some(client),
        })
    }

    /// Point this store at an S3-compatible endpoint other than R2 — in
    /// practice, the pond tier's local MinIO (`http://127.0.0.1:9000`).
    ///
    /// Everything else about the store is already endpoint-agnostic: the bucket
    /// lives in the URL path (path-style addressing, which MinIO also speaks)
    /// and SigV4 is signed against whatever host the URL names.
    ///
    /// This exists because without it the pond rehearsal could not exercise the
    /// *read* side of a publish at all. `publish_to_pond` uploads a directory
    /// tree and offers no way to read an object back, so the one part of a
    /// release that is a read-modify-write — the accumulating `index.json` that
    /// https://yah.dev/releases renders from — was the one part a green local
    /// rehearsal proved nothing about (R330-T32). A conditional-write loop that
    /// has never run is a conditional-write loop you do not have.
    ///
    /// The region stays `"auto"`; MinIO accepts it.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        let trimmed = endpoint.trim_end_matches('/');
        self.endpoint = (!trimmed.is_empty()).then(|| trimmed.to_string());
        self
    }

    fn client(&self) -> &Client {
        self.client
            .as_ref()
            .expect("client is Some until Drop takes it")
    }

    /// Construct from the yah keystore (vault), falling back to env vars.
    ///
    /// Reads `cloudflare-r2-access-key-id` / `cloudflare-r2-secret-key` slots
    /// (env fallback `CF_R2_ACCESS_KEY_ID` / `CF_R2_SECRET_KEY`). Returns
    /// [`Error::Auth`] if either is missing.
    pub fn from_vault(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Result<Self, Error> {
        let access_key = fob::get_or_env(R2_ACCESS_KEY_SLOT, R2_ACCESS_KEY_ENV)
            .map_err(|e| Error::Auth(format!("vault read {R2_ACCESS_KEY_SLOT}: {e}")))?
            .ok_or_else(|| {
                Error::Auth(format!(
                    "missing R2 credential: set vault slot {R2_ACCESS_KEY_SLOT} or env {R2_ACCESS_KEY_ENV}"
                ))
            })?;
        let secret_key = fob::get_or_env(R2_SECRET_KEY_SLOT, R2_SECRET_KEY_ENV)
            .map_err(|e| Error::Auth(format!("vault read {R2_SECRET_KEY_SLOT}: {e}")))?
            .ok_or_else(|| {
                Error::Auth(format!(
                    "missing R2 credential: set vault slot {R2_SECRET_KEY_SLOT} or env {R2_SECRET_KEY_ENV}"
                ))
            })?;
        Self::new(account_id, bucket, access_key, secret_key)
    }

    fn endpoint(&self) -> String {
        match &self.endpoint {
            Some(e) => e.clone(),
            None => format!("https://{}.r2.cloudflarestorage.com", self.account_id),
        }
    }

    /// R630-B1: the key is AWS-`UriEncode`d here, at the one place a key becomes
    /// a URL. Doing it here rather than in the signer is what makes the wire
    /// path and the signed path the same bytes — see [`uri_encode_key`]. Before
    /// this, a key holding `:` (an OCI digest `sha256:<hex>`, a timestamp) went
    /// out raw, R2 canonicalized it per spec, and every request 403'd
    /// `SignatureDoesNotMatch`.
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint(), self.bucket, uri_encode_key(key))
    }

    fn bucket_url(&self) -> String {
        format!("{}/{}", self.endpoint(), self.bucket)
    }

    /// The one PUT path, with `Cache-Control` optional (R703-B8).
    ///
    /// `put` and `put_cached` differ only in that header, so they share this
    /// rather than each carrying their own signing + status handling — the
    /// shape where one of two copies quietly stops matching the other.
    fn put_inner(
        &self,
        key: &str,
        data: Vec<u8>,
        cache_control: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.object_url(key);
        let body_sha256 = {
            let mut h = Sha256::new();
            h.update(&data);
            hex::encode(h.finalize())
        };
        let headers = sign_s3_put_object_with(
            &url,
            &body_sha256,
            data.len(),
            R2_REGION,
            &self.access_key,
            &self.secret_key,
            &S3PutOptions {
                content_type: content_type_for_key(key),
                // Generic object-store put — the BLAKE3 stamp is a static-asset
                // catalog concern, not a property of every object (R546-B10).
                blake3_meta: None,
                cache_control,
            },
        )
        .map_err(|e| Error::Backend(format!("sign PUT {key}: {e}")))?;

        let resp = self
            .client()
            .put(&url)
            .headers(headers)
            .body(data)
            .send()
            .map_err(|e| io_err(&format!("PUT {key}"), e))?;
        check_status(resp, "PUT", key)
    }
}

/// Convert a reqwest error into our generic [`Error`].
fn io_err(ctx: &str, e: impl std::fmt::Display) -> Error {
    Error::Io(format!("{ctx}: {e}"))
}

impl ObjectStore for R2ObjectStore {
    fn locate(&self, key: &str) -> String {
        self.object_url(key)
    }

    fn put(&self, key: &str, data: Vec<u8>) -> Result<(), Error> {
        self.put_inner(key, data, None)
    }

    fn put_cached(&self, key: &str, data: Vec<u8>, cache_control: &str) -> Result<(), Error> {
        self.put_inner(key, data, Some(cache_control))
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let url = self.object_url(key);
        // GET has no body: reqwest drops the `content-length: 0` header on the
        // wire, so signing it (as `sign_s3_empty_body` does) yields a signature
        // the server can't reproduce → 403 SignatureDoesNotMatch. Sign with the
        // content-length-free helper instead, exactly like ListObjectsV2. The
        // empty query string is correct for a plain object GET.
        let headers = sign_s3_get_with_query(
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign GET {key}: {e}")))?;

        let resp = self
            .client()
            .get(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("GET {key}"), e))?;

        match resp.status() {
            StatusCode::OK => {
                let bytes = resp
                    .bytes()
                    .map_err(|e| io_err(&format!("read GET {key}"), e))?;
                Ok(Some(bytes.to_vec()))
            }
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(status_err("GET", key, s, resp.text().ok())),
        }
    }

    fn head(&self, key: &str) -> Result<bool, Error> {
        let url = self.object_url(key);
        // HEAD is body-less like GET: sign without content-length (see `get`).
        let headers = sign_s3_no_body(
            "HEAD",
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign HEAD {key}: {e}")))?;

        let resp = self
            .client()
            .head(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("HEAD {key}"), e))?;

        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(status_err("HEAD", key, s, None)),
        }
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let url = self.object_url(key);
        // R630-F2: DELETE is body-less, so it signs like GET/HEAD and NOT with
        // `sign_s3_empty_body` — reqwest strips the `content-length: 0` that
        // signer puts in the canonical headers, R2 recomputes a different
        // signature, and every DELETE comes back 403 SignatureDoesNotMatch.
        // This code had never been run against live R2 (the trait tests use the
        // in-memory store), so `ObjectStore::delete` was 100% broken on R2 from
        // the day it landed. Confirmed live 2026-08-25, before and after.
        let headers = sign_s3_no_body(
            "DELETE",
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign DELETE {key}: {e}")))?;

        let resp = self
            .client()
            .delete(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("DELETE {key}"), e))?;

        match resp.status() {
            // S3 DELETE on a missing key returns 204 too — both are success
            // semantics for an idempotent delete.
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(()),
            s => Err(status_err("DELETE", key, s, resp.text().ok())),
        }
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error> {
        Ok(self
            .list_prefix_detailed(prefix)?
            .into_iter()
            .map(|m| m.key)
            .collect())
    }

    fn put_if(&self, key: &str, data: Vec<u8>, cond: Precondition) -> Result<String, Error> {
        let url = self.object_url(key);
        let body_sha256 = {
            let mut h = Sha256::new();
            h.update(&data);
            hex::encode(h.finalize())
        };
        // Sign the same fixed header set as an unconditional PUT. The conditional
        // header (If-Match / If-None-Match) is added *unsigned* afterwards: SigV4
        // only covers the headers in `SignedHeaders`, and S3/R2 honor extra
        // unsigned headers — so the precondition is enforced server-side without
        // touching the signer.
        let mut headers = sign_s3_put_object(
            &url,
            &body_sha256,
            content_type_for_key(key),
            data.len(),
            R2_REGION,
            &self.access_key,
            &self.secret_key,
            None,
        )
        .map_err(|e| Error::Backend(format!("sign PUT {key}: {e}")))?;

        match &cond {
            Precondition::IfAbsent => {
                headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
            }
            Precondition::IfMatch(etag) => {
                let v = HeaderValue::from_str(etag)
                    .map_err(|e| Error::Backend(format!("invalid If-Match etag {etag:?}: {e}")))?;
                headers.insert(IF_MATCH, v);
            }
        }

        let resp = self
            .client()
            .put(&url)
            .headers(headers)
            .body(data)
            .send()
            .map_err(|e| io_err(&format!("PUT(if) {key}"), e))?;

        let status = resp.status();
        if status == StatusCode::PRECONDITION_FAILED {
            return Err(Error::PreconditionFailed(format!(
                "put_if {key}: precondition not met ({cond:?})"
            )));
        }
        if !status.is_success() {
            return Err(status_err("PUT(if)", key, status, resp.text().ok()));
        }
        // Prefer the ETag echoed in the PUT response; fall back to a HEAD if a
        // backend ever omits it (R2 always returns it).
        match resp.headers().get(ETAG).and_then(|v| v.to_str().ok()) {
            Some(e) => Ok(e.to_string()),
            None => self
                .etag(key)?
                .ok_or_else(|| Error::Backend(format!("PUT(if) {key} returned no ETag"))),
        }
    }

    fn etag(&self, key: &str) -> Result<Option<String>, Error> {
        let url = self.object_url(key);
        // HEAD is body-less: sign without content-length (see `head`).
        let headers = sign_s3_no_body(
            "HEAD",
            &url,
            "",
            R2_REGION,
            &self.access_key,
            &self.secret_key,
        )
        .map_err(|e| Error::Backend(format!("sign HEAD {key}: {e}")))?;

        let resp = self
            .client()
            .head(&url)
            .headers(headers)
            .send()
            .map_err(|e| io_err(&format!("HEAD(etag) {key}"), e))?;

        match resp.status() {
            StatusCode::OK => Ok(resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())),
            StatusCode::NOT_FOUND => Ok(None),
            s => Err(status_err("HEAD(etag)", key, s, None)),
        }
    }
}

/// One `<Contents>` entry from an R2 `ListObjectsV2` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Object key (full path including any prefix).
    pub key: String,
    /// Object size in bytes.
    pub size: u64,
    /// Last-modified timestamp in ISO-8601 / RFC-3339 (R2's `<LastModified>` value).
    pub last_modified: String,
}

impl R2ObjectStore {
    /// List objects under `prefix` returning key + size + last-modified.
    ///
    /// Same paginated request as [`ObjectStore::list_prefix`] but parses the
    /// `<Size>` and `<LastModified>` siblings of each `<Key>` element. Used by
    /// the data-tab bucket viewer to render a directory-style listing.
    pub fn list_prefix_detailed(&self, prefix: &str) -> Result<Vec<ObjectMeta>, Error> {
        let mut entries = Vec::new();
        let mut continuation_token: Option<String> = None;
        let bucket_url = self.bucket_url();
        let encoded_prefix = utf8_percent_encode(prefix, QUERY_VALUE).to_string();

        loop {
            // Canonical query MUST be sorted by parameter name (SigV4).
            // Parameters: continuation-token (optional), list-type, prefix.
            let mut params: Vec<(String, String)> =
                vec![("list-type".to_string(), "2".to_string())];
            if let Some(token) = &continuation_token {
                let encoded = utf8_percent_encode(token, QUERY_VALUE).to_string();
                params.push(("continuation-token".to_string(), encoded));
            }
            params.push(("prefix".to_string(), encoded_prefix.clone()));
            params.sort_by(|a, b| a.0.cmp(&b.0));
            let canonical_query = params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");

            let url_with_query = format!("{bucket_url}?{canonical_query}");

            let headers = sign_s3_get_with_query(
                &bucket_url,
                &canonical_query,
                R2_REGION,
                &self.access_key,
                &self.secret_key,
            )
            .map_err(|e| Error::Backend(format!("sign LIST {prefix}: {e}")))?;

            let resp = self
                .client()
                .get(&url_with_query)
                .headers(headers)
                .send()
                .map_err(|e| io_err(&format!("LIST {prefix}"), e))?;

            if !resp.status().is_success() {
                return Err(status_err("LIST", prefix, resp.status(), resp.text().ok()));
            }
            let body = resp
                .text()
                .map_err(|e| io_err(&format!("LIST {prefix} body"), e))?;
            let (page_entries, next_token) = parse_list_v2_detailed(&body);
            entries.extend(page_entries);
            if let Some(t) = next_token {
                continuation_token = Some(t);
            } else {
                break;
            }
        }
        Ok(entries)
    }
}

fn check_status(resp: reqwest::blocking::Response, verb: &str, key: &str) -> Result<(), Error> {
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().ok();
        Err(status_err(verb, key, status, body))
    }
}

fn status_err(verb: &str, key: &str, status: StatusCode, body: Option<String>) -> Error {
    let snippet = body
        .as_deref()
        .map(|s| s.chars().take(200).collect::<String>())
        .unwrap_or_default();
    let msg = format!("{verb} {key} → {status} {snippet}");
    match status {
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Error::Auth(msg),
        StatusCode::NOT_FOUND => Error::NotFound(msg),
        _ => Error::Backend(msg),
    }
}

/// Parse a `ListObjectsV2` XML response for keys + next continuation token.
///
/// Deliberately tiny — full XML parsing is overkill for the two elements we
/// care about. Looks for `<Key>...</Key>` and `<NextContinuationToken>...`
/// inside the body. If R2 ever changes the element shape (it won't — it's
/// S3-compat), the integration test catches it.
fn parse_list_v2(body: &str) -> (Vec<String>, Option<String>) {
    let keys = extract_all_tags(body, "Key")
        .iter()
        .map(|k| decode_xml_entities(k))
        .collect();
    let next = extract_first_text(body, "NextContinuationToken");
    let truncated = extract_first_tag(body, "IsTruncated")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    (keys, if truncated { next } else { None })
}

/// Parse `<Contents>` blocks for key + size + last-modified.
///
/// R2's `<Contents>` always has `<Key>` followed by `<LastModified>` and
/// `<Size>` siblings. We walk `<Contents>...</Contents>` blocks and pull the
/// three tags from each — order-insensitive within the block. Entries missing
/// any of the three are skipped (defensive — R2 always emits all three).
fn parse_list_v2_detailed(body: &str) -> (Vec<ObjectMeta>, Option<String>) {
    let blocks = extract_all_tags(body, "Contents");
    let entries = blocks
        .into_iter()
        .filter_map(|block| {
            let key = extract_first_text(&block, "Key")?;
            let size = extract_first_tag(&block, "Size")?.trim().parse::<u64>().ok()?;
            let last_modified = extract_first_text(&block, "LastModified")?;
            Some(ObjectMeta { key, size, last_modified })
        })
        .collect();
    let next = extract_first_text(body, "NextContinuationToken");
    let truncated = extract_first_tag(body, "IsTruncated")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    (entries, if truncated { next } else { None })
}

fn extract_all_tags(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut search = body;
    while let Some(start) = search.find(&open) {
        let content_start = start + open.len();
        if let Some(end) = search[content_start..].find(&close) {
            out.push(search[content_start..content_start + end].to_string());
            search = &search[content_start + end + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn extract_first_tag(body: &str, tag: &str) -> Option<String> {
    extract_all_tags(body, tag).into_iter().next()
}

/// Like [`extract_first_tag`] but for a LEAF element, whose text is XML-escaped.
///
/// Never use this on a container like `<Contents>` — decoding a block that
/// still holds child tags would corrupt any `&amp;` that belongs to a nested
/// value before the child tag is even extracted.
fn extract_first_text(body: &str, tag: &str) -> Option<String> {
    extract_first_tag(body, tag).map(|raw| decode_xml_entities(&raw))
}

/// Decode the XML 1.0 predefined entities plus numeric character references.
///
/// R630-B1 fallout: object keys go out on the wire percent-encoded but come
/// back from `ListObjectsV2` as XML *text*, so a key holding `&` arrives as
/// `&amp;` and one holding `<` as `&lt;`. Before the SigV4 fix those keys could
/// not be written at all (they 403'd), so the raw-text read was never wrong in
/// practice; now that they can be written, `list_prefix` would hand back a key
/// that no subsequent `get`/`head`/`delete` can resolve. S3 also emits numeric
/// references (`&#13;`) for control characters, which are legal in a key.
///
/// An unrecognized `&…` sequence is passed through verbatim rather than
/// dropped — a literal `&` in a document that isn't escaping anything is not
/// something to silently eat.
fn decode_xml_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail.find(';').filter(|&i| i <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix('#')
                .and_then(|n| match n.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => n.parse::<u32>().ok(),
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_endpoint_redirects_every_url_and_leaves_r2_alone() {
        let store = R2ObjectStore::new("acct", "yah-dev", "k", "s").unwrap();
        assert_eq!(
            store.object_url("yah/index.json"),
            "https://acct.r2.cloudflarestorage.com/yah-dev/yah/index.json"
        );

        // Pond tier: same store, MinIO endpoint, path-style bucket preserved.
        let pond = R2ObjectStore::new("pond", "yah-dev", "k", "s")
            .unwrap()
            .with_endpoint("http://127.0.0.1:9000");
        assert_eq!(
            pond.object_url("yah/index.json"),
            "http://127.0.0.1:9000/yah-dev/yah/index.json"
        );
        assert_eq!(pond.bucket_url(), "http://127.0.0.1:9000/yah-dev");
    }

    #[test]
    fn with_endpoint_normalizes_trailing_slash_and_ignores_empty() {
        let s = R2ObjectStore::new("acct", "b", "k", "s")
            .unwrap()
            .with_endpoint("http://127.0.0.1:9000/");
        assert_eq!(s.object_url("k1"), "http://127.0.0.1:9000/b/k1");
        // An empty override is a config mistake, not an instruction to sign
        // against the empty host — fall back to the derived R2 endpoint.
        let s = R2ObjectStore::new("acct", "b", "k", "s")
            .unwrap()
            .with_endpoint("");
        assert_eq!(
            s.object_url("k1"),
            "https://acct.r2.cloudflarestorage.com/b/k1"
        );
    }

    /// Accept exactly one HTTP request on an ephemeral loopback port, answer
    /// `200`, and hand the raw request head back. Enough of a server to prove
    /// what went onto the wire, and no more — the point is the headers, and a
    /// mock at the `reqwest` layer would only re-assert what the signer already
    /// returned rather than what the client actually sent.
    fn one_shot_http() -> (String, std::thread::JoinHandle<String>) {
        use std::io::{BufRead, BufReader, Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let done = line == "\r\n";
                head.push_str(&line);
                if done {
                    break;
                }
            }
            // Drain the body, else the client sees the connection close
            // mid-write and reports a broken pipe instead of our 200.
            let len: usize = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length: ")
                        .or_else(|| l.strip_prefix("Content-Length: "))
                })
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            reader
                .into_inner()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            head
        });
        (url, handle)
    }

    /// R703-B8, the end of the chain: the signer builds a `Cache-Control` and
    /// `reqwest` has to actually put it on the socket. Every other test here
    /// stops at the `HeaderMap`, which is one `.headers()` call away from being
    /// a test that passes while R2 stores an object with no directive.
    #[test]
    fn put_cached_sends_the_cache_control_header_on_the_wire() {
        let (endpoint, server) = one_shot_http();
        let store = R2ObjectStore::new("acct", "yah-dev", "AK", "SK")
            .unwrap()
            .with_endpoint(endpoint);

        store
            .put_cached(
                "yah-desktop/latest.json",
                b"{\"version\":\"0.8.22\"}".to_vec(),
                crate::CACHE_CONTROL_NO_CACHE,
            )
            .unwrap();

        let head = server.join().unwrap().to_lowercase();
        assert!(
            head.starts_with("put /yah-dev/yah-desktop/latest.json "),
            "{head}"
        );
        assert!(head.contains("cache-control: no-cache, max-age=0\r\n"), "{head}");
        // Sent AND signed — an unsigned header R2 would reject the request over.
        assert!(
            head.contains("signedheaders=cache-control;content-length;content-type;host;"),
            "{head}"
        );
    }

    /// R630-B1, the property the whole fix rests on: the bytes on the wire and
    /// the bytes in the SigV4 canonical request are the SAME bytes. Every other
    /// test here stops at a `String` or a `HeaderMap`; only this one can catch
    /// reqwest re-encoding (or decoding) the path between `object_url` and the
    /// socket, which would put the signature back out of sync with the request
    /// and give exactly the 403 this ticket is about.
    #[test]
    fn a_colon_key_goes_on_the_wire_percent_encoded() {
        let (endpoint, server) = one_shot_http();
        let store = R2ObjectStore::new("acct", "yah-cr", "AK", "SK")
            .unwrap()
            .with_endpoint(endpoint);

        store
            .put("blobs/sha256:deadbeef", b"layer".to_vec())
            .unwrap();

        let head = server.join().unwrap();
        let request_line = head.lines().next().unwrap();
        assert_eq!(
            request_line, "PUT /yah-cr/blobs/sha256%3Adeadbeef HTTP/1.1",
            "full head: {head}"
        );
        // Uppercase hex specifically — R2 canonicalizes with uppercase, so a
        // lowercase `%3a` on the wire signs differently from what it computes.
        assert!(!request_line.contains("%3a"), "{request_line}");
    }

    /// And the regression half on the wire: an ordinary key must reach the
    /// socket byte-identical to before the encoding was introduced.
    #[test]
    fn an_unreserved_key_reaches_the_wire_unchanged() {
        let (endpoint, server) = one_shot_http();
        let store = R2ObjectStore::new("acct", "yah-dev", "AK", "SK")
            .unwrap()
            .with_endpoint(endpoint);

        store
            .put("yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz", b"x".to_vec())
            .unwrap();

        let head = server.join().unwrap();
        assert_eq!(
            head.lines().next().unwrap(),
            "PUT /yah-dev/yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz HTTP/1.1",
            "full head: {head}"
        );
    }

    /// R630-F2. `delete` signed with `sign_s3_empty_body` from the day it
    /// landed, which puts `content-length: 0` inside the signature — and
    /// reqwest strips that header off a body-less request, so R2 recomputed a
    /// different canonical request and answered 403 for EVERY delete. The
    /// in-memory `delete_is_idempotent` trait test passed throughout, because
    /// it never touches this code. Assert against the socket instead.
    #[test]
    fn delete_signs_without_content_length_and_sends_none() {
        let (endpoint, server) = one_shot_http();
        let store = R2ObjectStore::new("acct", "yah-dev", "AK", "SK")
            .unwrap()
            .with_endpoint(endpoint);

        store.delete("some/blob.bin").unwrap();

        let head = server.join().unwrap().to_lowercase();
        assert!(head.starts_with("delete /yah-dev/some/blob.bin "), "{head}");
        assert!(
            head.contains("signedheaders=host;x-amz-content-sha256;x-amz-date"),
            "content-length must NOT be signed on a body-less DELETE: {head}"
        );
        // And the header genuinely isn't on the wire — which is the whole
        // reason signing it was fatal.
        assert!(!head.contains("content-length"), "{head}");
    }

    /// The other half: a plain `put` must still send no directive at all. If it
    /// quietly gained a default, versioned release bytes would start carrying
    /// whatever that default was.
    #[test]
    fn a_plain_put_sends_no_cache_control_header() {
        let (endpoint, server) = one_shot_http();
        let store = R2ObjectStore::new("acct", "yah-dev", "AK", "SK")
            .unwrap()
            .with_endpoint(endpoint);

        store.put("some/blob.bin", b"bytes".to_vec()).unwrap();

        let head = server.join().unwrap().to_lowercase();
        assert!(!head.contains("cache-control"), "{head}");
    }

    #[test]
    fn parse_list_v2_extracts_keys() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <Contents><Key>yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz</Key></Contents>
                <Contents><Key>yubaba/release-manifest.json</Key></Contents>
            </ListBucketResult>"#;
        let (keys, next) = parse_list_v2(body);
        assert_eq!(
            keys,
            vec![
                "yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz".to_string(),
                "yubaba/release-manifest.json".to_string(),
            ]
        );
        assert!(next.is_none());
    }

    #[test]
    fn parse_list_v2_returns_continuation_when_truncated() {
        let body = r#"<ListBucketResult>
                <IsTruncated>true</IsTruncated>
                <NextContinuationToken>abc123</NextContinuationToken>
                <Contents><Key>a</Key></Contents>
            </ListBucketResult>"#;
        let (keys, next) = parse_list_v2(body);
        assert_eq!(keys, vec!["a".to_string()]);
        assert_eq!(next.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_list_v2_ignores_token_when_not_truncated() {
        // Some S3-compat impls emit NextContinuationToken with IsTruncated=false.
        // We treat IsTruncated as load-bearing.
        let body = r#"<ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <NextContinuationToken>stale</NextContinuationToken>
                <Contents><Key>a</Key></Contents>
            </ListBucketResult>"#;
        let (_, next) = parse_list_v2(body);
        assert!(next.is_none());
    }

    #[test]
    fn parse_list_v2_detailed_extracts_size_and_mtime() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <Contents>
                    <Key>yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz</Key>
                    <LastModified>2026-06-08T20:14:32.000Z</LastModified>
                    <ETag>"abc"</ETag>
                    <Size>4823104</Size>
                    <StorageClass>STANDARD</StorageClass>
                </Contents>
                <Contents>
                    <Key>yubaba/release-manifest.json</Key>
                    <LastModified>2026-06-08T20:14:35.000Z</LastModified>
                    <Size>412</Size>
                </Contents>
            </ListBucketResult>"#;
        let (entries, next) = parse_list_v2_detailed(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz");
        assert_eq!(entries[0].size, 4823104);
        assert_eq!(entries[0].last_modified, "2026-06-08T20:14:32.000Z");
        assert_eq!(entries[1].key, "yubaba/release-manifest.json");
        assert_eq!(entries[1].size, 412);
        assert!(next.is_none());
    }

    #[test]
    fn r2_object_store_constructs_with_explicit_keys() {
        let s = R2ObjectStore::new("acct", "yah-dev", "AK", "SK").unwrap();
        assert_eq!(s.object_url("k"), "https://acct.r2.cloudflarestorage.com/yah-dev/k");
        assert_eq!(s.bucket_url(), "https://acct.r2.cloudflarestorage.com/yah-dev");
    }

    #[test]
    fn object_url_preserves_slashes_in_key() {
        let s = R2ObjectStore::new("acct", "b", "AK", "SK").unwrap();
        assert_eq!(
            s.object_url("yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz"),
            "https://acct.r2.cloudflarestorage.com/b/yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz"
        );
    }

    /// R630-B1 fallout. A key holding `&` could not be written before the SigV4
    /// fix (it 403'd like every other non-unreserved key), so the raw-XML read
    /// was never observably wrong. Now that it CAN be written, a `list_prefix`
    /// that hands back `a&amp;b` names an object no `get`/`head`/`delete` can
    /// resolve — the round-trip would break at the far end instead of the near
    /// one.
    #[test]
    fn list_keys_are_xml_decoded() {
        let body = "<ListBucketResult>\
            <Contents><Key>a&amp;b.json</Key><Size>1</Size><LastModified>t</LastModified></Contents>\
            <Contents><Key>x&lt;y&gt;z</Key><Size>2</Size><LastModified>t</LastModified></Contents>\
            <Contents><Key>q&quot;r&apos;s</Key><Size>3</Size><LastModified>t</LastModified></Contents>\
            <Contents><Key>n&#13;m&#x41;</Key><Size>4</Size><LastModified>t</LastModified></Contents>\
            <IsTruncated>false</IsTruncated></ListBucketResult>";
        let (keys, next) = parse_list_v2(body);
        assert_eq!(keys, vec!["a&b.json", "x<y>z", "q\"r's", "n\rmA"]);
        assert!(next.is_none());
        // The detailed form shares the decode, and its `<Contents>` block walk
        // must still see the child tags — decoding the block first would break it.
        let (entries, _) = parse_list_v2_detailed(body);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].key, "a&b.json");
        assert_eq!(entries[0].size, 1);
    }

    /// A lone `&` that isn't opening an entity is passed through, not eaten.
    #[test]
    fn xml_decode_passes_through_a_non_entity_ampersand() {
        assert_eq!(decode_xml_entities("a & b"), "a & b");
        assert_eq!(decode_xml_entities("&notanentity;"), "&notanentity;");
        assert_eq!(decode_xml_entities("plain/key.json"), "plain/key.json");
        assert_eq!(decode_xml_entities("&amp;&amp;"), "&&");
    }

    /// R630-B1. The key becomes a URL exactly here, so this is the one place
    /// the AWS encoding can be applied such that the wire path and the SigV4
    /// canonical path agree. A `sha256:<hex>` OCI digest is the key shape that
    /// forced the issue — cr.yah.dev writes `sha256/<hex>` today purely to dodge
    /// it (see the R630 relay gotcha).
    #[test]
    fn object_url_encodes_a_colon_in_the_key() {
        let s = R2ObjectStore::new("acct", "yah-cr", "AK", "SK").unwrap();
        assert_eq!(
            s.object_url("blobs/sha256:deadbeef"),
            "https://acct.r2.cloudflarestorage.com/yah-cr/blobs/sha256%3Adeadbeef"
        );
        // `locate` shares the choke point, so a caller handed the URL for a
        // direct fetch gets the encoded form too.
        assert_eq!(s.locate("blobs/sha256:deadbeef"), s.object_url("blobs/sha256:deadbeef"));
    }

    /// Regression guard: today's keys must produce byte-identical URLs, or the
    /// fix for the colon case silently 403s everything that already works.
    #[test]
    fn object_url_leaves_unreserved_keys_untouched() {
        let s = R2ObjectStore::new("acct", "b", "AK", "SK").unwrap();
        for key in [
            "k",
            "yah/index.json",
            "yubaba/0.8.9/x86_64-unknown-linux-musl/yubaba.tar.gz",
            "releases/v1.2.3-rc.1/yah_1.2.3_aarch64.dmg",
        ] {
            assert_eq!(
                s.object_url(key),
                format!("https://acct.r2.cloudflarestorage.com/b/{key}")
            );
        }
    }

    #[test]
    fn content_type_inferred_from_extension() {
        assert_eq!(
            content_type_for_key("yah-marketing/cloud/index.html"),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type_for_key("app.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for_key("bundle.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for_key("illustrations/horse.webp"), "image/webp");
        assert_eq!(content_type_for_key("manifest.json"), "application/json");
        // Extensionless keys (pointers) and dotted directory segments fall back.
        assert_eq!(content_type_for_key("pointers/releases"), DEFAULT_CONTENT_TYPE);
        assert_eq!(content_type_for_key("v1.2/binary"), DEFAULT_CONTENT_TYPE);
    }
}
