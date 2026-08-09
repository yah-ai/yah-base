//! AWS Signature Version 4 helpers for S3-compatible object storage.
//!
//! Shared by `provider::hetzner` (Hetzner Object Storage) and
//! `provider::local_docker` (MinIO). Both speak S3 + AWS SigV4 for bucket
//! create/head/delete; only the endpoint and region differ.
//!
//! @yah:ticket(R630-B1, "SigV4 canonical URI is unencoded — any S3/R2 key containing a colon fails SignatureDoesNotMatch")
//! @yah:at(2026-07-23T03:12:20Z)
//! @yah:status(open)
//! @yah:parent(R630)
//! @yah:severity(high)
//! @yah:next("Repro, no setup: yah cloud bucket put --bucket yah-cr-cache 'test:colon' --file /tmp/any -> 403 SignatureDoesNotMatch. A colon-free key at the same moment succeeds, so it is not a credential problem.")
//! @yah:next("Cause: the sign_s3_* helpers build the SigV4 canonical URI as parsed.path() verbatim (~line 30, 'let uri = parsed.path().to_string()'). SigV4 requires it percent-encoded outside A-Za-z0-9-_.~ and /, so ':' must be '%3A'. R2 canonicalizes per spec, we do not, and the signatures diverge. All four entrypoints are affected: sign_s3_empty_body, sign_s3_no_body, sign_s3_put_object, sign_s3_get_with_query.")
//! @yah:verify("A key containing ':' round-trips through put/get/head/ls, AND existing colon-free keys still round-trip byte-identically (the double-encoding regression guard).")
//! @yah:gotcha("Do NOT fix by re-encoding parsed.path(). Url::parse has already percent-encoded part of it, so re-encoding double-encodes '%' to '%25' and breaks keys that work today. The raw key must be threaded to the signer, or the encoding applied before URL construction. This is exactly why it was left unfixed rather than patched in passing.")
//! @yah:gotcha("Blast radius is silent: the failure looks like bad credentials, not like a key-shape problem. cr.yah.dev stores OCI digests as sha256/<hex> rather than the natural sha256:<hex> purely to route around this — see digest_key in app/yah/cli/src/cr.rs and digestKey in app/yah/workers/yah-cr/src/index.ts, which must stay in lockstep.")

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The `host` value to sign, which must be byte-identical to the `Host` header
/// the HTTP client will actually send — SigV4 hashes it into the canonical
/// request, so any divergence is a 403 `SignatureDoesNotMatch` that reads like
/// a credentials problem.
///
/// `Url::host_str()` alone drops the port, and reqwest includes a NON-DEFAULT
/// port in `Host`. For every https endpoint this crate has signed until now
/// (Hetzner, R2) the port is implicit and the two agree, which is why this went
/// unnoticed. It stops being true the moment anything signs against a local
/// MinIO on `:9000` (R330-T32's pond-tier index writes). `Url::port()` returns
/// `None` for a scheme's default port, so the https path is unchanged.
fn canonical_host(parsed: &reqwest::Url) -> Result<String> {
    let host = parsed.host_str().context("no host in S3 URL")?;
    Ok(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// AWS Sig V4 for any S3 verb that sends no body (PUT CreateBucket, HEAD,
/// DELETE bucket). Callers supply the full `url`, S3 `region` string, and
/// HMAC credentials.
pub fn sign_s3_empty_body(
    method: &str,
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = canonical_host(&parsed)?;
    let uri = parsed.path().to_string();

    let empty_hash = {
        let mut h = Sha256::new();
        h.update(b"");
        hex::encode(h.finalize())
    };

    let canonical_headers = format!(
        "content-length:0\nhost:{host}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("{method}\n{uri}\n\n{canonical_headers}\n{signed_headers}\n{empty_hash}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", empty_hash.parse()?);
    headers.insert("content-length", "0".parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

pub fn sign_s3_put_bucket(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_empty_body("PUT", url, region, access_key, secret_key)
}

pub fn sign_s3_head_bucket(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_empty_body("HEAD", url, region, access_key, secret_key)
}

pub fn sign_s3_delete_bucket(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_empty_body("DELETE", url, region, access_key, secret_key)
}

/// AWS Sig V4 for a `GET` with an empty body and a canonical query string.
///
/// `canonical_query` is the already-formed query (no leading `?`) sorted
/// lexicographically by parameter name with URL-encoded keys + values, e.g.
/// `"list-type=2&prefix=whisper%2F"`. The caller is responsible for ordering
/// and encoding; this helper signs the request as given.
///
/// Used by `ListObjectsV2`. The returned headers are suitable for `reqwest`'s
/// `GET <url>` where `<url>` already includes the `?<canonical_query>` suffix.
pub fn sign_s3_get_with_query(
    url: &str,
    canonical_query: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    sign_s3_no_body("GET", url, canonical_query, region, access_key, secret_key)
}

/// AWS Sig V4 for any body-less verb (`GET`, `HEAD`) **without** signing
/// `content-length`.
///
/// reqwest/hyper strip the `content-length: 0` header off the wire for
/// body-less requests, so signing it — as [`sign_s3_empty_body`] does — leaves
/// the server unable to reproduce the signature, yielding
/// `403 SignatureDoesNotMatch`. Object `GET`/`HEAD` must use this signer; only
/// methods that actually carry a (possibly empty) body and emit
/// `content-length` on the wire may use [`sign_s3_empty_body`].
///
/// `canonical_query` follows the [`sign_s3_get_with_query`] contract (empty
/// string for no query).
pub fn sign_s3_no_body(
    method: &str,
    url: &str,
    canonical_query: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = canonical_host(&parsed)?;
    let uri = parsed.path().to_string();

    let empty_hash = {
        let mut h = Sha256::new();
        h.update(b"");
        hex::encode(h.finalize())
    };

    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "{method}\n{uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{empty_hash}"
    );

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", empty_hash.parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

/// The per-object headers a `PUT` carries beyond the ones SigV4 always needs.
///
/// A struct rather than more positional arguments: [`sign_s3_put_object`] was
/// already at eight, two of them `Option<&str>`, and a third adjacent optional
/// string is the kind of parameter list where a swapped pair compiles and ships
/// the wrong header.
#[derive(Debug, Clone, Default)]
pub struct S3PutOptions<'a> {
    /// `Content-Type`. Empty is not valid S3 — pass the caller's default.
    pub content_type: &'a str,
    /// `x-amz-meta-blake3` (R546-B10) — see [`sign_s3_put_object`].
    pub blake3_meta: Option<&'a str>,
    /// `Cache-Control` (R703-B8). `None` leaves the header off entirely, which
    /// is how every CLI-driven publish behaved before this existed: R2 then
    /// serves the object with no directive at all, so a browser (and any future
    /// edge-cache rule) is free to hold a mutable pointer — `latest.json`, a
    /// release manifest — for as long as it likes. Versioned, content-addressed
    /// keys want [`CACHE_CONTROL_IMMUTABLE`]; fixed-key pointers want
    /// [`CACHE_CONTROL_NO_CACHE`].
    pub cache_control: Option<&'a str>,
}

/// `Cache-Control` for immutable, versioned, content-addressed objects.
/// Matches what `.github/workflows/release.yml` tags them with, so an object
/// published by the CLI is indistinguishable from one published by CI.
pub const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for a mutable pointer at a fixed key — `latest.json`, a
/// release manifest, an index. Also matches `release.yml`.
pub const CACHE_CONTROL_NO_CACHE: &str = "no-cache, max-age=0";

/// AWS Sig V4 for `PUT /<bucket>/<key>` with an object body.
///
/// The caller pre-computes `body_sha256 = hex(sha256(body))` and passes
/// `content_length = body.len()` separately so the headers can be computed
/// without holding the bytes in this function.
///
/// `blake3_meta` attaches `x-amz-meta-blake3` to the object (R546-B10). This is
/// what lets a later run tell "the same bytes are already there" from "different
/// bytes are already there" — an existence probe alone cannot, and ETag is not a
/// usable substitute because it stops being a content MD5 for multipart uploads.
/// Pass `None` for callers that don't track a BLAKE3 for the body.
///
/// Reach for [`sign_s3_put_object_with`] when the object also needs a
/// `Cache-Control`; this signs without one.
pub fn sign_s3_put_object(
    url: &str,
    body_sha256: &str,
    content_type: &str,
    content_length: usize,
    region: &str,
    access_key: &str,
    secret_key: &str,
    blake3_meta: Option<&str>,
) -> Result<HeaderMap> {
    sign_s3_put_object_with(
        url,
        body_sha256,
        content_length,
        region,
        access_key,
        secret_key,
        &S3PutOptions {
            content_type,
            blake3_meta,
            cache_control: None,
        },
    )
}

/// [`sign_s3_put_object`] with the full per-object header set (R703-B8).
pub fn sign_s3_put_object_with(
    url: &str,
    body_sha256: &str,
    content_length: usize,
    region: &str,
    access_key: &str,
    secret_key: &str,
    opts: &S3PutOptions<'_>,
) -> Result<HeaderMap> {
    let S3PutOptions {
        content_type,
        blake3_meta,
        cache_control,
    } = *opts;
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 object URL")?;
    let host = canonical_host(&parsed)?;
    let uri = parsed.path().to_string();

    // SigV4 requires the canonical header block AND the SignedHeaders list to be
    // in lexicographic order, and the two must agree exactly or the server
    // computes a different signature and answers 403 SignatureDoesNotMatch.
    // Build both from one ordered list rather than two hand-maintained string
    // literals — the previous pair of literals was already one optional header
    // away from being wrong, and `cache-control` is the awkward case: it sorts
    // BEFORE `content-length`, so it prepends where `x-amz-meta-blake3` appends.
    let mut signed: Vec<(&str, String)> = Vec::with_capacity(7);
    if let Some(cc) = cache_control {
        signed.push(("cache-control", cc.to_string()));
    }
    signed.push(("content-length", content_length.to_string()));
    signed.push(("content-type", content_type.to_string()));
    signed.push(("host", host.clone()));
    signed.push(("x-amz-content-sha256", body_sha256.to_string()));
    signed.push(("x-amz-date", datetime.clone()));
    if let Some(b3) = blake3_meta {
        signed.push(("x-amz-meta-blake3", b3.to_string()));
    }
    debug_assert!(
        signed.windows(2).all(|w| w[0].0 < w[1].0),
        "canonical headers must be lexicographically ordered: {:?}",
        signed.iter().map(|(n, _)| *n).collect::<Vec<_>>()
    );

    let canonical_headers: String = signed
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed_headers = signed
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let signed_headers = signed_headers.as_str();

    let canonical_request =
        format!("PUT\n{uri}\n\n{canonical_headers}\n{signed_headers}\n{body_sha256}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", body_sha256.parse()?);
    headers.insert("content-length", content_length.to_string().parse()?);
    headers.insert("content-type", content_type.parse()?);
    if let Some(cc) = cache_control {
        headers.insert("cache-control", cc.parse()?);
    }
    if let Some(b3) = blake3_meta {
        headers.insert("x-amz-meta-blake3", b3.parse()?);
    }
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

/// AWS Sig V4 for `PUT /<bucket>?policy` with a JSON body.
///
/// Modern MinIO dropped the `?acl` endpoint; use this to apply an S3 bucket
/// policy document instead. The caller provides the raw JSON bytes; this
/// function hashes them for the signature and returns headers suitable for a
/// `reqwest` PUT with that body.
pub fn sign_s3_put_bucket_policy(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    policy_json: &[u8],
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = canonical_host(&parsed)?;
    let uri = parsed.path().to_string();
    let canonical_query = "policy=";
    let content_length = policy_json.len();

    let body_hash = {
        let mut h = Sha256::new();
        h.update(policy_json);
        hex::encode(h.finalize())
    };

    let canonical_headers = format!(
        "content-length:{content_length}\ncontent-type:application/json\nhost:{host}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;content-type;host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("PUT\n{uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{body_hash}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", body_hash.parse()?);
    headers.insert("content-length", content_length.to_string().parse()?);
    headers.insert("content-type", "application/json".parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

/// AWS Sig V4 for `PUT /<bucket>?acl` with a canned-ACL header.
///
/// **Deprecated for MinIO**: modern MinIO does not implement the ACL endpoint.
/// Use [`sign_s3_put_bucket_policy`] for pond/local-docker targets and
/// keep this only for S3-compatible providers that still honour canned ACLs
/// (e.g. Hetzner Object Storage).
pub fn sign_s3_put_bucket_acl(
    url: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    acl: &str,
) -> Result<HeaderMap> {
    let now = chrono::Utc::now();
    let date = now.format("%Y%m%d").to_string();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed = reqwest::Url::parse(url).context("parsing S3 URL")?;
    let host = canonical_host(&parsed)?;
    let uri = parsed.path().to_string();
    let canonical_query = "acl=";

    let empty_hash = {
        let mut h = Sha256::new();
        h.update(b"");
        hex::encode(h.finalize())
    };

    // Headers listed in lexicographic order (required by SigV4).
    let canonical_headers = format!(
        "content-length:0\nhost:{host}\nx-amz-acl:{acl}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{datetime}\n"
    );
    let signed_headers = "content-length;host;x-amz-acl;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("PUT\n{uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{empty_hash}");

    let cr_hash = {
        let mut h = Sha256::new();
        h.update(canonical_request.as_bytes());
        hex::encode(h.finalize())
    };

    let credential_scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    let hmac_sign = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };

    let date_key = hmac_sign(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let date_region_key = hmac_sign(&date_key, region.as_bytes());
    let date_region_service_key = hmac_sign(&date_region_key, b"s3");
    let signing_key = hmac_sign(&date_region_service_key, b"aws4_request");
    let signature = hex::encode(hmac_sign(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = HeaderMap::new();
    headers.insert("host", host.parse()?);
    headers.insert("x-amz-date", datetime.parse()?);
    headers.insert("x-amz-content-sha256", empty_hash.parse()?);
    headers.insert("content-length", "0".parse()?);
    headers.insert("x-amz-acl", acl.parse()?);
    headers.insert("authorization", authorization.parse()?);
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signed `host` must equal the `Host` header reqwest sends, or the
    /// server recomputes a different canonical request and answers 403
    /// `SignatureDoesNotMatch` — which reads like bad credentials. reqwest
    /// includes a non-default port in `Host`; `Url::host_str()` drops it.
    #[test]
    fn canonical_host_carries_a_nondefault_port() {
        let u = reqwest::Url::parse("http://127.0.0.1:9000/yah-dev/yah/index.json").unwrap();
        assert_eq!(canonical_host(&u).unwrap(), "127.0.0.1:9000");
        // Default ports stay implicit, so every https endpoint signed before
        // this existed (Hetzner, R2) signs byte-identically.
        let u = reqwest::Url::parse("https://acct.r2.cloudflarestorage.com/yah-dev/k").unwrap();
        assert_eq!(canonical_host(&u).unwrap(), "acct.r2.cloudflarestorage.com");
        let u = reqwest::Url::parse("https://acct.r2.cloudflarestorage.com:443/yah-dev/k").unwrap();
        assert_eq!(canonical_host(&u).unwrap(), "acct.r2.cloudflarestorage.com");
    }

    #[test]
    fn signed_headers_include_the_port_for_a_local_endpoint() {
        let headers = sign_s3_put_object(
            "http://127.0.0.1:9000/yah-dev/yah/index.json",
            &"0".repeat(64),
            "application/json",
            10,
            "auto",
            "AK",
            "SK",
            None,
        )
        .unwrap();
        assert_eq!(
            headers.get("host").unwrap().to_str().unwrap(),
            "127.0.0.1:9000"
        );
    }

    #[test]
    fn sign_produces_required_headers() {
        let headers = sign_s3_put_bucket(
            "https://fsn1.your-objectstorage.com/test-bucket",
            "fsn1",
            "AK",
            "SK",
        )
        .unwrap();
        assert!(headers.contains_key("authorization"));
        assert!(headers.contains_key("x-amz-date"));
        assert!(headers.contains_key("x-amz-content-sha256"));
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AK/"));
        assert!(
            auth.contains("SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date")
        );
    }

    /// R546-B10. The metadata header must be BOTH sent and covered by the
    /// signature. Sending it unsigned, or listing it in SignedHeaders without
    /// including it in the canonical headers, produces a SignatureDoesNotMatch
    /// 403 at runtime — which no local test would otherwise catch.
    #[test]
    fn put_object_signs_the_blake3_metadata_header() {
        let b3 = "d".repeat(64);
        let headers = sign_s3_put_object(
            "https://acct.r2.cloudflarestorage.com/yah-dev/some/key.tar.gz",
            &"0".repeat(64),
            "application/octet-stream",
            123,
            "auto",
            "AK",
            "SK",
            Some(&b3),
        )
        .unwrap();

        assert_eq!(headers.get("x-amz-meta-blake3").unwrap().to_str().unwrap(), b3);
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.contains(
                "SignedHeaders=content-length;content-type;host;x-amz-content-sha256;\
                 x-amz-date;x-amz-meta-blake3"
            ),
            "metadata header must be inside SignedHeaders, got: {auth}"
        );
    }

    /// Omitting the metadata must leave the previous signed-header set exactly
    /// as it was — otherwise every existing caller starts 403ing.
    #[test]
    fn put_object_without_metadata_keeps_the_original_signed_header_set() {
        let headers = sign_s3_put_object(
            "https://acct.r2.cloudflarestorage.com/yah-dev/some/key.bin",
            &"0".repeat(64),
            "application/octet-stream",
            7,
            "auto",
            "AK",
            "SK",
            None,
        )
        .unwrap();

        assert!(!headers.contains_key("x-amz-meta-blake3"));
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.contains(
                "SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date,"
            ),
            "unstamped PUT must keep the original signed-header set, got: {auth}"
        );
    }

    /// R703-B8. `cache-control` sorts BEFORE `content-length`, so unlike
    /// `x-amz-meta-blake3` it must PREPEND to the canonical header block. Get
    /// that backwards and SigV4 answers 403 SignatureDoesNotMatch — the same
    /// failure mode as bad credentials, and only ever visible against live R2.
    #[test]
    fn put_object_signs_cache_control_ahead_of_content_length() {
        let headers = sign_s3_put_object_with(
            "https://acct.r2.cloudflarestorage.com/yah-dev/yah-desktop/latest.json",
            &"0".repeat(64),
            42,
            "auto",
            "AK",
            "SK",
            &S3PutOptions {
                content_type: "application/json",
                blake3_meta: None,
                cache_control: Some(CACHE_CONTROL_NO_CACHE),
            },
        )
        .unwrap();

        assert_eq!(
            headers.get("cache-control").unwrap().to_str().unwrap(),
            "no-cache, max-age=0"
        );
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.contains(
                "SignedHeaders=cache-control;content-length;content-type;host;\
                 x-amz-content-sha256;x-amz-date,"
            ),
            "cache-control must be signed, and first, got: {auth}"
        );
    }

    /// Both optional headers at once — the ordering has to hold when one
    /// prepends and the other appends.
    #[test]
    fn put_object_signs_cache_control_and_blake3_together_in_order() {
        let b3 = "e".repeat(64);
        let headers = sign_s3_put_object_with(
            "https://acct.r2.cloudflarestorage.com/yah-dev/a/v1.2.3/yah.tar.gz",
            &"0".repeat(64),
            9,
            "auto",
            "AK",
            "SK",
            &S3PutOptions {
                content_type: "application/octet-stream",
                blake3_meta: Some(&b3),
                cache_control: Some(CACHE_CONTROL_IMMUTABLE),
            },
        )
        .unwrap();

        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.contains(
                "SignedHeaders=cache-control;content-length;content-type;host;\
                 x-amz-content-sha256;x-amz-date;x-amz-meta-blake3,"
            ),
            "got: {auth}"
        );
        assert_eq!(
            headers.get("cache-control").unwrap().to_str().unwrap(),
            "public, max-age=31536000, immutable"
        );
    }

    /// The wrapper must be byte-for-byte the old behaviour: same signature for
    /// the same inputs, so no existing caller starts 403ing. Signing twice
    /// within the same second is what makes this comparable at all — the date
    /// stamp is the only other input that moves.
    #[test]
    fn the_options_form_and_the_legacy_form_sign_identically() {
        let url = "https://acct.r2.cloudflarestorage.com/yah-dev/k.bin";
        let legacy =
            sign_s3_put_object(url, &"0".repeat(64), "text/plain", 3, "auto", "AK", "SK", None)
                .unwrap();
        let with_opts = sign_s3_put_object_with(
            url,
            &"0".repeat(64),
            3,
            "auto",
            "AK",
            "SK",
            &S3PutOptions {
                content_type: "text/plain",
                blake3_meta: None,
                cache_control: None,
            },
        )
        .unwrap();

        assert!(!with_opts.contains_key("cache-control"));
        // `x-amz-date` has second resolution; if the two calls straddled a
        // second boundary the signatures legitimately differ, so compare the
        // header SET, which is what a caller can actually break.
        let names = |h: &HeaderMap| {
            let mut v: Vec<String> = h.keys().map(|k| k.as_str().to_string()).collect();
            v.sort();
            v
        };
        assert_eq!(names(&legacy), names(&with_opts));
    }

    #[test]
    fn sign_get_with_query_signed_headers_omit_content_length() {
        let headers = sign_s3_get_with_query(
            "https://acct.r2.cloudflarestorage.com/yah-dev",
            "list-type=2&prefix=whisper%2F",
            "auto",
            "AK",
            "SK",
        )
        .unwrap();
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AK/"));
        assert!(
            auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
            "GET with query must NOT include content-length in SignedHeaders: {auth}"
        );
        assert!(!headers.contains_key("content-length"));
    }

    #[test]
    fn sign_no_body_get_object_omits_content_length() {
        // Plain object GET: empty query, no content-length signed (reqwest
        // strips content-length: 0 on the wire → would 403 otherwise).
        let headers = sign_s3_no_body(
            "GET",
            "https://acct.r2.cloudflarestorage.com/yah-dev/_yah-manifest.json",
            "",
            "auto",
            "AK",
            "SK",
        )
        .unwrap();
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
            "object GET must NOT sign content-length: {auth}"
        );
        assert!(!headers.contains_key("content-length"));
    }

    #[test]
    fn sign_no_body_head_uses_head_method() {
        // HEAD shares the body-less signing path; the canonical request must
        // use the HEAD verb, not GET, but still omit content-length.
        let head = sign_s3_no_body(
            "HEAD",
            "https://acct.r2.cloudflarestorage.com/yah-dev/k",
            "",
            "auto",
            "AK",
            "SK",
        )
        .unwrap();
        let get = sign_s3_no_body(
            "GET",
            "https://acct.r2.cloudflarestorage.com/yah-dev/k",
            "",
            "auto",
            "AK",
            "SK",
        )
        .unwrap();
        assert!(!head.contains_key("content-length"));
        // Different verb → different signature for the same URL/time-window.
        assert_ne!(
            head.get("authorization").unwrap().to_str().unwrap(),
            get.get("authorization").unwrap().to_str().unwrap(),
        );
    }

    #[test]
    fn sign_put_bucket_acl_includes_acl_header_and_query() {
        let headers = sign_s3_put_bucket_acl(
            "https://fsn1.your-objectstorage.com/test-bucket?acl",
            "fsn1",
            "AK",
            "SK",
            "public-read",
        )
        .unwrap();
        assert!(headers.contains_key("authorization"));
        assert!(headers.contains_key("x-amz-acl"));
        assert_eq!(headers.get("x-amz-acl").unwrap().to_str().unwrap(), "public-read");
        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AK/"));
        assert!(auth.contains("x-amz-acl"));
        assert!(auth.contains("SignedHeaders=content-length;host;x-amz-acl;x-amz-content-sha256;x-amz-date"));
    }
}
