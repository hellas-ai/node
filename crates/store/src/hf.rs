//! Fetching content from HuggingFace's Xet CAS.
//!
//! Three requests, in order:
//!
//! 1. `GET huggingface.co/api/{type}s/{repo}/xet-read-token/{rev}` for a
//!    short-lived CAS token and the CAS URL. **No `Authorization`
//!    header for public repositories** — anonymous read works, and the
//!    token that comes back says `userId: "public"`.
//! 2. `GET {cas}/v2/reconstructions/{file_id}` for the file's terms.
//! 3. `GET` each signed CDN URL for the xorb bytes those terms name.
//!
//! # Two conventions that differ inside one JSON object
//!
//! A term's `range` is over **chunk indices, half-open** `[start, end)`.
//! A fetch entry's `bytes` is a **byte range, inclusive** `[start, end]`.
//! Getting these the same way round produces off-by-one downloads that
//! decode as truncated xorbs rather than as anything obviously wrong.
//!
//! # The URL is signed, so ask for exactly what you were offered
//!
//! Fetch URLs are CloudFront-signed (`Expires`, `Policy`, `Signature`,
//! `Key-Pair-Id`). The protocol docs describe an `X-Xet-Signed-Range`
//! parameter pinning the URL to specific byte ranges; the
//! single-range responses observed here do not carry one, so that has
//! NOT been confirmed against production and multi-range behaviour is
//! untested. Either way the rule is the same: request the ranges the
//! response listed, unmodified. Widening a request to save a round trip
//! is how you get an authorisation failure instead of a 416.
//!
//! # Verification
//!
//! Whole-file: the reassembled bytes are re-chunked and their file hash
//! compared with the id that was asked for, so a wrong or tampered
//! response cannot be written into the store under a name it does not
//! own. Per-chunk: [`crate::xorb::decode_range`] additionally checks
//! every chunk against our own chunk list when we have one, which is
//! what makes a *partial* fetch verifiable at all — HuggingFace returns
//! no chunk hashes.

use std::io::Read as _;
use std::path::Path;

use hellas_xet::{Chunk, XetFileHasher, XetHash};

/// Which kind of repository a model lives in. The API path pluralises
/// it, which is why this is not just a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepoKind {
    Model,
    Dataset,
}

impl RepoKind {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::Model => "models",
            Self::Dataset => "datasets",
        }
    }
}

/// The repository a token is minted for.
///
/// HuggingFace's CAS is content-addressed for *reads* but not for
/// *authorisation*: a token is scoped to one repository and one
/// revision, so fetching by content id alone is not possible against
/// this source. A peer source would not need this.
#[derive(Clone, Debug)]
pub struct Repo {
    pub kind: RepoKind,
    /// `org/name`.
    pub id: String,
    /// Branch, tag or commit sha.
    pub revision: String,
}

/// Why a fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("{context}: {source}")]
    Http {
        context: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed reconstruction response: {0}")]
    Malformed(String),
    #[error("decoding a xorb: {0}")]
    Xorb(#[from] crate::xorb::XorbError),
    #[error("reconstructed content hashed to {actual}, asked for {expected}")]
    WrongContent { expected: XetHash, actual: XetHash },
}

type Result<T> = std::result::Result<T, FetchError>;

/// A CAS read token and where to spend it.
#[derive(Clone, Debug)]
pub struct XetToken {
    pub access_token: String,
    /// Where the CAS lives. Dynamic — do not hardcode it.
    pub cas_url: String,
}

/// One contiguous run of chunks inside one xorb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Term {
    pub xorb: XetHash,
    /// Chunk indices, half-open.
    pub chunks: core::ops::Range<u64>,
    pub unpacked_length: u64,
}

/// Where to get some of a xorb's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchRange {
    pub url: String,
    /// Chunk indices, half-open.
    pub chunks: core::ops::Range<u64>,
    /// Byte range, INCLUSIVE — unlike `chunks`.
    pub bytes: core::ops::RangeInclusive<u64>,
}

/// A file's layout across xorbs.
#[derive(Clone, Debug)]
pub struct Reconstruction {
    /// Bytes to drop from the front of the first term's output.
    pub offset_into_first_range: u64,
    pub terms: Vec<Term>,
    /// Fetch entries per xorb hash.
    pub fetches: Vec<(XetHash, Vec<FetchRange>)>,
}

impl Reconstruction {
    /// Parses a `/v2/reconstructions` response.
    pub fn parse(json: &str) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|err| FetchError::Malformed(err.to_string()))?;
        let bad = |what: &str| FetchError::Malformed(what.to_string());

        let terms = value
            .get("terms")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| bad("terms missing"))?
            .iter()
            .map(|term| {
                let range = term.get("range").ok_or_else(|| bad("term range missing"))?;
                Ok(Term {
                    xorb: hash_field(term, "hash")?,
                    chunks: u64_field(range, "start")?..u64_field(range, "end")?,
                    unpacked_length: u64_field(term, "unpacked_length")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let fetches = value
            .get("xorbs")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| bad("xorbs missing"))?
            .iter()
            .map(|(hash, entries)| {
                let hash = hash
                    .parse::<XetHash>()
                    .map_err(|_| bad("xorb key is not a hash"))?;
                let entries = entries
                    .as_array()
                    .ok_or_else(|| bad("xorb entries are not an array"))?
                    .iter()
                    .map(|entry| {
                        let url = entry
                            .get("url")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| bad("fetch url missing"))?
                            .to_string();
                        entry
                            .get("ranges")
                            .and_then(serde_json::Value::as_array)
                            .ok_or_else(|| bad("fetch ranges missing"))?
                            .iter()
                            .map(|range| {
                                let chunks =
                                    range.get("chunks").ok_or_else(|| bad("chunks missing"))?;
                                let bytes =
                                    range.get("bytes").ok_or_else(|| bad("bytes missing"))?;
                                Ok(FetchRange {
                                    url: url.clone(),
                                    // Half-open.
                                    chunks: u64_field(chunks, "start")?..u64_field(chunks, "end")?,
                                    // Inclusive. Deliberately not the same shape.
                                    bytes: u64_field(bytes, "start")?..=u64_field(bytes, "end")?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .collect::<Result<Vec<_>>>()?
                    .concat();
                Ok((hash, entries))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            offset_into_first_range: value
                .get("offset_into_first_range")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            terms,
            fetches,
        })
    }

    /// Fetch entries covering `term`, in chunk order.
    #[must_use]
    pub fn ranges_for(&self, term: &Term) -> Vec<&FetchRange> {
        let mut ranges: Vec<&FetchRange> = self
            .fetches
            .iter()
            .filter(|(hash, _)| *hash == term.xorb)
            .flat_map(|(_, entries)| entries)
            .filter(|range| {
                range.chunks.start < term.chunks.end && term.chunks.start < range.chunks.end
            })
            .collect();
        ranges.sort_by_key(|range| range.chunks.start);
        ranges
    }
}

fn u64_field(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| FetchError::Malformed(format!("{field} missing or not a number")))
}

fn hash_field(value: &serde_json::Value, field: &str) -> Result<XetHash> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|hash| hash.parse::<XetHash>().ok())
        .ok_or_else(|| FetchError::Malformed(format!("{field} missing or not a hash")))
}

/// A HuggingFace-backed source for one repository.
#[derive(Clone, Debug)]
pub struct HfCas {
    repo: Repo,
    /// Hub base, overridable for testing against another endpoint.
    hub: String,
}

impl HfCas {
    /// A source reading `repo` from huggingface.co.
    #[must_use]
    pub fn new(repo: Repo) -> Self {
        Self {
            repo,
            hub: "https://huggingface.co".to_string(),
        }
    }

    /// Obtains a CAS read token.
    ///
    /// Deliberately sends no `Authorization` header: public repositories
    /// need none, and this crate holds no credentials. Private
    /// repositories will fail here, loudly, which is the honest
    /// behaviour for a component that was not given a secret.
    pub fn token(&self) -> Result<XetToken> {
        let url = format!(
            "{}/api/{}/{}/xet-read-token/{}",
            self.hub,
            self.repo.kind.path_segment(),
            self.repo.id,
            self.repo.revision,
        );
        let body = get(&url, None)?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|err| FetchError::Malformed(format!("token response: {err}")))?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| FetchError::Malformed(format!("token response has no {name}")))
        };
        Ok(XetToken {
            access_token: field("accessToken")?,
            cas_url: field("casUrl")?,
        })
    }

    /// Reads the file's layout across xorbs.
    pub fn reconstruction(&self, token: &XetToken, id: XetHash) -> Result<Reconstruction> {
        let url = format!("{}/v2/reconstructions/{id}", token.cas_url);
        let body = get(&url, Some(&token.access_token))?;
        let json = String::from_utf8(body)
            .map_err(|_| FetchError::Malformed("reconstruction is not UTF-8".to_string()))?;
        Reconstruction::parse(&json)
    }

    /// Materialises content `id` at `dest`, refusing to write anything
    /// that does not hash to `id`.
    ///
    /// The file is assembled in memory before being written, so the
    /// store never contains a partially-fetched file under a real name.
    /// That costs one file's worth of memory and buys the guarantee that
    /// a path in the store always holds the content its id claims.
    pub fn fetch(&self, id: XetHash, dest: &Path, expected: Option<&[Chunk]>) -> Result<u64> {
        let token = self.token()?;
        let plan = self.reconstruction(&token, id)?;

        let mut assembled: Vec<u8> = Vec::new();
        let mut chunk_index = 0_usize;
        for term in &plan.terms {
            for range in plan.ranges_for(term) {
                let bytes = get_range(&range.url, *range.bytes.start(), *range.bytes.end())?;
                let count = usize::try_from(range.chunks.end - range.chunks.start)
                    .map_err(|_| FetchError::Malformed("absurd chunk count".to_string()))?;
                // Verify per-chunk when we already know what to expect.
                // Without a chunk list this is impossible: the response
                // carries no chunk hashes.
                let slice = expected
                    .map(|chunks| {
                        chunks
                            .get(chunk_index..chunk_index + count)
                            .ok_or_else(|| FetchError::Malformed("chunk list too short".into()))
                    })
                    .transpose()?;
                let decoded = crate::xorb::decode_chunks(&bytes, count, slice)?;
                for data in decoded {
                    assembled.extend_from_slice(&data);
                }
                chunk_index += count;
            }
        }

        let content = verified(id, &assembled, plan.offset_into_first_range)?;

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|source| FetchError::Io {
                context: format!("creating {}", parent.display()),
                source,
            })?;
        }
        std::fs::write(dest, content).map_err(|source| FetchError::Io {
            context: format!("writing {}", dest.display()),
            source,
        })?;
        Ok(content.len() as u64)
    }
}

/// Trims the leading offset and checks the result is the content that
/// was asked for.
///
/// Separated from [`HfCas::fetch`] so it is reachable without a network:
/// this is the check that stops a wrong or tampered response being
/// written into the store under a name it does not own, and a check
/// that only runs against production is a check nobody can regression-
/// test.
pub fn verified(id: XetHash, assembled: &[u8], offset: u64) -> Result<&[u8]> {
    let start =
        usize::try_from(offset).map_err(|_| FetchError::Malformed("absurd offset".into()))?;
    let content = assembled
        .get(start..)
        .ok_or_else(|| FetchError::Malformed("offset past the assembled content".into()))?;

    let mut hasher = XetFileHasher::new();
    hasher.update(content);
    let actual = hasher.finalize();
    if actual != id {
        return Err(FetchError::WrongContent {
            expected: id,
            actual,
        });
    }
    Ok(content)
}

fn get(url: &str, bearer: Option<&str>) -> Result<Vec<u8>> {
    let mut request = ureq::get(url);
    if let Some(token) = bearer {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    read_body(request, url)
}

fn get_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>> {
    // Inclusive, matching the reconstruction response's own convention
    // and the signed range on the URL.
    let request = ureq::get(url).header("Range", &format!("bytes={start}-{end}"));
    read_body(request, url)
}

fn read_body(
    request: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    url: &str,
) -> Result<Vec<u8>> {
    let context = || format!("GET {url}");
    let mut response = request.call().map_err(|source| FetchError::Http {
        context: context(),
        source: Box::new(source),
    })?;
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|source| FetchError::Io {
            context: context(),
            source,
        })?;
    Ok(body)
}

impl crate::Fetcher for HfCas {
    fn name(&self) -> &str {
        "huggingface"
    }

    fn fetch(&self, id: XetHash, dest: &Path, expected: Option<&[Chunk]>) -> Result<u64> {
        Self::fetch(self, id, dest, expected)
    }
}
