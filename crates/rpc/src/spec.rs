//! What a caller is allowed to name.
//!
//! A [`ModelSpec`] is parsed from a string that arrived over the wire on
//! an unauthenticated quote, and both of its halves become paths: the id
//! is encoded into a cache directory name, and the revision is either a
//! snapshot directory or a `refs/<revision>` file the HuggingFace client
//! reads to find one. So this type is a filesystem boundary, and it is
//! the only one — everything downstream joins these strings onto a cache
//! root.
//!
//! That is why the grammar is owned here rather than left to `hf-hub`.
//! The dependency's `folder_name()` happens to replace `/` with `--`,
//! which neutralises `../../etc` as an id today; it is a private
//! transform, it is not injective (`a/b` and `a--b` collide), and it
//! does nothing at all for the revision, which `hf-hub` pushes onto
//! `refs/` unchanged. An absolute revision replaces the base path and a
//! `..` walks out of it, so `org/model@/var/log/big` was an arbitrary
//! local read, a memory amplifier and an error oracle, reachable by
//! anyone who could dial the node.
//!
//! The grammar permitted is HuggingFace's own for ids and git's
//! `check-ref-format` for revisions, minus what cannot be a path
//! component. Nothing that resolves on the hub is refused here; nothing
//! refused here could have resolved.

use thiserror::Error;

pub const DEFAULT_MODEL_REVISION: &str = "main";

/// The longest one segment of a repository id may be — HuggingFace's own
/// limit, so a longer name names nothing there.
const MAX_ID_SEGMENT: usize = 96;

/// The longest a revision may be. Not a rule of git's; a bound, because
/// this string is joined onto a path and an unauthenticated caller
/// chooses its length.
const MAX_REVISION: usize = 256;

/// Characters git refuses in a ref name. Space and the ASCII control
/// range are refused separately, as is everything non-ASCII.
const REVISION_FORBIDDEN: &[u8] = b"~^:?*[\\";

/// Parse errors for [`ModelSpec`]. Carries no external dependencies so it stays
/// WASM-safe for consumers that only need identifier parsing.
///
/// The offending string is echoed with `{:?}`, not `{}`: what is being
/// reported is by definition a name we refused, so it may hold anything
/// a caller could put on the wire, and an error message is something an
/// operator reads in a terminal.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ModelSpecError {
    #[error("model id is empty")]
    EmptyId,
    #[error("model revision is empty")]
    EmptyRevision,
    #[error("model id {id:?} is not a HuggingFace repository name: {reason}")]
    InvalidId { id: String, reason: &'static str },
    #[error("model revision {revision:?} is not a git ref: {reason}")]
    InvalidRevision {
        revision: String,
        reason: &'static str,
    },
}

/// A HuggingFace-style model identifier with an optional revision.
///
/// Parsed from strings of the form `org/model` (revision defaults to
/// [`DEFAULT_MODEL_REVISION`]) or `org/model@revision`.
///
/// The fields are private because the validation is the point: a value
/// of this type exists only if [`ModelSpec::parse`] accepted both halves,
/// so a caller downstream cannot assemble one out of a wire string and
/// hand it to a path join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelSpec {
    id: String,
    revision: String,
}

impl ModelSpec {
    pub fn parse(raw: &str) -> Result<Self, ModelSpecError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ModelSpecError::EmptyId);
        }

        let (id, revision) = match raw.rsplit_once('@') {
            Some((id, revision)) => {
                let id = id.trim();
                let revision = revision.trim();
                if id.is_empty() {
                    return Err(ModelSpecError::EmptyId);
                }
                if revision.is_empty() {
                    return Err(ModelSpecError::EmptyRevision);
                }
                (id.to_string(), revision.to_string())
            }
            None => (raw.to_string(), DEFAULT_MODEL_REVISION.to_string()),
        };

        validate_id(&id)?;
        validate_revision(&revision)?;

        Ok(Self { id, revision })
    }

    /// The repository, `name` or `namespace/name`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The revision: a branch, a tag, or a commit sha.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// HuggingFace's repository grammar, as the hub itself enforces it.
///
/// `--` and `..` are forbidden by the hub, and that is load-bearing here
/// rather than merely inherited: `--` is what the cache encoding uses to
/// join `namespace` to `name`, so banning it in a segment is what makes
/// `models--org--name` mean one repository instead of several.
fn validate_id(id: &str) -> Result<(), ModelSpecError> {
    let bad = |reason| {
        Err(ModelSpecError::InvalidId {
            id: id.to_string(),
            reason,
        })
    };

    if id.split('/').count() > 2 {
        return bad("a repository is `name` or `namespace/name`");
    }
    if id.contains("--") {
        return bad("`--` is how the cache layout joins a namespace to a name");
    }
    if id.contains("..") {
        return bad("`..` is not a repository name");
    }
    if id.ends_with(".git") {
        return bad("a repository name does not carry `.git`");
    }
    for segment in id.split('/') {
        if segment.is_empty() {
            return bad("a `/` with nothing on one side of it");
        }
        if segment.len() > MAX_ID_SEGMENT {
            return bad("longer than the 96 characters a repository name may have");
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return bad("only ASCII letters, digits, `-`, `_` and `.` are allowed");
        }
        let ends = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        if !segment.bytes().next().is_some_and(ends)
            || !segment.bytes().next_back().is_some_and(ends)
        {
            return bad("must begin and end with a letter, a digit or `_`");
        }
    }
    Ok(())
}

/// Git's `check-ref-format`, restricted to what can be a path component.
///
/// A revision is resolved through `refs/<revision>` when it is not a
/// commit sha, so every rule here is about the same thing: the result of
/// that join must stay inside the repository's own cache directory, and
/// must name one file rather than a directory walk.
fn validate_revision(revision: &str) -> Result<(), ModelSpecError> {
    let bad = |reason| {
        Err(ModelSpecError::InvalidRevision {
            revision: revision.to_string(),
            reason,
        })
    };

    if revision.len() > MAX_REVISION {
        return bad("longer than any branch, tag or commit sha");
    }
    if revision.contains("..") {
        return bad("`..` walks out of the repository's cache directory");
    }
    if revision.contains("@{") {
        return bad("`@{` is git's reflog syntax, not a ref");
    }
    for byte in revision.bytes() {
        if !byte.is_ascii_graphic() {
            return bad("only printable ASCII, with no spaces");
        }
        if REVISION_FORBIDDEN.contains(&byte) {
            return bad("git forbids ~ ^ : ? * [ and \\ in a ref name");
        }
    }
    for segment in revision.split('/') {
        if segment.is_empty() {
            return bad("an empty path segment: a revision is a ref, never an absolute path");
        }
        if segment.starts_with('.') || segment.ends_with('.') {
            return bad("a ref component may not begin or end with `.`");
        }
        if segment.ends_with(".lock") {
            return bad("`.lock` names git's lock file, not a ref");
        }
    }
    Ok(())
}

impl std::fmt::Display for ModelSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.revision.is_empty() || self.revision == DEFAULT_MODEL_REVISION {
            write!(f, "{}", self.id)
        } else {
            write!(f, "{}@{}", self.id, self.revision)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MODEL_REVISION, ModelSpec, ModelSpecError};

    #[test]
    fn parses_default_revision_when_not_specified() {
        let spec = ModelSpec::parse("HuggingFaceTB/SmolLM2-135M-Instruct").unwrap();
        assert_eq!(spec.id(), "HuggingFaceTB/SmolLM2-135M-Instruct");
        assert_eq!(spec.revision(), DEFAULT_MODEL_REVISION);
    }

    #[test]
    fn parses_explicit_revision_suffix() {
        let spec = ModelSpec::parse("foo/bar@refs/pr/7").unwrap();
        assert_eq!(spec.id(), "foo/bar");
        assert_eq!(spec.revision(), "refs/pr/7");
    }

    #[test]
    fn rejects_empty_revision_suffix() {
        assert_eq!(
            ModelSpec::parse("foo/bar@").unwrap_err(),
            ModelSpecError::EmptyRevision,
        );
    }

    #[test]
    fn rejects_empty_id() {
        assert_eq!(ModelSpec::parse("").unwrap_err(), ModelSpecError::EmptyId,);
        assert_eq!(
            ModelSpec::parse("@main").unwrap_err(),
            ModelSpecError::EmptyId,
        );
    }

    #[test]
    fn display_elides_default_revision() {
        let spec = ModelSpec::parse("org/model").unwrap();
        assert_eq!(spec.to_string(), "org/model");
    }

    #[test]
    fn display_renders_explicit_revision() {
        let spec = ModelSpec::parse("org/model@v2").unwrap();
        assert_eq!(spec.to_string(), "org/model@v2");
    }

    /// The half that matters: a revision becomes `refs/<revision>` under
    /// the cache root, so anything that could leave that directory — or
    /// name something other than one file in it — is refused here or not
    /// at all.
    #[test]
    fn a_revision_that_could_leave_the_cache_is_refused() {
        // Through the whole parse, which is how one arrives: these are
        // the shapes that made an unauthenticated quote a local read.
        for spec in [
            "org/model@/etc/passwd",
            "org/model@../../..",
            "org/model@refs/heads/../../../etc",
        ] {
            assert!(
                matches!(
                    ModelSpec::parse(spec),
                    Err(ModelSpecError::InvalidRevision { .. }),
                ),
                "{spec:?} must be refused",
            );
        }

        // And the grammar itself. Some of these cannot be reached
        // through `parse` — `head@{1}` splits at its own `@` and fails as
        // an id — but the rule is the ref grammar, so it is asserted
        // against the ref grammar.
        for revision in [
            "/etc/passwd",
            "/var/log/large-text-file",
            "../../..",
            "../snapshots/escape",
            "a/../../b",
            ".",
            "..",
            "main/",
            "//main",
            "a//b",
            ".hidden",
            "main.lock",
            "refs/heads/main.lock",
            "main\nrefs/heads/x",
            "main with space",
            "head@{1}",
            "ref^",
            "ref~1",
            "ref:path",
            "ref?",
            "ref*",
            "ref[a]",
            "ref\\a",
            "main\0",
            "café",
        ] {
            assert!(
                super::validate_revision(revision).is_err(),
                "{revision:?} must be refused",
            );
        }
        assert!(super::validate_revision(&"v".repeat(257)).is_err());
    }

    /// The other half, without which the guard above could be a guard
    /// that refuses everything: the revisions HuggingFace actually serves
    /// still parse.
    #[test]
    fn ordinary_revisions_are_untouched() {
        for revision in [
            "main",
            "refs/pr/7",
            "refs/heads/release-1.2",
            "v1.0.0",
            "my_branch",
            "c1899de289a04d12100db370d81485cdf75e47ca",
        ] {
            let spec = ModelSpec::parse(&format!("org/model@{revision}"))
                .unwrap_or_else(|err| panic!("{revision:?} must parse: {err}"));
            assert_eq!(spec.revision(), revision);
        }
    }

    /// An id is encoded into a directory name rather than joined as a
    /// path, so the traversal was never live here — but resting on a
    /// dependency's private transform is not a property, and `--` is
    /// exactly what makes that transform reversible.
    #[test]
    fn an_id_that_is_not_a_repository_name_is_refused() {
        for id in [
            "../../../etc",
            "/etc/passwd",
            "org/model/extra",
            "org//model",
            "/model",
            "org/",
            ".hidden/model",
            "org/.hidden",
            "org/model-",
            "-org/model",
            "org--evil/model",
            "org/mo..del",
            "org/model.git",
            "org/model name",
            "org/model:tag",
            "org/модель",
        ] {
            assert!(
                matches!(
                    ModelSpec::parse(id),
                    Err(ModelSpecError::InvalidId { .. } | ModelSpecError::EmptyId),
                ),
                "{id:?} must be refused",
            );
        }
        assert!(matches!(
            ModelSpec::parse(&format!("org/{}", "m".repeat(97))),
            Err(ModelSpecError::InvalidId { .. }),
        ));
    }

    #[test]
    fn ordinary_repository_names_are_untouched() {
        for id in [
            "gpt2",
            "Qwen/Qwen3-0.6B",
            "HuggingFaceTB/SmolLM2-135M-Instruct",
            "meta-llama/Llama-3.1-8B",
            "hellas-test/enormous-repository-of-the-attacker-s-choosing",
            "org/model.v2",
            "org_name/model_name",
        ] {
            let spec =
                ModelSpec::parse(id).unwrap_or_else(|err| panic!("{id:?} must parse: {err}"));
            assert_eq!(spec.id(), id);
        }
    }
}
