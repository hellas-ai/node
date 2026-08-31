use crate::{ContentId, DagCborEncoder};

use super::value::{CanonicalDecodeError, CanonicalDecoder};

const PROGRAM_MANIFEST_DOMAIN: &str = "hellas.program.manifest.v4";
const MAX_PROGRAM_MANIFEST_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 byte length of each opaque application identity component.
pub const MAX_APPLICATION_ID_BYTES: usize = 1024;

/// The exact evaluator and adaptor that interpret a program root.
///
/// Both identifiers are opaque. Identity compares the complete pair exactly as
/// supplied: this layer performs no parsing, normalization, version
/// negotiation, or compatibility inference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Application {
    evaluator: String,
    adaptor: String,
}

impl Application {
    /// Builds one exact application identity without parsing or normalization.
    pub fn new(
        evaluator: impl Into<String>,
        adaptor: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        let evaluator = evaluator.into();
        let adaptor = adaptor.into();
        if evaluator.is_empty() {
            return Err(ApplicationError::EmptyEvaluator);
        }
        if evaluator.len() > MAX_APPLICATION_ID_BYTES {
            return Err(ApplicationError::EvaluatorTooLong {
                bytes: evaluator.len(),
                limit: MAX_APPLICATION_ID_BYTES,
            });
        }
        if adaptor.is_empty() {
            return Err(ApplicationError::EmptyAdaptor);
        }
        if adaptor.len() > MAX_APPLICATION_ID_BYTES {
            return Err(ApplicationError::AdaptorTooLong {
                bytes: adaptor.len(),
                limit: MAX_APPLICATION_ID_BYTES,
            });
        }
        Ok(Self { evaluator, adaptor })
    }

    /// Returns the exact opaque evaluator identity.
    #[must_use]
    pub fn evaluator(&self) -> &str {
        &self.evaluator
    }

    /// Returns the exact opaque adaptor identity.
    #[must_use]
    pub fn adaptor(&self) -> &str {
        &self.adaptor
    }
}

/// A malformed opaque component of an [`Application`] identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationError {
    /// The evaluator identity was empty.
    #[error("application evaluator must not be empty")]
    EmptyEvaluator,
    /// The adaptor identity was empty.
    #[error("application adaptor must not be empty")]
    EmptyAdaptor,
    /// The evaluator identity exceeded [`MAX_APPLICATION_ID_BYTES`].
    #[error("application evaluator is {bytes} UTF-8 bytes, over the {limit}-byte limit")]
    EvaluatorTooLong {
        /// Observed UTF-8 byte length.
        bytes: usize,
        /// Maximum accepted UTF-8 byte length.
        limit: usize,
    },
    /// The adaptor identity exceeded [`MAX_APPLICATION_ID_BYTES`].
    #[error("application adaptor is {bytes} UTF-8 bytes, over the {limit}-byte limit")]
    AdaptorTooLong {
        /// Observed UTF-8 byte length.
        bytes: usize,
        /// Maximum accepted UTF-8 byte length.
        limit: usize,
    },
}

/// One application-owned, content-addressed execution environment.
///
/// The application defines the meaning of `root`. For example, Catena causal
/// LM roots exclude tokenizers, chat templates, decoding, and other
/// presentation policy. An attested Fetch application instead includes its
/// exact request structuring and response destructuring because those steps are
/// trusted computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramManifest {
    application: Application,
    root: ContentId,
}

impl ProgramManifest {
    /// Binds an exact application identity to its application-owned root.
    #[must_use]
    pub const fn new(application: Application, root: ContentId) -> Self {
        Self { application, root }
    }

    /// Returns the complete, exact interpreter identity.
    #[must_use]
    pub const fn application(&self) -> &Application {
        &self.application
    }

    /// Returns the content identifier whose structure the application owns.
    #[must_use]
    pub const fn root(&self) -> ContentId {
        self.root
    }

    /// Strict DAG-CBOR `[domain, [evaluator, adaptor], root]` encoding.
    ///
    /// Definite arrays and the minimal encoder give every manifest exactly one
    /// wire representation, independent of which application interprets it.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(3);
        encoder.str(PROGRAM_MANIFEST_DOMAIN);
        encoder.array(2);
        encoder.str(&self.application.evaluator);
        encoder.str(&self.application.adaptor);
        encoder.bytes(self.root.as_bytes());
        encoder.into_bytes()
    }

    /// Decodes the single strict, bounded DAG-CBOR manifest representation.
    ///
    /// Evaluator and adaptor identifiers remain exact opaque strings; decoding
    /// does not normalize, parse, or negotiate either one.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        if bytes.len() > MAX_PROGRAM_MANIFEST_BYTES {
            return Err(CanonicalDecodeError::new(format!(
                "program manifest is {} bytes, over the {MAX_PROGRAM_MANIFEST_BYTES}-byte limit",
                bytes.len()
            )));
        }

        let mut decoder = CanonicalDecoder::new(bytes);
        decoder.array_exact(3)?;
        decoder.expect_str(PROGRAM_MANIFEST_DOMAIN)?;
        decoder.array_exact(2)?;
        let evaluator = decoder.str()?.to_string();
        let adaptor = decoder.str()?.to_string();
        let root = ContentId::from_bytes(decoder.bytes_32()?);
        decoder.finish()?;

        let application = Application::new(evaluator, adaptor)
            .map_err(|error| CanonicalDecodeError::new(error.to_string()))?;
        let manifest = Self::new(application, root);
        if manifest.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::new(
                "program manifest is not in canonical DAG-CBOR form",
            ));
        }
        Ok(manifest)
    }

    /// Returns the Xet content identifier of the canonical manifest bytes.
    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(evaluator: &str, adaptor: &str, root: u8) -> ProgramManifest {
        ProgramManifest::new(
            Application::new(evaluator, adaptor).unwrap(),
            ContentId::from_bytes([root; 32]),
        )
    }

    fn raw_manifest(evaluator: &str, adaptor: &str) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(3);
        encoder.str(PROGRAM_MANIFEST_DOMAIN);
        encoder.array(2);
        encoder.str(evaluator);
        encoder.str(adaptor);
        encoder.bytes(&[0; 32]);
        encoder.into_bytes()
    }

    #[test]
    fn application_validates_each_exact_utf8_component() {
        assert_eq!(
            Application::new("", "a"),
            Err(ApplicationError::EmptyEvaluator)
        );
        assert_eq!(
            Application::new("e", ""),
            Err(ApplicationError::EmptyAdaptor)
        );

        let boundary = "é".repeat(MAX_APPLICATION_ID_BYTES / 2);
        let application = Application::new(boundary.clone(), boundary.clone()).unwrap();
        assert_eq!(application.evaluator(), boundary);
        assert_eq!(application.adaptor(), boundary);
        let manifest = ProgramManifest::new(application, ContentId::from_bytes([0; 32]));
        assert!(manifest.canonical_bytes().len() <= MAX_PROGRAM_MANIFEST_BYTES);

        let unnormalized = Application::new(" evaluator ", "Adaptor+Build").unwrap();
        assert_eq!(unnormalized.evaluator(), " evaluator ");
        assert_eq!(unnormalized.adaptor(), "Adaptor+Build");

        assert_eq!(
            Application::new("e".repeat(MAX_APPLICATION_ID_BYTES + 1), "a"),
            Err(ApplicationError::EvaluatorTooLong {
                bytes: MAX_APPLICATION_ID_BYTES + 1,
                limit: MAX_APPLICATION_ID_BYTES,
            })
        );
        assert_eq!(
            Application::new("e", "é".repeat(MAX_APPLICATION_ID_BYTES / 2 + 1)),
            Err(ApplicationError::AdaptorTooLong {
                bytes: MAX_APPLICATION_ID_BYTES + 2,
                limit: MAX_APPLICATION_ID_BYTES,
            })
        );
    }

    #[test]
    fn decoder_applies_the_same_application_validation() {
        for (bytes, expected) in [
            (raw_manifest("", "a"), ApplicationError::EmptyEvaluator),
            (raw_manifest("e", ""), ApplicationError::EmptyAdaptor),
            (
                raw_manifest(&"e".repeat(MAX_APPLICATION_ID_BYTES + 1), "a"),
                ApplicationError::EvaluatorTooLong {
                    bytes: MAX_APPLICATION_ID_BYTES + 1,
                    limit: MAX_APPLICATION_ID_BYTES,
                },
            ),
            (
                raw_manifest("e", &"a".repeat(MAX_APPLICATION_ID_BYTES + 1)),
                ApplicationError::AdaptorTooLong {
                    bytes: MAX_APPLICATION_ID_BYTES + 1,
                    limit: MAX_APPLICATION_ID_BYTES,
                },
            ),
        ] {
            assert_eq!(
                ProgramManifest::from_canonical_bytes(&bytes)
                    .unwrap_err()
                    .to_string(),
                expected.to_string()
            );
        }
    }

    #[test]
    fn canonical_bytes_are_one_domain_tagged_shape() {
        let manifest = manifest("e", "a", 0x11);
        let mut expected = vec![0x83, 0x78, 0x1a];
        expected.extend_from_slice(b"hellas.program.manifest.v4");
        expected.extend_from_slice(&[0x82, 0x61, b'e', 0x61, b'a', 0x58, 0x20]);
        expected.extend_from_slice(&[0x11; 32]);

        assert_eq!(manifest.canonical_bytes(), expected);
        assert_eq!(
            ProgramManifest::from_canonical_bytes(&expected),
            Ok(manifest.clone())
        );
        assert_eq!(manifest.content_id(), ContentId::hash(&expected));
        assert_eq!(
            manifest.content_id().to_string(),
            "a0e154011f3dc2fdbcf69fafedca1d4aaf6bfc6e8fff625052c9a6f2b9169186"
        );
    }

    #[test]
    fn identity_binds_the_whole_opaque_application_pair_and_root() {
        let joined_left = manifest("ab", "c", 7);
        let joined_right = manifest("a", "bc", 7);
        let other_evaluator = manifest("AB", "c", 7);
        let other_adaptor = manifest("ab", "C", 7);
        let other_root = manifest("ab", "c", 8);

        for other in [&joined_right, &other_evaluator, &other_adaptor, &other_root] {
            assert_ne!(&joined_left, other);
            assert_ne!(joined_left.content_id(), other.content_id());
        }
    }

    #[test]
    fn decoder_rejects_noncanonical_trailing_and_oversized_inputs() {
        let canonical = manifest("e", "a", 0x11).canonical_bytes();

        let mut noncanonical = vec![0x98, 0x03];
        noncanonical.extend_from_slice(&canonical[1..]);
        assert!(
            ProgramManifest::from_canonical_bytes(&noncanonical)
                .unwrap_err()
                .to_string()
                .contains("non-canonical")
        );

        let mut trailing = canonical;
        trailing.push(0);
        assert!(
            ProgramManifest::from_canonical_bytes(&trailing)
                .unwrap_err()
                .to_string()
                .contains("trailing bytes")
        );

        let oversized = vec![0; MAX_PROGRAM_MANIFEST_BYTES + 1];
        assert!(
            ProgramManifest::from_canonical_bytes(&oversized)
                .unwrap_err()
                .to_string()
                .contains("over")
        );
    }
}
