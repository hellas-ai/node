//! What the store must actually do, as opposed to appear to do.
//!
//! Three claims are load-bearing and each is asserted here rather than
//! described: an id identifies content and not a path; adopting a
//! directory is enough to answer `have`; and indexing keeps the chunk
//! list, because that is the half that makes a partial fetch
//! verifiable.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hellas_store::{ContentStore, Substituter};
use hellas_xet::{XetHash, file_hash};

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "hellas-store-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(content).expect("write");
        file.sync_all().expect("sync");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The defining property: identity is the content, not the location.
/// Two paths holding the same bytes are one entry.
#[test]
fn the_same_bytes_at_two_paths_are_one_content() {
    let fixture = Fixture::new("same-bytes");
    let content = bytes(300_000, 1);
    let left = fixture.write("a/weights.bin", &content);
    let right = fixture.write("b/copied-elsewhere.bin", &content);

    let store = ContentStore::new();
    let first = store.index(&left).expect("index left");
    let second = store.index(&right).expect("index right");

    assert_eq!(first.id, second.id, "content id must not depend on path");
    assert_eq!(first.chunks, second.chunks);
    assert_eq!(first.len, content.len() as u64);
    assert_eq!(store.len(), 1, "one content, however many paths hold it");
    assert!(store.have(first.id));
}

/// The id must be the Xet file hash of the bytes — the same value
/// HuggingFace publishes — not merely self-consistent.
#[test]
fn the_id_is_the_xet_file_hash_of_the_content() {
    let fixture = Fixture::new("id-is-xet");
    for size in [0, 1, 8_192, 200_000, 2 * 1024 * 1024 + 7] {
        let content = bytes(size, size as u64);
        let path = fixture.write(&format!("f{size}"), &content);
        let indexed = ContentStore::new().index(&path).expect("index");
        assert_eq!(indexed.id, XetHash::hash(&content), "size {size}");
        assert_eq!(file_hash(&indexed.chunks), indexed.id, "size {size} chunks");
    }
}

/// Adopting a directory is what makes an existing HuggingFace cache a
/// populated store — no copy, no download.
#[test]
fn adopting_a_directory_answers_have_for_everything_in_it() {
    let fixture = Fixture::new("adopt");
    let one = bytes(150_000, 10);
    let two = bytes(90_000, 11);
    fixture.write("models--org--name/blobs/aaa", &one);
    fixture.write("models--org--name/blobs/bbb", &two);

    let store = ContentStore::new();
    let adopted = store.adopt(&fixture.0).expect("adopt");

    assert_eq!(adopted.len(), 2);
    assert!(store.have(XetHash::hash(&one)));
    assert!(store.have(XetHash::hash(&two)));
    assert!(!store.have(XetHash::hash(&bytes(1000, 999))));
}

/// A HuggingFace cache is littered with things that are not content.
/// Indexing them would put ids of lock files and half-downloads into a
/// store whose whole value is that an id means the bytes.
#[test]
fn cache_debris_is_never_indexed() {
    let fixture = Fixture::new("debris");
    let real = bytes(50_000, 20);
    fixture.write("blobs/abcdef", &real);
    fixture.write("blobs/abcdef.lock", b"lock");
    fixture.write("download/x.etag.incomplete", &bytes(40_000, 21));
    fixture.write(".no_exist/sha/adapter_config.json", b"");

    let store = ContentStore::new();
    let adopted = store.adopt(&fixture.0).expect("adopt");

    assert_eq!(adopted.len(), 1, "only the real blob is content");
    assert_eq!(adopted[0].id, XetHash::hash(&real));
    assert!(store.index(&fixture.0.join("blobs/abcdef.lock")).is_err());
}

/// Indexing must keep the metainfo, not just the id. Without the chunk
/// list a partial fetch from an untrusted peer cannot be verified until
/// the whole file is reassembled.
#[test]
fn indexing_keeps_the_chunk_list() {
    let fixture = Fixture::new("chunks");
    // Several chunks, so the list is not trivially one entry.
    let content = bytes(5 * 131_072 + 999, 30);
    let path = fixture.write("big.bin", &content);

    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");
    assert!(indexed.chunks.len() > 3, "fixture must span several chunks");

    assert_eq!(
        store.content_len(indexed.id),
        Some(content.len() as u64),
        "size must be answerable without re-reading",
    );
    let held = store.chunks(indexed.id).expect("chunks are retained");
    assert_eq!(held, indexed.chunks);
    assert_eq!(file_hash(&held), indexed.id);
    assert_eq!(
        held.iter().map(|chunk| chunk.data_len).sum::<u64>(),
        content.len() as u64,
        "chunk lengths must account for every byte",
    );
}

/// A substituter answers for content the store never indexed. This is
/// how "somewhere else already has it" becomes usable without copying.
#[test]
fn a_substituter_can_answer_for_content_the_store_lacks() {
    struct Fixed(XetHash, PathBuf);
    impl Substituter for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        fn locate(&self, id: XetHash) -> Option<PathBuf> {
            (id == self.0).then(|| self.1.clone())
        }
    }

    let fixture = Fixture::new("substituter");
    let content = bytes(1_000, 40);
    let path = fixture.write("elsewhere.bin", &content);
    let id = XetHash::hash(&content);

    let bare = ContentStore::new();
    assert!(!bare.have(id), "nothing indexed, nothing substituted");

    let store = ContentStore::new().with_substituter(Arc::new(Fixed(id, path.clone())));
    assert!(store.have(id));
    assert_eq!(store.locate(id).as_deref(), Some(path.as_path()));
    assert!(!store.have(XetHash::hash(b"something else")));
}

/// `have` must not claim content that has been deleted underneath it.
/// A quote answered on a stale entry commits to weights that are gone.
#[test]
fn have_is_false_once_the_file_is_gone() {
    let fixture = Fixture::new("vanish");
    let content = bytes(20_000, 50);
    let path = fixture.write("temporary.bin", &content);

    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");
    assert!(store.have(indexed.id));

    std::fs::remove_file(&path).expect("remove");
    assert!(
        !store.have(indexed.id),
        "an index entry is not evidence the bytes are still there",
    );
    assert_eq!(store.locate(indexed.id), None);
}

/// Empty content has a defined id and is not special-cased into
/// existence.
#[test]
fn empty_content_is_addressable() {
    let fixture = Fixture::new("empty");
    let path = fixture.write("empty.bin", b"");
    let store = ContentStore::new();
    let indexed = store.index(Path::new(&path)).expect("index");
    assert_eq!(indexed.id, XetHash::ZERO);
    assert_eq!(indexed.len, 0);
    assert!(indexed.chunks.is_empty());
}
