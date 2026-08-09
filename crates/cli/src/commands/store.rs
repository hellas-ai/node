//! Operating the content store from the command line.
//!
//! The store is otherwise only reachable from inside the executor, which
//! makes it impossible to answer "what does this node already hold?"
//! without running one. These commands exist so adopting a cache,
//! checking what is present, and pulling a file are things an operator
//! can do and observe.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use hellas_store::ContentStore;
use hellas_store::hf::{HfCas, Repo, RepoKind};
use hellas_store::hf_cache::HfCache;
use hellas_xet::XetHash;

use crate::commands::CliResult;

#[derive(Subcommand)]
pub enum StoreCommand {
    /// Index a HuggingFace cache so its contents can be served without
    /// re-downloading them
    Adopt {
        /// Cache root (default: HF_HUB_CACHE, else HF_HOME/hub, else
        /// ~/.cache/huggingface/hub)
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Where to persist what was hashed
        #[arg(long)]
        records: Option<PathBuf>,
        /// Hash everything again, ignoring any existing record
        #[arg(long)]
        recheck: bool,
    },
    /// Show what a persisted record holds
    Status {
        #[arg(long)]
        records: Option<PathBuf>,
    },
    /// Fetch one content id from HuggingFace and verify it
    Fetch {
        /// Xet file hash, 64 hex characters
        #[arg(long)]
        id: String,
        /// Repository the read token is minted for, `org/name`
        #[arg(long)]
        repo: String,
        /// Treat the repository as a dataset rather than a model
        #[arg(long)]
        dataset: bool,
        #[arg(long, default_value = "main")]
        revision: String,
        /// Where to write the content
        #[arg(long)]
        out: PathBuf,
    },
}

pub async fn run(command: StoreCommand) -> CliResult {
    match command {
        StoreCommand::Adopt {
            cache,
            records,
            recheck,
        } => adopt(cache, records, recheck),
        StoreCommand::Status { records } => status(records),
        StoreCommand::Fetch {
            id,
            repo,
            dataset,
            revision,
            out,
        } => fetch(&id, &repo, dataset, &revision, &out),
    }
}

fn records_path(explicit: Option<PathBuf>) -> CliResult<PathBuf> {
    explicit
        .or_else(hellas_store::state::records_path)
        .ok_or_else(|| anyhow::anyhow!("no home directory; pass --records"))
}

fn adopt(cache: Option<PathBuf>, records: Option<PathBuf>, recheck: bool) -> CliResult {
    let cache = match cache {
        Some(root) => HfCache::new(root),
        None => HfCache::discover()
            .ok_or_else(|| anyhow::anyhow!("no HuggingFace cache found; pass --cache"))?,
    };
    let records_path = records_path(records)?;

    let store = ContentStore::new();
    let loaded = if recheck {
        0
    } else {
        store.records().load(&records_path)
    };

    let started = std::time::Instant::now();
    let adopted = cache.adopt_into(&store)?;
    let elapsed = started.elapsed();
    let saved = store.records().save(&records_path)?;

    // Adopting a cache the quote path has never heard of would leave the
    // operator watching quotes refuse for models this command just said
    // it holds. Recording the root is what makes those one question.
    let registry = hellas_store::state::adopted_caches_path();
    if let Some(registry) = registry.as_deref() {
        hellas_store::hf_cache::remember_adopted(registry, cache.root())?;
    }

    println!("cache      {}", cache.root().display());
    println!(
        "known      {loaded} remembered from {}",
        records_path.display()
    );
    println!("adopted    {adopted} blobs in {elapsed:.2?}");
    println!("contents   {} distinct", store.len());
    println!("records    {saved} saved");
    match registry.as_deref() {
        Some(registry) => println!("quotable   from {}", registry.display()),
        None => println!("quotable   no; set HELLAS_STORE_DIR or HOME so the root can be recorded"),
    }
    Ok(())
}

fn status(records: Option<PathBuf>) -> CliResult {
    let path = records_path(records)?;
    let store = ContentStore::new();
    let loaded = store.records().load(&path);
    println!("records    {}", path.display());
    println!("remembered {loaded} files");
    // The caches a node resolves models against. Kept beside the record
    // rather than derived from `--records`, because it is state about
    // this node and not about one invocation of this command.
    if let Some(registry) = hellas_store::state::adopted_caches_path() {
        println!("caches     {}", registry.display());
        for root in hellas_store::hf_cache::adopted_caches_in(&registry) {
            println!("adopted    {}", root.display());
        }
    }
    if loaded == 0 && !path.exists() {
        println!("\nNothing adopted yet. Try: hellas store adopt");
    }
    Ok(())
}

fn fetch(id: &str, repo: &str, dataset: bool, revision: &str, out: &Path) -> CliResult {
    let id: XetHash = id
        .parse()
        .map_err(|_| anyhow::anyhow!("--id must be 64 hex characters"))?;
    let source = HfCas::new(Repo {
        kind: if dataset {
            RepoKind::Dataset
        } else {
            RepoKind::Model
        },
        id: repo.to_string(),
        revision: revision.to_string(),
    });

    let store = ContentStore::new();
    let started = std::time::Instant::now();
    // `materialize` re-indexes and refuses to keep anything that does
    // not hash to `id`, so reaching the print below is itself the proof
    // the bytes are the ones asked for.
    let indexed = store.materialize(id, out, &source)?;
    println!("id         {}", indexed.id);
    println!("bytes      {}", indexed.len);
    println!("chunks     {}", indexed.chunks.len());
    println!("written    {} in {:.2?}", out.display(), started.elapsed());
    Ok(())
}
