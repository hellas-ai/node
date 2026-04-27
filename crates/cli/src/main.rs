#[macro_use]
extern crate tracing;

use catgrad::prelude::Dtype;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use tonic_iroh_transport::iroh::EndpointId;

mod commands;
mod execution;
mod identity;
mod metrics;
mod text_output;
mod tracing_config;

/// `clap` value parser for `--dtype`. Accepts `f32`, `f16`, `bf16`. Rejects
/// `u32`, which is the catgrad token-tensor dtype, never a model dtype.
fn parse_model_dtype(s: &str) -> Result<Dtype, String> {
    let dtype = Dtype::from_str(s)?;
    match dtype {
        Dtype::F32 | Dtype::F16 | Dtype::BF16 => Ok(dtype),
        Dtype::U32 => Err("model dtype must be f32, f16, or bf16".to_string()),
    }
}

/// Default dtype per build configuration. CUDA / Metal builds assume modern
/// hardware (Ampere+, M2+) where `bf16` matches the dtype most current models
/// are trained at and gives a real perf/VRAM win. CPU / unspecified-backend
/// builds default to `f32` because CPUs typically emulate bf16 via f32 anyway,
/// and `f32` is the safest broadly-correct choice. Used for `serve --dtype`
/// and `gateway --dtype`.
#[cfg(any(feature = "candle-cuda", feature = "candle-metal"))]
const DEFAULT_DTYPE_STR: &str = "bf16";
#[cfg(not(any(feature = "candle-cuda", feature = "candle-metal")))]
const DEFAULT_DTYPE_STR: &str = "f32";

/// Default `--dtype` preference list for `llm`, resolved at dispatch.
///
/// - **Network mode** (no `--local` / `--verify-local`): `[bf16, f32, f16]`
///   regardless of build. The remote executor decides what it can run; the
///   CLI's local hardware capability is irrelevant to the wire request.
/// - **Local-ish mode on a cuda/metal build**: same `[bf16, f32, f16]`.
///   The operator opted into a GPU-backend feature, so the build assumes
///   Ampere+/M2+ where bf16 is natively supported. If the GPU lacks bf16
///   the weight load will fail loudly at first attempt — that's a build /
///   hardware mismatch the operator should fix, not something we paper over.
/// - **Local-ish mode on a cpu / unspecified build**: `[f32, f16]`. Skips
///   bf16 because CPU bf16 throughput is rarely a win and we want a default
///   that loads on every backend including older GPUs an operator might
///   bring in via a non-standard build.
fn default_llm_dtypes(is_local_mode: bool) -> Vec<Dtype> {
    let cuda_or_metal = cfg!(any(feature = "candle-cuda", feature = "candle-metal"));
    if is_local_mode && !cuda_or_metal {
        vec![Dtype::F32, Dtype::F16]
    } else {
        vec![Dtype::BF16, Dtype::F32, Dtype::F16]
    }
}

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version)]
#[command(about = "Hellas node CLI")]
struct Cli {
    /// Path to node identity file (default: $HOME/.hellas/identity)
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Print the node ID (hex public key) derived from the identity file
    ShowNodeId,
}

#[derive(Subcommand)]
enum Commands {
    #[cfg(feature = "hellas-executor")]
    /// Run the RPC server
    Serve {
        /// Port to listen on (auto-selects if not specified or if in use)
        #[arg(long)]
        port: Option<u16>,
        /// Download policy: 'skip' (default, cache-only, never download),
        /// 'eager' (download freely),
        /// or 'allow(pattern,...)' (download only matching HF models)
        #[arg(long = "download-policy", default_value = "skip")]
        download_policy: hellas_rpc::policy::DownloadPolicy,
        /// Execute policy: 'skip' (default, refuse all executions),
        /// 'eager' (execute any graph),
        /// or 'allow(hf/pattern,...,graph/pattern,...)' (execute only matching)
        #[arg(long = "execute-policy", default_value = "skip")]
        execute_policy: hellas_rpc::policy::ExecutePolicy,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Preload model weights on startup. Repeat or use commas: --preload foo/bar --preload baz/qux@rev
        #[arg(long = "preload", value_delimiter = ',')]
        preload_weights: Vec<String>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Operator graffiti tag (up to 16 bytes, padded/truncated)
        #[arg(long = "graffiti", default_value = "")]
        graffiti: String,
        /// Dtypes this executor will accept, comma-separated. The first entry
        /// is the executor's preferred dtype (used when the server constructs
        /// a program itself, e.g. for `QuotePromptRequest`). Other entries are
        /// also accepted on a per-request basis. Each accepted dtype loads its
        /// own bundle of weights, so listing more dtypes costs more VRAM.
        /// Defaults to `f32`.
        #[arg(
            long = "dtype",
            default_value = DEFAULT_DTYPE_STR,
            value_delimiter = ',',
            value_parser = parse_model_dtype
        )]
        dtype: Vec<Dtype>,
    },
    /// Run HTTP gateway exposing OpenAI/Anthropic/plain APIs over Hellas network
    Gateway {
        /// Host interface to bind
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Direct target node id (omit to use discovery)
        #[arg(long)]
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[cfg(feature = "hellas-executor")]
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and verify that the response matches a local catgrad execution
        #[cfg(feature = "hellas-executor")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with_all = ["local", "verify"]
        )]
        verify_local: bool,
        /// Verify the primary remote node against a second remote node
        #[cfg_attr(
            feature = "hellas-executor",
            arg(
                long = "verify",
                conflicts_with_all = ["local", "verify_local"],
                requires = "node_id"
            )
        )]
        #[cfg_attr(
            not(feature = "hellas-executor"),
            arg(long = "verify", requires = "node_id")
        )]
        verify: Option<EndpointId>,
        /// Maximum number of queued local executions when `--local` is set
        #[cfg(feature = "hellas-executor")]
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Max execution retries on failure (discovery mode)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Fallback max new tokens when request omits max_tokens
        #[arg(long = "default-max-tokens", default_value_t = 128)]
        default_max_tokens: u32,
        /// Override request model and force this HuggingFace model id, optionally with @revision
        #[arg(long = "force-model")]
        force_model: Option<String>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Dtype the local executor (when `--local` or `--verify-local`) runs at,
        /// and the dtype the client builds the quote program at: f32, f16, or bf16
        #[arg(long = "dtype", default_value = DEFAULT_DTYPE_STR, value_parser = parse_model_dtype)]
        dtype: Dtype,
        /// Spawn `pi-coding-agent` once the gateway is listening. Args after
        /// `--` are forwarded to pi; the gateway exits when pi exits.
        /// Requires `--force-model` so pi can advertise a concrete model id.
        #[arg(long = "pi", default_value_t = false, requires = "force_model")]
        pi: bool,
        /// Path to the `pi` binary (default: looked up on PATH)
        #[arg(long = "pi-bin", default_value = "pi", requires = "pi")]
        pi_bin: String,
        /// Pi provider `api` kind. `openai-completions` hits `/v1/chat/completions`,
        /// `anthropic-messages` hits `/v1/messages`.
        #[arg(
            long = "pi-api",
            default_value = "openai-completions",
            value_parser = ["openai-completions", "anthropic-messages"],
            requires = "pi",
        )]
        pi_api: String,
        /// Redirect pi's stdout+stderr to this file (gateway's own logs are
        /// untouched). Default: pi inherits the parent terminal.
        #[arg(long = "pi-log", requires = "pi")]
        pi_log: Option<std::path::PathBuf>,
        /// Trailing args forwarded verbatim to `pi`. Use `--` to introduce them.
        #[arg(last = true, allow_hyphen_values = true)]
        pi_args: Vec<String>,
    },
    /// Query a remote node via RPC
    Rpc {
        /// Node ID to check
        node_id: EndpointId,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
    },
    /// Run LLM inference remotely or locally
    Llm {
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',', requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        /// HuggingFace model id used to fetch weights, optionally with @revision
        #[arg(short = 'm', long = "model", default_value = "Qwen/Qwen3-0.6B")]
        model: String,
        /// Prompt to send (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Pass the prompt through unchanged instead of applying the model chat template
        #[arg(long = "raw", default_value_t = false)]
        raw: bool,
        /// Maximum number of new tokens to generate
        #[arg(long = "max-seq", default_value_t = 16)]
        max_seq: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Run locally with the catgrad backend instead of the Hellas network
        #[cfg(feature = "hellas-executor")]
        #[arg(long = "local", default_value_t = false, conflicts_with_all = ["verify_local", "node_id", "node_addrs"])]
        local: bool,
        /// Run remotely and locally, then verify that both outputs match
        #[cfg(feature = "hellas-executor")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with = "local"
        )]
        verify_local: bool,
        /// Comma-separated preference list (each one of `f32`, `f16`,
        /// `bf16`). The client builds the quote program at the first entry,
        /// then on a remote `DtypeNotSupported` rejection retries at the
        /// next. For `--local` / `--verify-local` the embedded executor's
        /// `supported_dtypes` is the full list. If omitted the default
        /// depends on the build and mode (cuda/metal builds and any network
        /// mode prefer `bf16,f32,f16`; cpu builds in local-ish mode prefer
        /// `f32,f16` to stay safe on hardware without bf16/f16 support).
        #[arg(long = "dtype", value_delimiter = ',', value_parser = parse_model_dtype)]
        dtype: Vec<Dtype>,
    },
    /// Inspect the local identity file
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Discover peers and log network events
    Monitor {
        /// Stop monitoring after N seconds (default: run until Ctrl+C)
        #[arg(long = "timeout-secs")]
        timeout_secs: Option<u64>,
        /// Disable peer interrogation RPCs (health + known peers)
        #[arg(long = "no-interrogate", default_value_t = false)]
        no_interrogate: bool,
    },
}

#[tokio::main]
async fn main() {
    let tracer_provider = tracing_config::init_tracing();

    let cli = Cli::parse();

    // show-node-id is a read-only query; never create an identity file as a
    // side effect of it (would race with a running service's own creator).
    let load_identity = match &cli.command {
        Commands::Identity {
            command: IdentityCommand::ShowNodeId,
        } => identity::load_existing,
        _ => identity::load_or_create,
    };
    let secret_key = match load_identity(cli.identity.as_deref()) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        #[cfg(feature = "hellas-executor")]
        Commands::Serve {
            port,
            download_policy,
            execute_policy,
            queue_size,
            preload_weights,
            metrics_port,
            graffiti,
            dtype,
        } => {
            commands::serve::run(
                port,
                download_policy,
                execute_policy,
                queue_size,
                preload_weights,
                metrics_port,
                graffiti,
                dtype,
                secret_key,
            )
            .await
        }
        Commands::Gateway {
            host,
            port,
            node_id,
            node_addrs,
            #[cfg(feature = "hellas-executor")]
            local,
            #[cfg(feature = "hellas-executor")]
            verify_local,
            verify,
            #[cfg(feature = "hellas-executor")]
            queue_size,
            retries,
            default_max_tokens,
            force_model,
            metrics_port,
            dtype,
            pi,
            pi_bin,
            pi_api,
            pi_log,
            pi_args,
        } => {
            commands::gateway::run(commands::gateway::GatewayOptions {
                host,
                port,
                node_id,
                node_addrs,
                #[cfg(feature = "hellas-executor")]
                local,
                #[cfg(feature = "hellas-executor")]
                verify_local,
                verify,
                #[cfg(feature = "hellas-executor")]
                queue_size,
                retries,
                default_max_tokens,
                force_model,
                metrics_port,
                dtype,
                secret_key,
                pi,
                pi_bin,
                pi_api,
                pi_log,
                pi_args,
            })
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        Commands::Llm {
            node_id,
            node_addrs,
            model,
            prompt,
            raw,
            max_seq,
            retries,
            #[cfg(feature = "hellas-executor")]
            local,
            #[cfg(feature = "hellas-executor")]
            verify_local,
            dtype,
        } => {
            #[cfg(feature = "hellas-executor")]
            let is_local_mode = local || verify_local;
            #[cfg(not(feature = "hellas-executor"))]
            let is_local_mode = false;
            let dtype = if dtype.is_empty() {
                default_llm_dtypes(is_local_mode)
            } else {
                dtype
            };
            commands::llm::run(
                commands::llm::ExecuteOptions {
                    node_id,
                    node_addrs,
                    model,
                    prompt,
                    raw,
                    max_seq,
                    retries,
                    #[cfg(feature = "hellas-executor")]
                    local,
                    #[cfg(feature = "hellas-executor")]
                    verify_local,
                    dtype,
                },
                secret_key,
            )
            .await
        }
        Commands::Identity { command } => match command {
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
        },
        Commands::Monitor {
            timeout_secs,
            no_interrogate,
        } => commands::monitor::run(timeout_secs, !no_interrogate, secret_key).await,
    };

    if let Some(provider) = tracer_provider
        && let Err(err) = provider.shutdown()
    {
        eprintln!("warning: failed to flush traces: {err}");
    }

    if let Err(err) = result {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn llm_accepts_local_mode() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--local", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm {
                node_id,
                node_addrs,
                local,
                verify_local,
                raw,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
                assert!(!verify_local);
                assert!(!raw);
            }
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_accepts_raw_mode() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--raw", "-p", "hello"]).unwrap();
        match cli.command {
            Commands::Llm { raw, .. } => assert!(raw),
            _ => panic!("expected llm command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn llm_rejects_local_with_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "llm",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
            "--local",
            "-p",
            "hello",
        ]);

        assert!(result.is_err());
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn llm_rejects_conflicting_local_modes() {
        let result =
            Cli::try_parse_from(["hellas", "llm", "--local", "--verify-local", "-p", "hello"]);

        assert!(result.is_err());
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn gateway_accepts_local_mode() {
        let cli = Cli::try_parse_from(["hellas", "gateway", "--local"]).unwrap();
        match cli.command {
            Commands::Gateway {
                node_id,
                node_addrs,
                local,
                ..
            } => {
                assert!(node_id.is_none());
                assert!(node_addrs.is_empty());
                assert!(local);
            }
            _ => panic!("expected gateway command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn gateway_rejects_local_with_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "gateway",
            "--local",
            "--node-id",
            "bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn llm_rejects_node_addr_without_node_id() {
        let result = Cli::try_parse_from([
            "hellas",
            "llm",
            "--node-addr",
            "127.0.0.1:31145",
            "-p",
            "hello",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn gateway_rejects_node_addr_without_node_id() {
        let result = Cli::try_parse_from(["hellas", "gateway", "--node-addr", "127.0.0.1:31145"]);

        assert!(result.is_err());
    }

    /// On CPU-only builds the default is `f32`; on CUDA/Metal builds it is
    /// `bf16`. See [`DEFAULT_DTYPE_STR`]. Used for `serve` / `gateway`,
    /// which still take a single dtype.
    fn expected_default_dtype() -> Dtype {
        parse_model_dtype(DEFAULT_DTYPE_STR).unwrap()
    }

    #[test]
    fn llm_dtype_omitted_yields_empty_vec_for_runtime_resolution() {
        // Clap parses no `--dtype` as an empty `Vec<Dtype>`; main resolves
        // the per-mode default via [`default_llm_dtypes`].
        let cli = Cli::try_parse_from(["hellas", "llm", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => assert!(dtype.is_empty()),
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_accepts_single_dtype() {
        let cli = Cli::try_parse_from(["hellas", "llm", "--dtype", "f16", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => assert_eq!(dtype, vec![Dtype::F16]),
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn llm_accepts_dtype_preference_list() {
        let cli =
            Cli::try_parse_from(["hellas", "llm", "--dtype", "bf16,f32,f16", "-p", "hi"]).unwrap();
        match cli.command {
            Commands::Llm { dtype, .. } => {
                assert_eq!(dtype, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
            }
            _ => panic!("expected llm command"),
        }
    }

    #[test]
    fn default_llm_dtypes_local_cpu_skips_bf16() {
        let cuda_or_metal = cfg!(any(feature = "candle-cuda", feature = "candle-metal"));
        let prefs = default_llm_dtypes(/* is_local_mode = */ true);
        if cuda_or_metal {
            assert_eq!(prefs, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
        } else {
            assert_eq!(prefs, vec![Dtype::F32, Dtype::F16]);
        }
    }

    #[test]
    fn default_llm_dtypes_network_uses_bf16_first() {
        let prefs = default_llm_dtypes(/* is_local_mode = */ false);
        assert_eq!(prefs, vec![Dtype::BF16, Dtype::F32, Dtype::F16]);
    }

    #[test]
    fn gateway_accepts_dtype_bf16() {
        let cli = Cli::try_parse_from(["hellas", "gateway", "--dtype", "bf16"]).unwrap();
        match cli.command {
            Commands::Gateway { dtype, .. } => assert_eq!(dtype, Dtype::BF16),
            _ => panic!("expected gateway command"),
        }
    }

    #[test]
    fn gateway_pi_forwards_trailing_args() {
        let cli = Cli::try_parse_from([
            "hellas",
            "gateway",
            "--force-model",
            "Qwen/Qwen3-0.6B",
            "--pi",
            "--",
            "-p",
            "--no-session",
            "say hello",
        ])
        .unwrap();
        match cli.command {
            Commands::Gateway { pi, pi_args, .. } => {
                assert!(pi);
                assert_eq!(pi_args, vec!["-p", "--no-session", "say hello"]);
            }
            _ => panic!("expected gateway command"),
        }
    }

    #[test]
    fn gateway_pi_requires_force_model() {
        let result = Cli::try_parse_from(["hellas", "gateway", "--pi"]);
        assert!(result.is_err(), "--pi without --force-model should error");
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_accepts_dtype_f16() {
        let cli = Cli::try_parse_from(["hellas", "serve", "--dtype", "f16"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => assert_eq!(dtype, vec![Dtype::F16]),
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_accepts_multi_dtype() {
        let cli = Cli::try_parse_from(["hellas", "serve", "--dtype", "f32,f16,bf16"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => {
                assert_eq!(dtype, vec![Dtype::F32, Dtype::F16, Dtype::BF16]);
            }
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_dtype_defaults_to_build_default() {
        let cli = Cli::try_parse_from(["hellas", "serve"]).unwrap();
        match cli.command {
            Commands::Serve { dtype, .. } => {
                assert_eq!(dtype, vec![expected_default_dtype()]);
            }
            _ => panic!("expected serve command"),
        }
    }

    #[cfg(feature = "hellas-executor")]
    #[test]
    fn serve_rejects_dtype_u32_in_list() {
        let result = Cli::try_parse_from(["hellas", "serve", "--dtype", "f32,u32"]);
        assert!(result.is_err());
    }

    #[test]
    fn llm_rejects_dtype_u32() {
        let result = Cli::try_parse_from(["hellas", "llm", "--dtype", "u32", "-p", "hi"]);
        assert!(result.is_err());
    }
}
