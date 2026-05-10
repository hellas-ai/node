# Hellas-Alto Performance Architecture

This document outlines the core performance design decisions for the Hellas-Alto blockchain. It defines a hybrid architecture that combines the **object-centric parallel execution** pioneered by Sui with the **hardware-sympathetic, zero-overhead optimizations** of TigerBeetle.

## 1. Sui-Style Parallel Execution (The Core Engine)

Parallel execution is fundamental to scaling Hellas-Alto. Since State Channels operate mostly independently of global shared state, they are naturally commutative and highly parallelizable.

*   **Explicit State-Access Declarations (Object-Centric Model):** Every transaction MUST declare the exact state keys (e.g., specific `channel_id`, `client_balance_id`, `provider_balance_id`) it will read or write before execution. 
*   **Disjoint Parallelism:** The execution engine analyzes the read/write sets of incoming transactions in a block. Transactions with disjoint state dependencies (e.g., Channel A opening and Channel B closing) are executed on separate CPU cores concurrently without any locking overhead.
*   **Hotspot Mitigation:** For "Mega-Providers" that participate in thousands of channels simultaneously, directly updating their global balance per transaction would create a massive lock-contention hotspot. 
    *   *Solution:* State channel escrows should be locked from the client's end, and provider payouts can be aggregated. The provider's global balance does not need to be locked synchronously for every channel operation.

## 2. Advanced Chain Optimizations (From Sui, Aptos, & Monad)

Beyond basic parallel execution, modern high-performance chains achieve massive throughput using the following techniques, which should be integrated into Hellas-Alto:

*   **Decoupled Mempool and Consensus (Narwhal/Mysticeti):** Do not send full transactions through the consensus protocol (Minimmit). Instead, use a DAG-based mempool where nodes gossip batches of transactions constantly. The consensus layer only votes on small cryptographic commitments (metadata/hashes) to those batches. This maximizes network bandwidth and keeps the consensus layer lean.
*   **Pipelining / Asynchronous Execution:** The consensus layer (voting and finalizing blocks) should be completely decoupled from the execution layer (applying state transitions). Once consensus determines the total order of transactions (Block N), it immediately moves to ordering Block N+1, while a background thread pool executes Block N.
*   **Optimistic Concurrency Control (Block-STM from Aptos):** If strict state declaration becomes too complex for certain smart contracts, you can use Block-STM. Transactions are speculatively executed in parallel. If a read/write conflict is detected after the fact, the conflicting transaction is aborted and re-executed.

## 3. TigerBeetle-Inspired Hardware Sympathy

While Sui provides the blueprint for parallelizing workloads across cores, TigerBeetle provides the blueprint for making a single core process transactions at theoretical hardware limits. We can apply these to the individual worker threads in the parallel execution engine:

*   **Tightly Packed, Fixed-Size Schemas:** Avoid dynamic memory allocations (`String`, `Vec<u8>`). Use fixed-size byte arrays (e.g., `[u8; 32]`) for hashes, identifiers, and commitments. Use `#[repr(C)]` or `#[repr(packed)]` in Rust to ensure the memory layout of state objects fits perfectly into L1/L2 CPU cache lines.
*   **Zero Dynamic Memory Allocation (No `malloc` in the Hot Path):** The execution engine should never dynamically allocate memory during block processing. Pre-allocate all transaction buffers, state maps, and message queues when the node boots. This eliminates garbage collection pauses, memory fragmentation, and out-of-memory crashes under load.
*   **Direct I/O and `io_uring` (via Commonware):** The Write-Ahead Log (WAL) and block storage should bypass the OS page cache using Direct I/O (`O_DIRECT`). `commonware` likely provides or can wrap asynchronous I/O primitives (like `io_uring` on Linux). This ensures that disk writes never block the execution or consensus threads, preventing latency spikes.

## 4. The Hybrid Execution Strategy: "Parallel but Packed"

By adopting this hybrid approach, Hellas-Alto will achieve the best of both worlds:
1.  **Sui's Scalability:** We can utilize all available CPU cores by safely executing non-conflicting State Channel transactions in parallel.
2.  **TigerBeetle's Efficiency:** Each parallel thread operates on tightly packed, pre-allocated memory structures, executing state transitions incredibly fast without cache invalidations or memory allocation overhead.

**Rule of Thumb for Hellas-Alto Kernel Development:**
> "Declare state upfront to route it to a parallel thread, but once on that thread, execute using zero-allocation, fixed-size data structures."
