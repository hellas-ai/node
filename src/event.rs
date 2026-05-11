//! Public events and private store effects.
//!
//! Abstract counterpart: `models/types.qnt::Event` (the public events
//! `EdgeOpenedEvent` / `EdgeResolvedEvent`) and the `lastEvent` recording
//! var in `models/l1.qnt`. ITF replay (`tests/itf.rs`) drives the kernel
//! and asserts each emitted [`EventKind`] against the abstract event the
//! producing action recorded.

use crate::{
    consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS},
    error::{ApplyError, KernelResult},
    list::List,
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId},
    store::Batch,
};

type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type ResolveCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;

/// Deterministic event diff produced by an ordered operation batch.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Diff<const N: usize> {
    events: [Option<Event>; N],
    len: usize,
}

impl<const N: usize> core::fmt::Debug for Diff<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<const N: usize> Diff<N> {
    pub(crate) const fn empty() -> Self {
        Self {
            events: [const { None }; N],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, event: &Event) {
        debug_assert!(self.len < N);
        self.events[self.len] = Some(event.clone());
        self.len += 1;
    }

    /// Returns the number of committed events in the diff.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the diff has no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the event at `index`, if any.
    #[must_use]
    pub const fn event(&self, index: usize) -> Option<&Event> {
        if index >= self.len {
            return None;
        }

        self.events[index].as_ref()
    }

    /// Iterates over committed events.
    pub fn iter(&self) -> impl Iterator<Item = &Event> + '_ {
        self.events[..self.len].iter().flatten()
    }
}

/// An externally visible kernel mutation.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Event {
    kind: EventKind,
}

impl Event {
    /// Returns the public event payload.
    #[must_use]
    pub const fn kind(&self) -> &EventKind {
        &self.kind
    }
}

/// Public event payload.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum EventKind {
    /// Bounded funding was locked into one shared edge.
    EdgeOpened {
        /// Coins consumed by the open.
        inputs: List<CoinId, MAX_EDGE_INPUTS>,
        /// Edge produced by the open.
        output: EdgeId,
    },

    /// One edge was resolved into bounded owner-only coins.
    EdgeResolved {
        /// Edge consumed by the resolve.
        input: EdgeId,
        /// Coins produced by the resolve.
        outputs: List<CoinId, MAX_EDGE_OUTPUTS>,
    },
}

/// Internal reducer output: public event plus private effect.
#[allow(clippy::redundant_pub_crate)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) struct Change {
    event: Event,
    effect: Effect,
}

impl Change {
    pub(super) fn open(inputs: &OpenCoins, output: (EdgeId, Edge)) -> Self {
        let event = Event {
            kind: EventKind::EdgeOpened {
                inputs: Self::ids(inputs),
                output: output.0,
            },
        };

        Self {
            event,
            effect: Effect::open(inputs.clone(), output),
        }
    }

    pub(super) fn resolve(input: (EdgeId, Edge), outputs: &ResolveCoins) -> Self {
        let event = Event {
            kind: EventKind::EdgeResolved {
                input: input.0,
                outputs: Self::ids(outputs),
            },
        };
        let effect = Effect::resolve(input, outputs.clone());

        Self { event, effect }
    }

    pub(super) const fn event(&self) -> &Event {
        &self.event
    }

    pub(super) fn fold<B: Batch>(&self, batch: &mut B) -> KernelResult<()> {
        self.effect.fold(batch)
    }

    fn ids<const N: usize>(coins: &List<(CoinId, Coin), N>) -> List<CoinId, N> {
        let fill = coins.as_slice().first().map_or(CoinId::ZERO, |&(id, _)| id);
        let mut items = [fill; N];
        for (index, (id, _)) in coins.as_slice().iter().enumerate() {
            items[index] = *id;
        }
        List::take(items, coins.len())
    }
}

/// Private store mutation carried by a [`Change`].
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
enum Effect {
    Open {
        coins: OpenCoins,
        edge: (EdgeId, Edge),
    },
    Resolve {
        edge: (EdgeId, Edge),
        coins: ResolveCoins,
    },
}

impl Effect {
    const fn open(coins: OpenCoins, edge: (EdgeId, Edge)) -> Self {
        Self::Open { edge, coins }
    }

    const fn resolve(edge: (EdgeId, Edge), coins: ResolveCoins) -> Self {
        Self::Resolve { edge, coins }
    }

    fn fold<B: Batch>(&self, batch: &mut B) -> KernelResult<()> {
        match self {
            Self::Open { coins, edge } => {
                Self::remove_coins(batch, coins)?;
                Self::insert_edge(batch, *edge)
            }
            Self::Resolve { edge, coins } => {
                Self::remove_edge(batch, *edge)?;
                Self::insert_coins(batch, coins)
            }
        }
    }

    fn insert_coins<B: Batch, const N: usize>(
        batch: &mut B,
        coins: &List<(CoinId, Coin), N>,
    ) -> KernelResult<()> {
        for coin in coins.as_slice() {
            Self::insert_coin(batch, *coin)?;
        }
        Ok(())
    }

    fn remove_coins<B: Batch, const N: usize>(
        batch: &mut B,
        coins: &List<(CoinId, Coin), N>,
    ) -> KernelResult<()> {
        for coin in coins.as_slice() {
            Self::remove_coin(batch, *coin)?;
        }
        Ok(())
    }

    fn insert_coin<B: Batch>(batch: &mut B, coin: (CoinId, Coin)) -> KernelResult<()> {
        batch
            .insert_coin(coin.0, coin.1)
            .map_err(|reason| ApplyError::CoinInsertRejected { id: coin.0, reason })
    }

    fn remove_coin<B: Batch>(batch: &mut B, coin: (CoinId, Coin)) -> KernelResult<()> {
        match batch.remove_coin(coin.0) {
            Some(removed) if removed == coin.1 => Ok(()),
            Some(_) => Err(ApplyError::CoinChanged { id: coin.0 }),
            None => Err(ApplyError::MissingCoin { id: coin.0 }),
        }
    }

    fn insert_edge<B: Batch>(batch: &mut B, edge: (EdgeId, Edge)) -> KernelResult<()> {
        batch
            .insert_edge(edge.0, edge.1)
            .map_err(|reason| ApplyError::EdgeInsertRejected { id: edge.0, reason })
    }

    fn remove_edge<B: Batch>(batch: &mut B, edge: (EdgeId, Edge)) -> KernelResult<()> {
        match batch.remove_edge(edge.0) {
            Some(removed) if removed == edge.1 => Ok(()),
            Some(_) => Err(ApplyError::EdgeChanged { id: edge.0 }),
            None => Err(ApplyError::MissingEdge { id: edge.0 }),
        }
    }
}
