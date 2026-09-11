use super::*;

impl SetupRecord {
    /// Whether recording this step is what lets a signature leave.
    ///
    /// The two revisions, and only those: everything else here is a
    /// marker about transactions already signed, or a note of what a
    /// finalized block said.
    pub(super) const fn exports_signature(&self) -> bool {
        matches!(self, Self::Bundle { .. } | Self::ArmedBundle { .. })
    }

    /// Whether this step takes on an obligation rather than discharging
    /// one.
    ///
    /// The scan floor and the two revisions are where a handshake
    /// commits itself, so they are what stops when the journal cannot
    /// rotate. Everything below them follows a revision this endpoint
    /// has already exported — the submissions it authorised, the history
    /// that resolves them, and the end it reaches — and a journal that
    /// refused those would be one that stopped an obligation it had
    /// already taken.
    pub(super) const fn is_new_work(&self) -> bool {
        matches!(
            self,
            Self::Bundle { .. } | Self::ArmedBundle { .. } | Self::ScanArmed { .. }
        )
    }

    /// Returns this record's canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Bundle { bundle } => {
                out.push(tag::BUNDLE);
                // Last field, and the whole of the rest: the journal
                // frame already carries this record's length, and a
                // second length here could disagree with it.
                out.extend_from_slice(bundle);
            }
            Self::ScanArmed { height, payload } => {
                out.push(tag::SCAN_ARMED);
                put_u64(&mut out, *height);
                out.extend_from_slice(payload);
            }
            Self::ArmedBundle {
                bundle,
                close_descriptor,
            } => {
                out.push(tag::ARMED_BUNDLE);
                put_u64(&mut out, u64::try_from(bundle.len()).unwrap_or(u64::MAX));
                out.extend_from_slice(bundle);
                out.extend_from_slice(&close_descriptor.encode());
            }
            Self::SetupHistoryBatch(batch) => {
                out.push(tag::SETUP_HISTORY_BATCH);
                out.extend_from_slice(&(batch.blocks.len() as u16).to_be_bytes());
                for block in &batch.blocks {
                    put_block(&mut out, block);
                }
            }
            Self::BondTimeoutSubmitted => out.push(tag::BOND_TIMEOUT_SUBMITTED),
            Self::BondSubmitted => out.push(tag::BOND_SUBMITTED),
            Self::PaymentSubmitted => out.push(tag::PAYMENT_SUBMITTED),
            Self::Complete {
                payment_edge,
                origin_height,
                origin_payload,
                origin_parent,
            } => {
                out.push(tag::COMPLETE);
                out.extend_from_slice(&payment_edge.to_bytes());
                put_u64(&mut out, *origin_height);
                out.extend_from_slice(origin_payload);
                out.extend_from_slice(origin_parent);
            }
            Self::Ended { outcome } => {
                out.push(tag::ENDED);
                out.push(end_to_code(*outcome));
            }
        }
        out
    }

    /// Reads one record from exactly its canonical bytes.
    ///
    /// # Errors
    ///
    /// [`SetupStateError::Malformed`] for an unknown tag, a truncated
    /// body, or a trailing byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, SetupStateError> {
        let mut cursor = Cursor::new(bytes);
        let record = match cursor.byte().ok_or(SetupStateError::Malformed)? {
            tag::BUNDLE => Self::Bundle {
                bundle: cursor.rest().to_vec(),
            },
            tag::SCAN_ARMED => Self::ScanArmed {
                height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
            },
            tag::ARMED_BUNDLE => {
                let bundle_len = usize::try_from(cursor.u64().ok_or(SetupStateError::Malformed)?)
                    .map_err(|_| SetupStateError::Malformed)?;
                let bundle = cursor
                    .take(bundle_len)
                    .ok_or(SetupStateError::Malformed)?
                    .to_vec();
                let close_descriptor = CloseDescriptor::decode(cursor.rest())
                    .map_err(|_| SetupStateError::Malformed)?;
                Self::ArmedBundle {
                    bundle,
                    close_descriptor: Box::new(close_descriptor),
                }
            }
            tag::SETUP_HISTORY_BATCH => {
                let count = usize::from(u16::from_be_bytes(
                    cursor.array::<2>().ok_or(SetupStateError::Malformed)?,
                ));
                let mut blocks = Vec::with_capacity(count);
                for _ in 0..count {
                    blocks.push(take_block(&mut cursor)?);
                }
                Self::SetupHistoryBatch(SetupHistoryBatch { blocks })
            }
            tag::BOND_TIMEOUT_SUBMITTED => Self::BondTimeoutSubmitted,
            tag::BOND_SUBMITTED => Self::BondSubmitted,
            tag::PAYMENT_SUBMITTED => Self::PaymentSubmitted,
            tag::COMPLETE => Self::Complete {
                payment_edge: EdgeId::from_bytes(
                    cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                ),
                origin_height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                origin_payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                origin_parent: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
            },
            tag::ENDED => Self::Ended {
                outcome: end_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)
                    .ok_or(SetupStateError::Malformed)?,
            },
            _ => return Err(SetupStateError::Malformed),
        };
        if cursor.is_empty() {
            Ok(record)
        } else {
            Err(SetupStateError::Malformed)
        }
    }
}

/// Writes one finalized header and the transactions in it.
///
/// One spelling, because a record and a checkpoint hold the same blocks:
/// a second encoder for the checkpoint's copy would be a second answer
/// to what a retained block is.
pub(super) fn put_block(out: &mut Vec<u8>, block: &SetupHistoryBlock) {
    put_u64(out, block.height);
    out.extend_from_slice(&block.parent);
    out.extend_from_slice(&block.payload);
    out.extend_from_slice(&(block.txs.len() as u16).to_be_bytes());
    for tx in &block.txs {
        let mut bytes = vec![0_u8; Tx::MAX_ENCODED_SIZE];
        let written = tx.write_to(&mut bytes);
        out.extend_from_slice(&(written as u32).to_be_bytes());
        out.extend_from_slice(&bytes[..written]);
    }
}

/// Reads back exactly what [`put_block`] wrote.
pub(super) fn take_block(cursor: &mut Cursor<'_>) -> Result<SetupHistoryBlock, SetupStateError> {
    let height = cursor.u64().ok_or(SetupStateError::Malformed)?;
    let parent = cursor.array::<32>().ok_or(SetupStateError::Malformed)?;
    let payload = cursor.array::<32>().ok_or(SetupStateError::Malformed)?;
    let tx_count = usize::from(u16::from_be_bytes(
        cursor.array::<2>().ok_or(SetupStateError::Malformed)?,
    ));
    let mut txs = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let len = usize::try_from(u32::from_be_bytes(
            cursor.array::<4>().ok_or(SetupStateError::Malformed)?,
        ))
        .map_err(|_| SetupStateError::Malformed)?;
        let bytes = cursor.take(len).ok_or(SetupStateError::Malformed)?;
        let (tx, consumed) = Tx::decode(bytes).map_err(|_| SetupStateError::Malformed)?;
        if consumed != len {
            return Err(SetupStateError::Malformed);
        }
        txs.push(tx);
    }
    Ok(SetupHistoryBlock {
        height,
        parent,
        payload,
        txs,
    })
}

pub(super) fn put_scan(out: &mut Vec<u8>, scan: &SetupScan) {
    put_u64(out, scan.height);
    out.extend_from_slice(&scan.payload);
}

pub(super) fn take_scan(cursor: &mut Cursor<'_>) -> Result<SetupScan, SetupStateError> {
    Ok(SetupScan {
        height: cursor.u64().ok_or(SetupStateError::Malformed)?,
        payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
    })
}

pub(super) const fn role_code(role: Role) -> u8 {
    match role {
        Role::Client => 1,
        Role::Provider => 2,
    }
}

pub(super) const fn role_from_code(code: u8) -> Result<Role, SetupStateError> {
    match code {
        1 => Ok(Role::Client),
        2 => Ok(Role::Provider),
        _ => Err(SetupStateError::Malformed),
    }
}

/// Whether a close descriptor is the one its setup bundle produces.
///
/// One spelling, asked when the descriptor is first armed beside its
/// revision and again when a checkpoint carrying the pair is opened. A
/// descriptor that described some other channel would be an endpoint
/// recovering a close for a channel it does not have.
pub(super) fn describes_bundle(
    bundle: &WorkChannelSetupBundleV1,
    close_descriptor: &CloseDescriptor,
) -> Result<(), SetupStateError> {
    let Some(payment_edge) = bundle.payment_edge() else {
        return Err(SetupStateError::DescriptorMismatch);
    };
    if close_descriptor.channel().network() != bundle.network()
        || close_descriptor.channel().payment_edge() != payment_edge
        || bundle.payment_terms() != Some(close_descriptor.channel().payment_terms())
        || close_descriptor.bond_edge() != bundle.bond_edge()
    {
        return Err(SetupStateError::DescriptorMismatch);
    }
    Ok(())
}

impl SetupState {
    /// Returns this state's canonical bytes: the whole of what a
    /// successor generation replays from.
    ///
    /// Not a summary, and the destructuring below is what keeps it from
    /// becoming one. Every field of this struct is named here and named
    /// again in [`Self::decode_checkpoint`]'s literal, so a field added
    /// to [`SetupState`] and forgotten here does not compile: the
    /// pattern is refused for the field it does not mention, and the
    /// literal for the field it cannot fill. A checkpoint that quietly
    /// dropped a field a duty reads would be replay that is wrong and
    /// says nothing, which is the one failure rotation must not add.
    ///
    /// The bundle is written as its exact retained bytes and read back
    /// by decoding them, rather than as two copies of one revision that
    /// could disagree. Everything the retained history decided is
    /// written *and* re-derived on the way in — see [`Self::revalidate`]
    /// — so the derived half of this encoding is checked rather than
    /// believed.
    #[must_use]
    pub fn checkpoint(&self) -> Vec<u8> {
        let Self {
            network,
            bond_edge,
            role,
            bundle,
            bundle_bytes,
            scan_armed,
            close_descriptor,
            unresolved_bond_open,
            unresolved_payment_open,
            history_cursor,
            history,
            bond_finalized,
            payment_finalized,
            bond_closed,
            payment_closed,
            bond_timeout_submitted,
            origin,
            end,
        } = self;

        let mut out = Vec::new();
        put_bytes(&mut out, network.as_str().as_bytes());
        out.extend_from_slice(&bond_edge.to_bytes());
        out.push(role_code(*role));
        // The value and its bytes are one field written once: the
        // presence byte is the decoded revision's, and the body is the
        // bytes it was decoded from.
        put_option(&mut out, bundle.as_ref(), |out, _| {
            put_bytes(out, bundle_bytes);
        });
        put_option(&mut out, scan_armed.as_ref(), put_scan);
        put_option(&mut out, close_descriptor.as_ref(), |out, descriptor| {
            put_bytes(out, &descriptor.encode());
        });
        out.push(u8::from(*unresolved_bond_open));
        out.push(u8::from(*unresolved_payment_open));
        put_option(&mut out, history_cursor.as_ref(), put_scan);
        out.extend_from_slice(&(history.len() as u32).to_be_bytes());
        for block in history {
            put_block(&mut out, block);
        }
        out.push(u8::from(*bond_finalized));
        out.push(u8::from(*payment_finalized));
        out.push(u8::from(*bond_closed));
        out.push(u8::from(*payment_closed));
        out.push(u8::from(*bond_timeout_submitted));
        put_option(&mut out, origin.as_ref(), |out, origin| {
            out.extend_from_slice(&origin.payment_edge.to_bytes());
            put_u64(out, origin.height);
            out.extend_from_slice(&origin.payload);
            out.extend_from_slice(&origin.parent);
        });
        put_option(&mut out, end.as_ref(), |out, end| {
            out.push(end_to_code(*end));
        });
        out
    }

    /// Reads a checkpoint back into the state it was written from.
    ///
    /// Decoding only. What makes those bytes a state this endpoint may
    /// hold is [`Self::revalidate`] and the signature check beside it,
    /// and [`SetupStore::open`] runs both — this is separate because
    /// discovery has a journal to name and no verifier to name it with.
    ///
    /// # Errors
    ///
    /// [`SetupStateError::Malformed`] for a truncated body, an unknown
    /// code, or a trailing byte, and
    /// [`SetupStateError::Bundle`]/[`SetupStateError::Descriptor`] when
    /// a nested body does not decode.
    pub(super) fn decode_checkpoint(bytes: &[u8]) -> Result<Self, SetupStateError> {
        let mut cursor = Cursor::new(bytes);
        let network = std::str::from_utf8(take_bytes(&mut cursor, SetupStateError::Malformed)?)
            .ok()
            .and_then(NetworkId::new)
            .ok_or(SetupStateError::Malformed)?;
        let bond_edge = EdgeId::from_bytes(cursor.array::<32>().ok_or(SetupStateError::Malformed)?);
        let role = role_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)?;
        let bundle_bytes = take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
            Ok(take_bytes(cursor, SetupStateError::Malformed)?.to_vec())
        })?;
        let bundle = bundle_bytes
            .as_deref()
            .map(WorkChannelSetupBundleV1::decode)
            .transpose()?;
        let scan_armed = take_option(&mut cursor, SetupStateError::Malformed, take_scan)?;
        let close_descriptor = take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
            Ok(CloseDescriptor::decode(take_bytes(
                cursor,
                SetupStateError::Malformed,
            )?)?)
        })?;
        let unresolved_bond_open = take_bool(&mut cursor, SetupStateError::Malformed)?;
        let unresolved_payment_open = take_bool(&mut cursor, SetupStateError::Malformed)?;
        let history_cursor = take_option(&mut cursor, SetupStateError::Malformed, take_scan)?;
        let block_count = usize::try_from(u32::from_be_bytes(
            cursor.array::<4>().ok_or(SetupStateError::Malformed)?,
        ))
        .map_err(|_| SetupStateError::Malformed)?;
        let mut history = Vec::new();
        for _ in 0..block_count {
            history.push(take_block(&mut cursor)?);
        }
        let state = Self {
            network,
            bond_edge,
            role,
            bundle,
            bundle_bytes: bundle_bytes.unwrap_or_default(),
            scan_armed,
            close_descriptor,
            unresolved_bond_open,
            unresolved_payment_open,
            history_cursor,
            history,
            bond_finalized: take_bool(&mut cursor, SetupStateError::Malformed)?,
            payment_finalized: take_bool(&mut cursor, SetupStateError::Malformed)?,
            bond_closed: take_bool(&mut cursor, SetupStateError::Malformed)?,
            payment_closed: take_bool(&mut cursor, SetupStateError::Malformed)?,
            bond_timeout_submitted: take_bool(&mut cursor, SetupStateError::Malformed)?,
            origin: take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
                Ok(SetupOrigin {
                    payment_edge: EdgeId::from_bytes(
                        cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                    ),
                    height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                    payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                    parent: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                })
            })?,
            end: take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
                end_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)
                    .ok_or(SetupStateError::Malformed)
            })?,
        };
        if cursor.is_empty() {
            Ok(state)
        } else {
            Err(SetupStateError::Malformed)
        }
    }
}
