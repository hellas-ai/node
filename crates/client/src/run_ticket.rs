use hellas_rpc::ProducerSigningKey;
use hellas_rpc::pb::execute::{PublicKey, RunTicketRequest, Ticket};

use crate::{ClientError, ClientResult};

pub fn signed_run_ticket_request(
    ticket: Ticket,
    key: &ProducerSigningKey,
) -> ClientResult<RunTicketRequest> {
    hellas_rpc::run_ticket::sign_run_ticket(ticket, key)
        .map_err(|source| ClientError::source("failed to sign run ticket", source))
}

pub fn runner_public_key(key: &ProducerSigningKey) -> PublicKey {
    hellas_rpc::run_ticket::public_key_to_pb(&key.public_key())
}
