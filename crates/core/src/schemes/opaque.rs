use serde::{Deserialize, Serialize};

use crate::{Commitment, CommitmentScheme, DagCborEncoder, JsonBytes, SchemeId, tags};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueRequest {
    pub service: String,
    pub method: String,
    pub payload: JsonBytes,
}

pub struct Opaque;

impl CommitmentScheme for Opaque {
    type Request = OpaqueRequest;
    type Output = JsonBytes;

    const SCHEME: SchemeId = SchemeId::Opaque;

    fn commit_request(request: &Self::Request) -> Commitment {
        Commitment::from_canonical_bytes(&Self::request_bytes(request))
    }

    fn commit_output(output: &Self::Output) -> Commitment {
        Commitment::from_canonical_bytes(&Self::output_bytes(output))
    }
}

impl Opaque {
    pub fn request_bytes(request: &OpaqueRequest) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(4);
        encoder.str(tags::OPAQUE_REQUEST_V1);
        encoder.str(&request.service);
        encoder.str(&request.method);
        encoder.bytes(request.payload.as_bytes());
        encoder.into_bytes()
    }

    pub fn output_bytes(output: &JsonBytes) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(2);
        encoder.str(tags::OPAQUE_RESULT_V1);
        encoder.bytes(output.as_bytes());
        encoder.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_json_bytes_commit_exactly() {
        let a = JsonBytes::new(br#"{"temp":0.7}"#.to_vec());
        let b = JsonBytes::new(br#"{"temp": 0.7}"#.to_vec());
        assert_ne!(Opaque::commit_output(&a), Opaque::commit_output(&b));
    }

    #[test]
    fn opaque_request_schema_separates_identical_payload_from_output() {
        let payload = JsonBytes::new(br#"{"x":1}"#.to_vec());
        let request = OpaqueRequest {
            service: "svc".to_string(),
            method: "run".to_string(),
            payload: payload.clone(),
        };

        assert_ne!(
            Opaque::commit_request(&request),
            Opaque::commit_output(&payload)
        );
    }
}
