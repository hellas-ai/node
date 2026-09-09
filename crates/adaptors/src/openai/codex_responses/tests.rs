use super::*;
use crate::{CodexToolSearchArguments, CodexUsage, CodexUsageMetadata};
use serde_json::Number;

#[test]
fn renderer_preserves_encrypted_reasoning_and_fractional_rollout_units() {
    let reasoning = render_codex_event(CodexResponsesEvent::OutputItemDone(
        CodexResponseItem::Reasoning {
            id: Some("rs_1".to_string()),
            summary: Vec::new(),
            content: None,
            encrypted_content: Some("cipher".to_string()),
        },
    ))
    .unwrap();
    assert_eq!(
        match reasoning.data {
            crate::WireEventData::Json(value) => {
                assert!(value["item"].get("status").is_none());
                assert!(value["item"].get("content").is_none());
                value["item"]["encrypted_content"].clone()
            }
            _ => unreachable!(),
        },
        "cipher"
    );

    let message = render_codex_event(CodexResponsesEvent::OutputItemDone(
        CodexResponseItem::Message {
            id: None,
            content: vec![CodexMessageContent::OutputText {
                text: "hello".to_string(),
            }],
            phase: None,
        },
    ))
    .unwrap();
    let crate::WireEventData::Json(message) = message.data else {
        unreachable!()
    };
    assert!(message["item"].get("id").is_none());
    assert!(message["item"].get("status").is_none());
    assert!(message["item"].get("phase").is_none());

    let completed = render_codex_event(CodexResponsesEvent::Completed(CodexCompleted {
        response_id: "resp_1".to_string(),
        server_model: Some("gpt-5.5-codex".to_string()),
        usage: CodexUsage {
            input_tokens: 2,
            input_tokens_details: None,
            output_tokens: 1,
            output_tokens_details: None,
            total_tokens: 3,
            codex_rollout_budget_units: Number::from_f64(2.5),
        },
        usage_metadata: Some(CodexUsageMetadata {
            amount: Some("0.1".to_string()),
        }),
        end_turn: Some(false),
    }))
    .unwrap();
    assert_eq!(
        match completed.data {
            crate::WireEventData::Json(value) => {
                value["response"]["usage"]["codex_rollout_budget_units"].clone()
            }
            _ => unreachable!(),
        },
        json!(2.5)
    );
}

#[test]
fn renderer_goldens_sparse_message_and_tool_search_items() {
    let message = render_codex_event(CodexResponsesEvent::OutputItemDone(
        CodexResponseItem::Message {
            id: None,
            content: vec![CodexMessageContent::OutputText {
                text: "hello".to_string(),
            }],
            phase: None,
        },
    ))
    .unwrap();
    assert_eq!(
        message,
        WireStreamEvent::json(
            Some("response.output_item.done".to_string()),
            json!({
                "type":"response.output_item.done",
                "item":{
                    "type":"message",
                    "role":"assistant",
                    "content":[{"type":"output_text","text":"hello"}]
                }
            }),
        )
    );

    let search = render_codex_event(CodexResponsesEvent::OutputItemDone(
        CodexResponseItem::ToolSearchCall {
            id: Some("ts_1".to_string()),
            call_id: "search_1".to_string(),
            status: Some(CodexItemStatus::Completed),
            arguments: CodexToolSearchArguments {
                query: "calendar create".to_string(),
                limit: Some(1),
            },
        },
    ))
    .unwrap();
    assert_eq!(
        search,
        WireStreamEvent::json(
            Some("response.output_item.done".to_string()),
            json!({
                "type":"response.output_item.done",
                "item":{
                    "type":"tool_search_call",
                    "id":"ts_1",
                    "call_id":"search_1",
                    "status":"completed",
                    "execution":"client",
                    "arguments":{"query":"calendar create","limit":1}
                }
            }),
        )
    );
}

#[test]
fn renderer_rejects_events_after_terminal_error() {
    let adaptor = CodexResponsesAdaptor;
    let request = ParsedCodexRequest {
        model: "gpt-5.5-codex".to_string(),
        input: Vec::new(),
    };
    let mut state = CodexStreamState::default();
    adaptor
        .render_stream_event(
            &request,
            &mut state,
            OutputEvent::Error {
                message: "failed".to_string(),
                code: None,
            },
        )
        .unwrap();
    assert!(
        adaptor
            .render_stream_event(
                &request,
                &mut state,
                OutputEvent::Error {
                    message: "late".to_string(),
                    code: None,
                },
            )
            .is_err()
    );
}
