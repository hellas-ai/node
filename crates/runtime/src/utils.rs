use crate::{LLMError, Result, types};
use catgrad::prelude::Dtype;
use catgrad_llm::PreparedPrompt as UpstreamPreparedPrompt;
use catgrad_llm::utils::RenderChatTemplateOptions as UpstreamRenderChatTemplateOptions;
use minijinja::Value;
use serde_json::{Map as JsonMap, Value as JsonValue};
use tokenizers::tokenizer::Tokenizer;

pub use catgrad_llm::utils::*;

pub fn get_model(
    config_json: &serde_json::Value,
    max_sequence_length: usize,
    runtime_context: Option<&catgrad_llm_models::utils::ModelRuntimeContext>,
    dtype: Dtype,
) -> Result<Box<dyn catgrad_llm::helpers::LLMModel>> {
    catgrad_llm_models::utils::get_model(config_json, max_sequence_length, runtime_context, dtype)
        .map_err(LLMError::from)
}

pub fn get_model_architecture(config_json: &serde_json::Value) -> Result<&str> {
    catgrad_llm_models::utils::get_model_architecture(config_json).map_err(LLMError::from)
}

pub fn prepared_prompt_from_messages_with_tools(
    tokenizer: &Tokenizer,
    chat_template: &str,
    tokenizer_config: &JsonValue,
    messages: &[types::Message],
    stop_token_ids: &[i32],
    thinking: types::ThinkingPolicy,
    tools: Option<&JsonValue>,
) -> Result<UpstreamPreparedPrompt> {
    let messages: Vec<_> = messages
        .iter()
        .map(message_to_template_context)
        .collect::<Result<_>>()?;
    let tool_values = tools.map(tool_values_from_json);
    let prompt = catgrad_llm::utils::render_chat_template_values(
        chat_template,
        tokenizer_config,
        &messages,
        UpstreamRenderChatTemplateOptions {
            thinking,
            tools: tool_values.as_deref(),
        },
    )?;
    UpstreamPreparedPrompt::from_prompt(tokenizer, &prompt, stop_token_ids).map_err(LLMError::from)
}

fn tool_values_from_json(tools: &JsonValue) -> Vec<Value> {
    match tools {
        JsonValue::Array(items) => items.iter().map(Value::from_serialize).collect(),
        value => vec![Value::from_serialize(value)],
    }
}

fn message_to_template_context(message: &types::Message) -> Result<Value> {
    let mut map = JsonMap::new();

    match message {
        types::Message::OpenAI(msg) => {
            let content_blocks = match msg.content.as_ref() {
                Some(content) => openai_content_to_template_blocks(content),
                None => Vec::new(),
            };
            map.insert("role".to_string(), JsonValue::String(msg.role.clone()));
            map.insert(
                "content".to_string(),
                match msg.content.as_ref() {
                    Some(_) if openai_blocks_include_image(&content_blocks) => {
                        JsonValue::Array(content_blocks.clone())
                    }
                    Some(content) => JsonValue::String(openai_content_to_template_string(content)?),
                    None => JsonValue::String(String::new()),
                },
            );
            map.insert(
                "content_blocks".to_string(),
                JsonValue::Array(content_blocks),
            );
            if let Some(tool_calls) = msg
                .tool_calls
                .as_ref()
                .filter(|tool_calls| !tool_calls.is_empty())
            {
                map.insert(
                    "tool_calls".to_string(),
                    JsonValue::Array(tool_calls.iter().map(normalize_openai_tool_call).collect()),
                );
            }
            if let Some(tool_call_id) = &msg.tool_call_id {
                map.insert(
                    "tool_call_id".to_string(),
                    JsonValue::String(tool_call_id.clone()),
                );
            }
            if let Some(name) = &msg.name {
                map.insert("name".to_string(), JsonValue::String(name.clone()));
            }
        }
        types::Message::Anthropic(msg) => {
            map.insert("role".to_string(), JsonValue::String(msg.role.clone()));
            map.insert(
                "content".to_string(),
                JsonValue::String(anthropic_content_to_template_string(&msg.content)?),
            );
            map.insert(
                "content_blocks".to_string(),
                serde_json::to_value(anthropic_content_to_template_blocks(&msg.content))?,
            );
        }
    }

    Ok(Value::from_serialize(map))
}

fn openai_content_to_template_string(content: &types::openai::MessageContent) -> Result<String> {
    match content {
        types::openai::MessageContent::Text(text) => Ok(text.clone()),
        types::openai::MessageContent::Parts(parts) => {
            let mut out = String::new();
            for part in parts {
                match part {
                    types::openai::ContentPart::Text { text } => out.push_str(text),
                    types::openai::ContentPart::ImageUrl { .. } => {}
                }
            }
            Ok(out)
        }
    }
}

fn openai_content_to_template_blocks(content: &types::openai::MessageContent) -> Vec<JsonValue> {
    match content {
        types::openai::MessageContent::Text(text) => {
            vec![JsonValue::Object(JsonMap::from_iter([
                ("type".to_string(), JsonValue::String("text".to_string())),
                ("text".to_string(), JsonValue::String(text.clone())),
            ]))]
        }
        types::openai::MessageContent::Parts(parts) => parts
            .iter()
            .map(|part| match part {
                types::openai::ContentPart::Text { text } => {
                    JsonValue::Object(JsonMap::from_iter([
                        ("type".to_string(), JsonValue::String("text".to_string())),
                        ("text".to_string(), JsonValue::String(text.clone())),
                    ]))
                }
                types::openai::ContentPart::ImageUrl { image_url } => {
                    JsonValue::Object(JsonMap::from_iter([
                        ("type".to_string(), JsonValue::String("image".to_string())),
                        (
                            "image_url".to_string(),
                            serde_json::to_value(image_url).unwrap_or(JsonValue::Null),
                        ),
                    ]))
                }
            })
            .collect(),
    }
}

fn openai_blocks_include_image(blocks: &[JsonValue]) -> bool {
    blocks.iter().any(|block| {
        block
            .get("type")
            .and_then(JsonValue::as_str)
            .is_some_and(|ty| ty == "image")
    })
}

fn anthropic_content_to_template_string(
    content: &types::anthropic::MessageContent,
) -> Result<String> {
    let blocks = match content {
        types::anthropic::MessageContent::Text(text) => return Ok(text.clone()),
        types::anthropic::MessageContent::Blocks(blocks) => blocks,
    };
    let mut out = String::new();
    for block in blocks {
        match block {
            types::anthropic::ContentBlock::Text { text } => out.push_str(text),
        }
    }
    Ok(out)
}

fn anthropic_content_to_template_blocks(
    content: &types::anthropic::MessageContent,
) -> Vec<JsonValue> {
    let blocks = match content {
        types::anthropic::MessageContent::Text(text) => {
            return vec![JsonValue::Object(JsonMap::from_iter([
                ("type".to_string(), JsonValue::String("text".to_string())),
                ("text".to_string(), JsonValue::String(text.clone())),
            ]))];
        }
        types::anthropic::MessageContent::Blocks(blocks) => blocks,
    };
    blocks
        .iter()
        .map(|block| match block {
            types::anthropic::ContentBlock::Text { text } => {
                Some(JsonValue::Object(JsonMap::from_iter([
                    ("type".to_string(), JsonValue::String("text".to_string())),
                    ("text".to_string(), JsonValue::String(text.clone())),
                ])))
            }
        })
        .flatten()
        .collect()
}

fn normalize_openai_tool_call(tool_call: &JsonValue) -> JsonValue {
    let Some(mut tool_call) = tool_call.as_object().cloned() else {
        return tool_call.clone();
    };
    let Some(function) = tool_call
        .get_mut("function")
        .and_then(JsonValue::as_object_mut)
    else {
        return JsonValue::Object(tool_call);
    };
    let Some(arguments) = function.get_mut("arguments") else {
        return JsonValue::Object(tool_call);
    };
    let Some(encoded_arguments) = arguments.as_str() else {
        return JsonValue::Object(tool_call);
    };
    let Ok(decoded_arguments) = serde_json::from_str::<JsonValue>(encoded_arguments) else {
        return JsonValue::Object(tool_call);
    };
    if decoded_arguments.is_object() {
        *arguments = decoded_arguments;
    }
    JsonValue::Object(tool_call)
}
