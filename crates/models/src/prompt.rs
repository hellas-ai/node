use chrono::Local;
use minijinja::{Environment, Error, ErrorKind, State, Value, context};
use minijinja_contrib::pycompat::unknown_method_callback;
use serde_json::{Map, Value as JsonValue};
use tokenizers::Tokenizer;

#[derive(Clone, Debug, PartialEq)]
pub struct ChatMessage {
    pub role: String,
    pub content: Option<String>,
    pub tool_calls: Vec<JsonValue>,
    pub tool_call_id: Option<String>,
    pub name: Option<String>,
}

impl ChatMessage {
    pub fn text(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: Some(content.into()),
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::text("system", content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::text("user", content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::text("assistant", content)
    }

    fn template_value(&self) -> Value {
        let mut message = Map::from_iter([
            ("role".to_string(), JsonValue::String(self.role.clone())),
            (
                "content".to_string(),
                JsonValue::String(self.content.clone().unwrap_or_default()),
            ),
            (
                "content_blocks".to_string(),
                self.content.as_ref().map_or_else(
                    || JsonValue::Array(Vec::new()),
                    |text| {
                        JsonValue::Array(vec![JsonValue::Object(Map::from_iter([
                            ("type".to_string(), JsonValue::String("text".to_string())),
                            ("text".to_string(), JsonValue::String(text.clone())),
                        ]))])
                    },
                ),
            ),
        ]);
        if !self.tool_calls.is_empty() {
            message.insert(
                "tool_calls".to_string(),
                JsonValue::Array(self.tool_calls.iter().map(normalize_tool_call).collect()),
            );
        }
        if let Some(tool_call_id) = &self.tool_call_id {
            message.insert(
                "tool_call_id".to_string(),
                JsonValue::String(tool_call_id.clone()),
            );
        }
        if let Some(name) = &self.name {
            message.insert("name".to_string(), JsonValue::String(name.clone()));
        }
        Value::from_serialize(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPrompt {
    pub input_ids: Vec<u32>,
    pub stop_token_ids: Vec<u32>,
}

impl PreparedPrompt {
    pub fn from_prompt(
        tokenizer: &Tokenizer,
        prompt: &str,
        stop_token_ids: &[u32],
    ) -> tokenizers::Result<Self> {
        let encoding = tokenizer.encode(prompt, true)?;
        Ok(Self {
            input_ids: encoding.get_ids().to_vec(),
            stop_token_ids: stop_token_ids.to_vec(),
        })
    }
}

pub(super) fn render_chat_prompt(
    chat_template: &str,
    tokenizer_config: &JsonValue,
    messages: &[ChatMessage],
    tools: Option<&[JsonValue]>,
    enable_thinking: bool,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.set_unknown_method_callback(template_unknown_method_callback);
    env.add_function("strftime_now", |format: String| {
        Local::now().format(&format).to_string()
    });
    env.add_template("chat", chat_template)?;
    let template = env.get_template("chat")?;
    let messages: Vec<_> = messages.iter().map(ChatMessage::template_value).collect();
    let bos_token = tokenizer_config
        .get("bos_token")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    template.render(context!(
        messages => Value::from_serialize(messages),
        tools => tools
            .map(Value::from_serialize)
            .unwrap_or(Value::UNDEFINED),
        add_generation_prompt => true,
        enable_thinking => enable_thinking,
        bos_token => bos_token
    ))
}

fn template_unknown_method_callback(
    state: &State,
    value: &Value,
    method: &str,
    args: &[Value],
) -> Result<Value, Error> {
    if method == "get"
        && let Some(object) = value.as_object()
    {
        return match args {
            [key] => Ok(object.get_value(key).unwrap_or_else(|| Value::from(()))),
            [key, default] => Ok(object.get_value(key).unwrap_or_else(|| default.clone())),
            [] => Err(Error::from(ErrorKind::MissingArgument)),
            _ => Err(Error::from(ErrorKind::TooManyArguments)),
        };
    }
    unknown_method_callback(state, value, method, args)
}

fn normalize_tool_call(tool_call: &JsonValue) -> JsonValue {
    let Some(mut tool_call) = tool_call.as_object().cloned() else {
        return tool_call.clone();
    };
    let Some(arguments) = tool_call
        .get_mut("function")
        .and_then(JsonValue::as_object_mut)
        .and_then(|function| function.get_mut("arguments"))
    else {
        return JsonValue::Object(tool_call);
    };
    if let Some(encoded) = arguments.as_str()
        && let Ok(decoded @ JsonValue::Object(_)) = serde_json::from_str(encoded)
    {
        *arguments = decoded;
    }
    JsonValue::Object(tool_call)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenizers::models::wordlevel::WordLevel;

    #[test]
    fn renders_only_the_template_shape_hellas_supports() {
        let messages = [
            ChatMessage::user("hello"),
            ChatMessage {
                role: "assistant".to_string(),
                content: None,
                tool_calls: vec![serde_json::json!({
                    "type": "function",
                    "function": { "name": "lookup", "arguments": "{\"x\":1}" }
                })],
                tool_call_id: None,
                name: None,
            },
        ];
        let tools = [serde_json::json!({
            "type": "function",
            "function": { "name": "lookup" }
        })];
        let rendered = render_chat_prompt(
            "{{ messages[0].get('role') }}|{{ messages[0].content_blocks[0].text }}|{{ messages[1].tool_calls[0].function.arguments.x }}|{{ tools[0].function.name }}|{{ enable_thinking }}",
            &serde_json::json!({ "bos_token": "<s>" }),
            &messages,
            Some(&tools),
            true,
        )
        .unwrap();
        assert_eq!(rendered, "user|hello|1|lookup|true");
    }

    #[test]
    fn prepared_prompt_keeps_wire_native_token_ids() {
        let model = WordLevel::builder()
            .vocab(
                [("[UNK]".to_string(), 0), ("hello".to_string(), 7)]
                    .into_iter()
                    .collect(),
            )
            .unk_token("[UNK]".to_string())
            .build()
            .unwrap();
        let prepared = PreparedPrompt::from_prompt(&Tokenizer::new(model), "hello", &[9]).unwrap();
        assert_eq!(prepared.input_ids, [7]);
        assert_eq!(prepared.stop_token_ids, [9]);
    }
}
