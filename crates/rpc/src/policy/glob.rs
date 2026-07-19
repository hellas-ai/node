/// Simple glob match supporting `*` as a wildcard for any sequence of characters.
pub(super) fn matches(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut pos = 0;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        match text[pos..].find(part) {
            Some(found) => {
                if index == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    if parts.last().is_some_and(|last| !last.is_empty()) {
        return pos == text.len();
    }

    true
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn exact_match() {
        assert!(matches("exact", "exact"));
        assert!(!matches("exact", "exactX"));
        assert!(!matches("exact", "Xexact"));
    }

    #[test]
    fn trailing_star() {
        assert!(matches("Qwen3/*", "Qwen3/Qwen3-0.6B"));
        assert!(matches("Qwen3/*", "Qwen3/anything"));
        assert!(!matches("Qwen3/*", "meta-llama/Llama-3"));
    }

    #[test]
    fn leading_star() {
        assert!(matches("*-Instruct", "SmolLM2-135M-Instruct"));
        assert!(!matches("*-Instruct", "SmolLM2-135M"));
    }

    #[test]
    fn middle_star() {
        assert!(matches("meta-llama/Llama*8B", "meta-llama/Llama-3.1-8B"));
        assert!(!matches("meta-llama/Llama*8B", "meta-llama/Llama-3.1-70B"));
    }

    #[test]
    fn star_matches_all() {
        assert!(matches("*", "anything/at-all"));
        assert!(matches("*", ""));
    }

    #[test]
    fn multiple_stars() {
        assert!(matches("*llama*8B", "meta-llama/Llama-3.1-8B"));
        assert!(!matches("*llama*70B", "meta-llama/Llama-3.1-8B"));
    }
}
