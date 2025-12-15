// secret_validators.rs - Surgical Secret Validation & False Positive Filtering
// Purpose: Advanced validation to reduce false positives in secret detection
// Features: Entropy analysis, context detection, placeholder filtering, confidence scoring

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CodeContext {
    Comment,         // Inside a comment
    StringLiteral,   // Real string literal
    TestCode,        // Test/spec code
    Example,         // Documentation/example
    RealCode,        // Production code
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    VeryHigh,   // 90-100% - Almost certain it's real
    High,       // 75-90%  - High confidence
    Medium,     // 50-75%  - Moderate confidence
    Low,        // 25-50%  // Low confidence
    VeryLow,    // 0-25%   - Likely false positive
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretConfidenceScore {
    pub total_score: f64,
    pub entropy_score: f64,
    pub context_score: f64,
    pub format_score: f64,
    pub placeholder_penalty: f64,
    pub validation_score: f64,
    pub confidence_level: ConfidenceLevel,
    pub reasons: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// ENTROPY CALCULATION (Shannon Entropy)
// ═══════════════════════════════════════════════════════════════════

/// Calculate Shannon entropy of a string
/// Higher entropy = more randomness = more likely to be a real secret
///
/// Examples:
/// - "aaaaaaaaaa" = 0.0 (no entropy)
/// - "example123" = 2.8 (low entropy)
/// - "xK9$mP2&vQ" = 4.2 (high entropy)
#[allow(dead_code)]
pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut frequencies = HashMap::new();
    let len = s.len() as f64;

    for byte in s.bytes() {
        *frequencies.entry(byte).or_insert(0) += 1;
    }

    frequencies.values()
        .map(|&count| {
            let p = count as f64 / len;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

/// Check if secret has high enough entropy to be real
#[allow(dead_code)]
pub fn is_high_entropy_secret(secret: &str, min_entropy: f64) -> bool {
    if secret.len() < 12 {
        return false;
    }

    let entropy = calculate_shannon_entropy(secret);
    entropy >= min_entropy
}

// ═══════════════════════════════════════════════════════════════════
// CONTEXT DETECTION
// ═══════════════════════════════════════════════════════════════════

/// Detect if a match is inside a comment
#[allow(dead_code)]
pub fn is_in_comment(content: &str, position: usize) -> bool {
    if position >= content.len() {
        return false;
    }

    let lines_before = &content[..position];
    let current_line_start = lines_before.rfind('\n').map(|p| p + 1).unwrap_or(0);
    let current_line = &content[current_line_start..position];

    // Single-line comments: //, #, *
    let trimmed = current_line.trim_start();
    if trimmed.starts_with("//") ||
       trimmed.starts_with('#') ||
       trimmed.starts_with('*') {
        return true;
    }

    // Multi-line comments: /* */
    let before = &content[..position];
    if let Some(last_open) = before.rfind("/*") {
        if let Some(last_close) = before.rfind("*/") {
            if last_open > last_close {
                return true; // Inside /* ... */
            }
        } else {
            return true; // /* opened but not closed
        }
    }

    // HTML comments: <!-- -->
    if let Some(last_open) = before.rfind("<!--") {
        if let Some(last_close) = before.rfind("-->") {
            if last_open > last_close {
                return true;
            }
        } else {
            return true;
        }
    }

    false
}

/// Detect if code is in a test file or test context
#[allow(dead_code)]
pub fn is_test_code(content: &str, position: usize) -> bool {
    let test_indicators = [
        "describe(", "it(", "test(", "expect(",
        "jest.mock", "sinon.stub", "chai.",
        "beforeEach", "afterEach", "beforeAll", "afterAll",
        "// Test", "// Example", "// Demo",
        "__tests__", ".test.js", ".spec.js",
        "mocha", "jasmine", "qunit", "vitest",
        "TestCase", "unittest", "pytest",
        "Mock", "Stub", "Spy", "Fake",
    ];

    // Check within 500 chars before position
    let start = position.saturating_sub(500);
    let end = (position + 100).min(content.len());
    let nearby_content = &content[start..end];

    test_indicators.iter().any(|indicator| {
        nearby_content.contains(indicator)
    })
}

/// Detect if content contains example/documentation indicators
#[allow(dead_code)]
pub fn has_example_indicators(content: &str, position: usize) -> bool {
    let example_indicators = [
        "example", "Example", "EXAMPLE",
        "sample", "Sample", "SAMPLE",
        "demo", "Demo", "DEMO",
        "placeholder", "Placeholder", "PLACEHOLDER",
        "TODO:", "FIXME:", "NOTE:", "HACK:",
        "Replace with", "Change this", "Insert your",
        "your-", "my-", "our-",
        "documentation", "README", "docs/",
        "<your", "<my", "{{", "}}", "${",
    ];

    // Check within 250 chars before and after
    let start = position.saturating_sub(250);
    let end = (position + 250).min(content.len());
    let nearby_content = &content[start..end];

    example_indicators.iter().any(|indicator| {
        nearby_content.contains(indicator)
    })
}

/// Analyze the context of a matched secret
#[allow(dead_code)]
pub fn analyze_context(content: &str, match_position: usize) -> CodeContext {
    // Priority 1: Check if in comment
    if is_in_comment(content, match_position) {
        return CodeContext::Comment;
    }

    // Priority 2: Check if test code
    if is_test_code(content, match_position) {
        return CodeContext::TestCode;
    }

    // Priority 3: Check if example/documentation
    if has_example_indicators(content, match_position) {
        return CodeContext::Example;
    }

    // Default: Assume real code
    CodeContext::RealCode
}

// ═══════════════════════════════════════════════════════════════════
// PLACEHOLDER DETECTION
// ═══════════════════════════════════════════════════════════════════

/// Check if value is a placeholder/example
#[allow(dead_code)]
pub fn is_placeholder(value: &str) -> bool {
    let placeholders = [
        "example", "test", "demo", "sample", "placeholder",
        "your-", "my-", "our-", "todo", "change-me", "replace",
        "xxx", "yyy", "zzz", "aaa", "bbb",
        "secret-here", "insert-", "add-your", "put-your",
        "12345", "abcde", "qwerty",
        "<change", "<replace", "<insert",
    ];

    let lower = value.to_lowercase();

    // 1. Check obvious placeholder words
    if placeholders.iter().any(|p| lower.contains(p)) {
        return true;
    }

    // 2. Check repetitive patterns
    if has_repetitive_pattern(value) {
        return true;
    }

    // 3. Check for template syntax
    if lower.contains("{{") || lower.contains("${") || lower.contains("<%") {
        return true;
    }

    // 4. Check for instructional text
    if lower.contains("insert") || lower.contains("replace") || lower.contains("change") {
        return true;
    }

    false
}

/// Detect repetitive patterns in string
#[allow(dead_code)]
fn has_repetitive_pattern(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }

    // Check single character repetition (aaaa, 1111, etc.)
    let first_char = s.chars().next().unwrap();
    let same_char_count = s.chars().filter(|&c| c == first_char).count();
    if same_char_count > s.len() * 2 / 3 {
        return true; // More than 66% same character
    }

    // Check substring repetition (abcabc, 123123, etc.)
    for chunk_size in 2..=(s.len() / 2) {
        if s.len().is_multiple_of(chunk_size) {
            let chunk = &s[..chunk_size];
            let repeated = chunk.repeat(s.len() / chunk_size);
            if repeated == s {
                return true;
            }
        }
    }

    false
}

// ═══════════════════════════════════════════════════════════════════
// FORMAT VALIDATION
// ═══════════════════════════════════════════════════════════════════

/// Check if secret matches a known format
#[allow(dead_code)]
pub fn has_known_format(secret: &str, secret_type: &str) -> bool {
    match secret_type {
        "GITHUB_PAT_NEW" => {
            secret.starts_with("github_pat_") && secret.len() == 93
        },
        "STRIPE_SECRET_KEY" => {
            secret.starts_with("sk_live_") && secret.len() >= 32
        },
        "STRIPE_PUBLIC_KEY" => {
            secret.starts_with("pk_live_") && secret.len() >= 32
        },
        "VERCEL_TOKEN" => {
            (secret.starts_with("vcel_") || secret.starts_with("vc_")) && secret.len() >= 36
        },
        "AWS_ACCESS_KEY" => {
            secret.len() == 20 && secret.chars().all(|c| c.is_ascii_alphanumeric())
        },
        "AWS_SECRET_KEY" => {
            secret.len() == 40 && secret.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        },
        "PRIVATE_KEY" => {
            secret.contains("BEGIN") && secret.contains("PRIVATE KEY")
        },
        "TWILIO_API_KEY" => {
            secret.starts_with("SK") && secret.len() == 34
        },
        _ => false,
    }
}

/// Check if string is UUID format
#[allow(dead_code)]
pub fn is_uuid_format(s: &str) -> bool {
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    if s.len() != 36 {
        return false;
    }

    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }

    if parts[0].len() != 8 || parts[1].len() != 4 || parts[2].len() != 4 ||
       parts[3].len() != 4 || parts[4].len() != 12 {
        return false;
    }

    parts.iter().all(|part| {
        part.chars().all(|c| c.is_ascii_hexdigit())
    })
}

// ═══════════════════════════════════════════════════════════════════
// CONFIDENCE SCORING SYSTEM
// ═══════════════════════════════════════════════════════════════════

/// Calculate comprehensive confidence score for a secret
#[allow(dead_code)]
pub fn score_secret(
    secret: &str,
    secret_type: &str,
    content: &str,
    match_position: usize,
    validated: bool,
) -> SecretConfidenceScore {
    let mut total_score: f64 = 0.0;
    let mut reasons = Vec::new();

    // 1. ENTROPY SCORE (30 points)
    let entropy = calculate_shannon_entropy(secret);
    let entropy_score = if entropy >= 4.5 {
        reasons.push(format!("Very high entropy ({:.2})", entropy));
        30.0
    } else if entropy >= 4.0 {
        reasons.push(format!("High entropy ({:.2})", entropy));
        25.0
    } else if entropy >= 3.5 {
        reasons.push(format!("Moderate entropy ({:.2})", entropy));
        18.0
    } else if entropy >= 3.0 {
        reasons.push(format!("Low entropy ({:.2})", entropy));
        10.0
    } else {
        reasons.push(format!("Very low entropy ({:.2})", entropy));
        0.0
    };
    total_score += entropy_score;

    // 2. CONTEXT SCORE (30 points)
    let code_context = analyze_context(content, match_position);
    let context_score = match code_context {
        CodeContext::Comment => {
            reasons.push("Found in comment".to_string());
            0.0
        },
        CodeContext::TestCode => {
            reasons.push("Found in test code".to_string());
            8.0
        },
        CodeContext::Example => {
            reasons.push("Found in example/documentation".to_string());
            0.0
        },
        CodeContext::RealCode => {
            reasons.push("Found in production code".to_string());
            30.0
        },
        _ => 15.0,
    };
    total_score += context_score;

    // 3. FORMAT SCORE (20 points)
    let format_score = if has_known_format(secret, secret_type) {
        reasons.push(format!("Matches {} format", secret_type));
        20.0
    } else if is_uuid_format(secret) {
        reasons.push("UUID format".to_string());
        15.0
    } else if secret.len() >= 32 {
        reasons.push("Long key (≥32 chars)".to_string());
        10.0
    } else {
        reasons.push("Generic format".to_string());
        5.0
    };
    total_score += format_score;

    // 4. PLACEHOLDER PENALTY (-40 points)
    let placeholder_penalty = if is_placeholder(secret) {
        reasons.push("⚠ Placeholder/example detected".to_string());
        -40.0
    } else {
        0.0
    };
    total_score += placeholder_penalty;

    // 5. VALIDATION SCORE (20 points)
    let validation_score = if validated {
        reasons.push("✓ Token validated successfully".to_string());
        20.0
    } else {
        0.0
    };
    total_score += validation_score;

    // Calculate final confidence level
    let final_score = total_score.clamp(0.0, 100.0);
    let confidence_level = match final_score {
        s if s >= 85.0 => ConfidenceLevel::VeryHigh,
        s if s >= 70.0 => ConfidenceLevel::High,
        s if s >= 50.0 => ConfidenceLevel::Medium,
        s if s >= 30.0 => ConfidenceLevel::Low,
        _ => ConfidenceLevel::VeryLow,
    };

    SecretConfidenceScore {
        total_score: final_score,
        entropy_score,
        context_score,
        format_score,
        placeholder_penalty,
        validation_score,
        confidence_level,
        reasons,
    }
}

/// Filter secrets by minimum confidence level
#[allow(dead_code)]
pub fn filter_by_confidence(
    secrets: Vec<(String, String, SecretConfidenceScore)>,
    min_level: ConfidenceLevel,
) -> Vec<(String, String, SecretConfidenceScore)> {
    let min_score = match min_level {
        ConfidenceLevel::VeryHigh => 85.0,
        ConfidenceLevel::High => 70.0,
        ConfidenceLevel::Medium => 50.0,
        ConfidenceLevel::Low => 30.0,
        ConfidenceLevel::VeryLow => 0.0,
    };

    secrets.into_iter()
        .filter(|(_, _, score)| score.total_score >= min_score)
        .collect()
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        // Low entropy
        assert!(calculate_shannon_entropy("aaaaaaaaaa") < 1.0);
        assert!(calculate_shannon_entropy("123456789") < 3.0);

        // Medium entropy
        assert!(calculate_shannon_entropy("example123") > 2.5);
        assert!(calculate_shannon_entropy("example123") < 3.5);

        // High entropy
        assert!(calculate_shannon_entropy("xK9$mP2&vQ5#rT8") > 4.0);
    }

    #[test]
    fn test_is_in_comment() {
        let content = r#"
            var x = "real";
            // const secret = "fake";
            var y = "real2";
        "#;

        // Should detect comment
        let comment_pos = content.find("fake").unwrap();
        assert!(is_in_comment(content, comment_pos));

        // Should not detect real code
        let real_pos = content.find("real2").unwrap();
        assert!(!is_in_comment(content, real_pos));
    }

    #[test]
    fn test_is_placeholder() {
        // Should detect placeholders
        assert!(is_placeholder("example-secret-123"));
        assert!(is_placeholder("your-api-key-here"));
        assert!(is_placeholder("TODO-change-me"));
        assert!(is_placeholder("xxxxxxxxxx"));
        assert!(is_placeholder("123456789"));

        // Should NOT detect real secrets
        assert!(!is_placeholder("xK9$mP2&vQ5#rT8*nL3"));
        assert!(!is_placeholder("sk_live_51HxG..."));
    }

    #[test]
    fn test_has_known_format() {
        assert!(has_known_format("github_pat_11ABCDEFGHIJKLMNOPQRST_123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQR", "GITHUB_PAT_NEW"));
        assert!(has_known_format("sk_live_51HxGTY2Z3a4b5c6d7e8f9", "STRIPE_SECRET_KEY"));
        assert!(has_known_format("vcel_abcdefgh12345678901234567890", "VERCEL_TOKEN"));
    }

    #[test]
    fn test_score_secret() {
        let content = r#"const API_KEY = "sk_live_51HxGTY2Z3a4b5c6d7e8f9";"#;
        let position = content.find("sk_live").unwrap();

        let score = score_secret(
            "sk_live_51HxGTY2Z3a4b5c6d7e8f9",
            "STRIPE_SECRET_KEY",
            content,
            position,
            false,
        );

        // Should have high confidence (known format + real code + high entropy)
        assert!(score.total_score >= 70.0);
        assert_eq!(score.confidence_level, ConfidenceLevel::High);
    }

    #[test]
    fn test_score_secret_example() {
        let content = r#"// Example: const API_KEY = "example-key-123456";"#;
        let position = content.find("example").unwrap();

        let score = score_secret(
            "example-key-123456",
            "API_KEY",
            content,
            position,
            false,
        );

        // Should have very low confidence (comment + placeholder + low entropy)
        assert!(score.total_score < 30.0);
        assert_eq!(score.confidence_level, ConfidenceLevel::VeryLow);
    }
}
