//! Deterministic checksums, stable 64-bit hashing, and fast LLM token counting.

/// Computes a hardware-accelerated CRC32 checksum over `data`.
#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Computes a platform-independent, deterministic 64-bit hash for `(kind, key)`.
///
/// Uses FNV-1a seeding followed by a SplitMix64 avalanche finalizer so the
/// on-disk hash is guaranteed stable across Rust compiler versions and CPUs.
#[inline]
pub fn hash_key(kind: u8, key: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut h = FNV_OFFSET ^ (kind as u64);
    h = h.wrapping_mul(FNV_PRIME);
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }

    // SplitMix64 avalanche finalizer for uniform bit distribution.
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Deterministically counts approximate BPE/subword tokens for LLM context budgeting.
///
/// Unlike naive `len / 4` heuristics, this scanner accounts for:
/// - Identifier boundaries (`camelCase`, `snake_case`, numeric runs),
/// - Individual punctuation/operator tokens in source code and JSON,
/// - Long words split into ~4-character subword pieces,
/// - UTF-8 multibyte continuation bytes without double-counting codepoints.
pub fn count_tokens_exact(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 0;
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Class {
        Whitespace,
        AlphaLower,
        AlphaUpper,
        Digit,
        Other,
    }

    let mut tokens: u32 = 0;
    let mut prev = Class::Whitespace;
    let mut run_len: u32 = 0;

    for &b in bytes {
        // Skip UTF-8 continuation bytes (10xxxxxx) so multi-byte characters count as one char.
        if (b & 0b1100_0000) == 0b1000_0000 {
            continue;
        }

        let cls = if b.is_ascii_whitespace() {
            Class::Whitespace
        } else if b.is_ascii_lowercase() || b >= 0xC0 {
            Class::AlphaLower
        } else if b.is_ascii_uppercase() {
            Class::AlphaUpper
        } else if b.is_ascii_digit() {
            Class::Digit
        } else {
            Class::Other
        };

        match cls {
            Class::Whitespace => {
                prev = Class::Whitespace;
                run_len = 0;
            }
            Class::Other => {
                // Pairwise operators (`->`, `::`, `==`, `()`) merge up to 2 symbols per BPE token.
                if prev != Class::Other || run_len >= 2 {
                    tokens = tokens.saturating_add(1);
                    run_len = 1;
                } else {
                    run_len += 1;
                }
                prev = Class::Other;
            }
            Class::AlphaUpper => {
                let starts_new = prev != Class::AlphaUpper;
                if starts_new {
                    tokens = tokens.saturating_add(1);
                    run_len = 1;
                } else {
                    run_len += 1;
                    if run_len > 7 {
                        tokens = tokens.saturating_add(1);
                        run_len = 1;
                    }
                }
                prev = Class::AlphaUpper;
            }
            Class::AlphaLower => {
                // Transition from AlphaUpper -> AlphaLower continues the same capitalized word!
                let continues_word = prev == Class::AlphaLower || prev == Class::AlphaUpper;
                if !continues_word {
                    tokens = tokens.saturating_add(1);
                    run_len = 1;
                } else {
                    run_len += 1;
                    if run_len > 7 {
                        tokens = tokens.saturating_add(1);
                        run_len = 1;
                    }
                }
                prev = Class::AlphaLower;
            }
            Class::Digit => {
                if prev != Class::Digit {
                    tokens = tokens.saturating_add(1);
                    run_len = 1;
                } else {
                    run_len += 1;
                    if run_len > 3 {
                        tokens = tokens.saturating_add(1);
                        run_len = 1;
                    }
                }
                prev = Class::Digit;
            }
        }
    }

    tokens.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_key_hash_stability() {
        let h1 = hash_key(1, b"global-formatting");
        let h2 = hash_key(1, b"global-formatting");
        let h3 = hash_key(2, b"global-formatting");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn token_counter_handles_code_and_umlauts() {
        assert_eq!(count_tokens_exact(b""), 0);
        let code = b"fn execute_with_retry(conn: &Connection) -> Result<()>";
        let c = count_tokens_exact(code);
        assert!((10..=20).contains(&c), "unexpected token count: {c}");

        // UTF-8 multi-byte sequence via ASCII hex escapes to keep source strictly 7-bit ASCII.
        let multibyte = b"\xC3\x9Cbersetzung f\xC3\xBCr Langzeitged\xC3\xA4chtnis";
        let g = count_tokens_exact(multibyte);
        assert!((4..=10).contains(&g), "unexpected multibyte token count: {g}");
    }
}
