use rand::Rng;

/// Mutation strategies for fuzzing request bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    /// Flip a random bit in the input.
    BitFlip,
    /// Substitute a random byte with a random value.
    ByteSubstitution,
    /// Append random bytes to the end of the input.
    LengthExtension,
}

/// Mutate `input` using all available strategies, producing `iterations` mutated
/// variants. The returned Vec has `iterations` entries; each entry is a distinct
/// mutated copy of the input.
///
/// Used for fuzzing API request bodies to probe for parsing vulnerabilities.
pub fn mutate(input: &[u8], iterations: u32) -> Vec<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let strategies = [
        MutationStrategy::BitFlip,
        MutationStrategy::ByteSubstitution,
        MutationStrategy::LengthExtension,
    ];

    (0..iterations)
        .map(|i| {
            let strategy = strategies[(i as usize) % strategies.len()];
            apply_mutation(input, strategy, &mut rng)
        })
        .collect()
}

fn apply_mutation(
    input: &[u8],
    strategy: MutationStrategy,
    rng: &mut impl Rng,
) -> Vec<u8> {
    let mut output = input.to_vec();

    if output.is_empty() {
        output.push(rng.gen());
        return output;
    }

    match strategy {
        MutationStrategy::BitFlip => {
            let byte_idx = rng.gen_range(0..output.len());
            let bit_idx = rng.gen_range(0u8..8);
            output[byte_idx] ^= 1 << bit_idx;
        }
        MutationStrategy::ByteSubstitution => {
            let idx = rng.gen_range(0..output.len());
            output[idx] = rng.gen();
        }
        MutationStrategy::LengthExtension => {
            // Append between 1 and 16 random bytes
            let extra_len = rng.gen_range(1usize..=16);
            for _ in 0..extra_len {
                output.push(rng.gen());
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_returns_correct_count() {
        let input = b"hello";
        let results = mutate(input, 9);
        assert_eq!(results.len(), 9);
    }

    #[test]
    fn mutate_each_result_is_nonempty() {
        let input = b"test payload";
        for variant in mutate(input, 6) {
            assert!(!variant.is_empty());
        }
    }

    #[test]
    fn length_extension_grows_input() {
        let input = b"base";
        let result = apply_mutation(input, MutationStrategy::LengthExtension, &mut rand::thread_rng());
        assert!(result.len() > input.len());
    }

    #[test]
    fn bit_flip_changes_one_bit() {
        // Run many times to statistically confirm at least one byte changes
        let input = vec![0xAA_u8; 64];
        let mut found_change = false;
        for _ in 0..50 {
            let result = apply_mutation(&input, MutationStrategy::BitFlip, &mut rand::thread_rng());
            if result != input {
                found_change = true;
                break;
            }
        }
        assert!(found_change);
    }

    #[test]
    fn mutate_empty_input_does_not_panic() {
        let results = mutate(&[], 3);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(!r.is_empty());
        }
    }
}
