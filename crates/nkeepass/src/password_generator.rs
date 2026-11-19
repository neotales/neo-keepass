//! Entry-password policy. Composition is an application choice, not a NIST mandate.
use crate::service::ServiceError;
use zeroize::Zeroizing;

const CLASSES: [&[u8]; 4] = [
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    b"abcdefghijklmnopqrstuvwxyz",
    b"0123456789",
    b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
];

/// Selected character classes; no selection means all four classes.
#[derive(Clone, Copy, Debug, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent selectable character classes"
)]
pub struct Policy {
    /// Include uppercase ASCII letters.
    pub upper: bool,
    /// Include lowercase ASCII letters.
    pub lower: bool,
    /// Include ASCII digits.
    pub digits: bool,
    /// Include printable ASCII punctuation.
    pub symbols: bool,
}

impl Policy {
    /// Whether any class was explicitly selected.
    #[must_use]
    pub fn selected(self) -> bool {
        self.upper || self.lower || self.digits || self.symbols
    }

    fn classes(self) -> Vec<&'static [u8]> {
        let flags = [self.upper, self.lower, self.digits, self.symbols];
        CLASSES
            .into_iter()
            .zip(flags)
            .filter_map(|(class, selected)| (selected || !self.selected()).then_some(class))
            .collect()
    }

    /// Refuse impossible lengths before any randomness or mutation.
    ///
    /// # Errors
    /// Returns [`ServiceError::InvalidSize`] outside the supported range or
    /// when there are more required classes than characters.
    pub fn validate(self, size: usize) -> Result<(), ServiceError> {
        if size < self.classes().len() || size > 4096 {
            Err(ServiceError::InvalidSize)
        } else {
            Ok(())
        }
    }

    /// Generate uniformly from strings satisfying the selected composition.
    ///
    /// Rejection sampling both bytes and complete candidates avoids modulo and
    /// forced-placement bias. With at most four disjoint classes and size >=
    /// class count, candidate rejection has a bounded expected cost.
    ///
    /// # Errors
    /// Returns [`ServiceError::InvalidSize`] for an impossible policy and
    /// [`ServiceError::RandomGeneration`] if OS randomness is unavailable.
    pub fn generate(self, size: usize) -> Result<Zeroizing<String>, ServiceError> {
        self.validate(size)?;
        let classes = self.classes();
        let alphabet = classes.concat();
        let limit = 256 - 256 % alphabet.len();
        loop {
            let mut candidate = Zeroizing::new(String::with_capacity(size));
            let mut found = vec![false; classes.len()];
            while candidate.len() < size {
                let mut random = Zeroizing::new([0_u8; 128]);
                getrandom::fill(&mut *random).map_err(|_| ServiceError::RandomGeneration)?;
                for byte in random.iter().copied() {
                    if usize::from(byte) >= limit {
                        continue;
                    }
                    let character = alphabet[usize::from(byte) % alphabet.len()];
                    candidate.push(char::from(character));
                    for (index, class) in classes.iter().enumerate() {
                        found[index] |= class.contains(&character);
                    }
                    if candidate.len() == size {
                        break;
                    }
                }
            }
            if found.iter().all(|found| *found) {
                return Ok(candidate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_selection_has_only_selected_classes_and_guarantees_each() {
        for mask in 0..16 {
            let policy = Policy {
                upper: mask & 1 != 0,
                lower: mask & 2 != 0,
                digits: mask & 4 != 0,
                symbols: mask & 8 != 0,
            };
            let classes = policy.classes();
            for size in [classes.len(), 16, 128] {
                for _ in 0..12 {
                    let value = policy.generate(size).unwrap();
                    assert_eq!(value.len(), size);
                    assert!(
                        classes
                            .iter()
                            .all(|class| value.bytes().any(|byte| class.contains(&byte)))
                    );
                    assert!(
                        value
                            .bytes()
                            .all(|byte| classes.iter().any(|class| class.contains(&byte)))
                    );
                }
            }
            assert!(policy.generate(classes.len() - 1).is_err());
            assert!(policy.generate(4097).is_err());
        }
    }
}
