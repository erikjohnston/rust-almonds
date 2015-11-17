use Almond;


struct DeconstructedCaveatEntry<'a> {
    pub key: &'a [u8],
    pub value: Option<&'a [u8]>,
    pub accepted: Option<bool>,
}


/// The verifier takes an almond and checks if it satisfies a list of
/// predicates.
///
/// An almond will be accepted if:
///
/// - All caveats match and pass at least one predicate.
/// - No caveats are rejected by any predicate.
///
/// In particular, an almond will be rejected if it has any "unrecognized"
/// caveats, i.e. ones that do not match any predicates. On the other hand,
/// not all predicates must have matched a caveat.
pub struct Verifier<'a> {
    caveats: Vec<DeconstructedCaveatEntry<'a>>,
    reject: bool,
}

impl <'a> Verifier<'a> {
    /// Create a new instance to verify the given caveat.
    pub fn new(almond: &'a Almond, generation: u8, almond_type: &[u8])
        -> Verifier<'a>
    {
        let caveats = almond.caveats().iter()
            .map(
                |caveat| {
                    let mut it = caveat.splitn(2, |c| *c == b' ');

                    // By definition this must have at least one item
                    let key = it.next().expect(
                        "`split` returned zero results."
                    );
                    let value = it.next();

                    DeconstructedCaveatEntry {
                        key: key,
                        value: value,
                        accepted: None,
                    }
                }
            )
            .collect();

        Verifier {
            caveats: caveats,
            reject:
                almond.generation() != generation
                || almond.almond_type() != almond_type
        }
    }

    /// Allow all caveats with the given key, irrespective of their values.
    ///
    /// This should generally only be used if the value will be pulled out of
    /// the almond for usage.
    ///
    /// *Note: If you are expecting a key with no value then use
    /// `satisfies_exact` with `value` set to `None`*
    ///
    /// ```
    /// # use almond::{Almond, Verifier};
    /// let mut almond = Almond::create(b"secret", 1, b"access".to_vec());
    /// almond.add_caveat(b"user", Some(b"erikj"));
    ///
    /// let mut v = Verifier::new(&almond, 1, b"access");
    /// v.allow(b"user");
    /// assert!(v.verify());
    /// ```
    pub fn allow(&mut self, key: &[u8]) -> &mut Self {
        for item in &mut self.caveats {
            if item.key == key {
                item.accepted = item.accepted.or(Some(true));
            }
        }

        self
    }

    /// Invokes `predicate` against the value of every caveat with the given
    /// key. If `predicate` returns `true` then the caveat is accepted,
    /// `false` rejects the caveat.
    ///
    /// Rejects the caveat if the key matches but has no value.
    ///
    /// ```
    /// # use std::str;
    /// # use almond::{Almond, Verifier};
    /// let mut almond = Almond::create(b"secret", 1, b"access".to_vec());
    /// almond.add_caveat(b"expires", Some(b"1500000000"));
    ///
    /// let mut v = Verifier::new(&almond, 1, b"access");
    /// v.satisfies(
    ///    b"expires",
    ///    |val| {
    ///         str::from_utf8(val).ok().and_then(
    ///             |val| val.parse().ok()
    ///         ).map(
    ///             |val| 1447720058 < val   // Where `1447720058` is 'now'
    ///         ).unwrap_or(false)
    ///     }
    /// );
    /// assert!(v.verify());
    /// ```
    pub fn satisfies<F>(&mut self, key: &[u8], mut predicate: F) -> &mut Self
        where F: FnMut(&[u8]) -> bool
    {
        for item in &mut self.caveats {
            if item.key == key {
                item.accepted = if let Some(val) = item.value {
                    let res = predicate(val);
                    Some(res && item.accepted.unwrap_or(true))
                } else {
                    None
                };
            }
        }

        self
    }

    /// Compares `value` with the value of every caveat with the given key.
    /// If they match then the caveat is accpeted, otherwise it is rejected.
    ///
    /// ```
    /// # use almond::{Almond, Verifier};
    /// let mut almond = Almond::create(b"secret", 1, b"access".to_vec());
    /// almond.add_caveat(b"user", Some(b"erikj"));
    ///
    /// let mut v = Verifier::new(&almond, 1, b"access");
    /// v.satisfies_exact(b"user", Some(b"erikj"));
    /// assert!(v.verify());
    /// ```
    pub fn satisfies_exact(&mut self, key: &[u8], value: Option<&[u8]>) {
        for item in &mut self.caveats {
            if item.key == key {
                let res = item.value.map(|x| &*x) == value;
                item.accepted = Some(res && item.accepted.unwrap_or(true));
            }
        }
    }

    /// Returns whether the almond satisfies the given conditions and whether
    /// all caveats have been accepted by at least one condition.
    ///
    /// Always returns false if the almond does not have match specified
    /// `almond_type` and `generation`.
    pub fn verify(&self) -> bool {
        !self.reject && self.caveats.iter().all(
            |item| item.accepted.unwrap_or(false)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Verifier;
    use Almond;

    use std::str;

    #[test]
    fn verify_test() {
        let key = b"this_is_a_secret";
        let mut almond = Almond::create(key, 1, b"login".to_vec());
        almond.add_caveat(b"user", Some(b"erikj"));
        almond.add_caveat(b"guest", None);

        let mut v = Verifier::new(&almond, 1, b"login");
        v.allow(b"user");
        assert!(!v.verify());

        v.satisfies_exact(b"guest", None);
        assert!(v.verify());

        v.satisfies_exact(b"user", Some(b"noterikj"));
        assert!(!v.verify());
    }

    #[test]
    fn verify_test_gen_type() {
        let key = b"this_is_a_secret";
        let mut almond = Almond::create(key, 1, b"login".to_vec());
        almond.add_caveat(b"user", Some(b"erikj"));

        let mut v = Verifier::new(&almond, 2, b"login");
        v.allow(b"user");
        assert!(!v.verify());

        let mut v = Verifier::new(&almond, 1, b"notlogin");
        v.allow(b"user");
        assert!(!v.verify());
    }

    #[test]
    fn expires() {
        let mut almond = Almond::create(b"secret", 1, b"access".to_vec());
        almond.add_caveat(b"expires", Some(b"1500000000"));

        let now = 1447720058;  // Pretend this came from the clock.

        let mut v = Verifier::new(&almond, 1, b"access");
        v.satisfies(
            b"expires",
            |val| str::from_utf8(val).ok().and_then(
                    |val| val.parse().ok()
                ).map(
                    |val| now < val
                ).unwrap_or(false)
        );
        assert!(v.verify());
    }
}
