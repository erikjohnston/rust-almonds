
use Almond;


struct DeconstructedCaveatEntry<'a> {
    pub key: &'a [u8],
    pub value: Option<&'a [u8]>,
    pub accepted: Option<bool>,
}

pub struct Verifier<'a> {
    caveats: Vec<DeconstructedCaveatEntry<'a>>,
    reject: bool,
}

impl <'a> Verifier<'a> {
    pub fn new(almond: &'a Almond, generation: u8, almond_type: &[u8]) -> Verifier<'a> {
        let caveats = almond.caveats().iter()
            .map(
                |caveat| {
                    let mut it = caveat.splitn(2, |c| *c == b' ');

                    // By definition this must have at least one item
                    let key = it.next().expect("`split` returned zero results.");
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
            reject: almond.generation() != generation || almond.almond_type() != almond_type
        }
    }

    pub fn allow(&mut self, key: &[u8]) -> &mut Self {
        for item in &mut self.caveats {
            if item.key == key {
                item.accepted = item.accepted.or(Some(true));
            }
        }

        self
    }

    pub fn satisfies<F>(&mut self, key: &[u8], mut predicate: F) -> &mut Self
        where F: FnMut(Option<&[u8]>) -> bool
    {
        for item in &mut self.caveats {
            if item.key == key {
                let res = predicate(item.value);
                item.accepted = Some(res && item.accepted.unwrap_or(true));
            }
        }

        self
    }

    pub fn satisfies_exact(&mut self, key: &[u8], value: Option<&[u8]>) {
        for item in &mut self.caveats {
            if item.key == key {
                let res = item.value.map(|x| &*x) == value;
                item.accepted = Some(res && item.accepted.unwrap_or(true));
            }
        }
    }

    pub fn verify(&self) -> bool {
        !self.reject && self.caveats.iter().all(|item| item.accepted.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::Verifier;
    use Almond;

    #[test]
    fn verify_test() {
        let key = b"this_is_a_secret";
        let mut almond = Almond::create(key, 1, b"login".to_vec());
        almond.add_caveat(b"user erikj".to_vec());
        almond.add_caveat(b"guest".to_vec());

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
        almond.add_caveat(b"user erikj".to_vec());

        let mut v = Verifier::new(&almond, 2, b"login");
        v.allow(b"user");
        assert!(!v.verify());

        let mut v = Verifier::new(&almond, 1, b"notlogin");
        v.allow(b"user");
        assert!(!v.verify());
    }
}
