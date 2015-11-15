#![feature(vec_push_all)]
#![feature(test)]

extern crate crypto;
extern crate rustc_serialize;
extern crate test;

use crypto::mac::{Mac, MacResult};
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use rustc_serialize::base64;


pub const ALMOND_HASH_SEED : &'static [u8; 32] = b"this_is_a_bit_of_arbitrary_data!";


pub struct Almond {
    hash: [u8; 32],
    caveats: Vec<Vec<u8>>,
    generation: u8,
    almond_type: Vec<u8>,
}

impl Almond {
    pub fn create(key: &[u8], generation: u8, almond_type: Vec<u8>) -> Almond {
        let mut almond = Almond {
            hash: *ALMOND_HASH_SEED,
            caveats: Vec::new(),
            generation: generation,
            almond_type: almond_type,
        };

        add_to_hash(&mut almond.hash, key);
        add_to_hash(&mut almond.hash, &[generation]);
        add_to_hash(&mut almond.hash, &almond.almond_type[..]);

        almond
    }

    pub fn parse_and_verify(key: &[u8], input: &[u8]) -> Result<Almond, &'static str> {
        if input.len() < 34 {
            return Err("Too small");
        }

        let hash = &input[..32];
        let generation = input[32];

        let mut split_it = input[33..].split(|c| *c == b'\n');

        let almond_type = try!(split_it.next().ok_or("No initial newline"));

        let mut almond = Almond::create(key, generation, almond_type.to_vec());

        for caveat in split_it {
            almond.add_caveat(caveat.to_vec());
        }

        // Always compare hashes using equality operators that are
        // resistent to timing attacks.
        if MacResult::new(hash) == MacResult::new(almond.hash()) {
            Ok(almond)
        } else {
            Err("Hash do not match")
        }
    }

    pub fn add_caveat(&mut self, caveat: Vec<u8>) -> &mut Self {
        add_to_hash(&mut self.hash, &caveat[..]);
        self.caveats.push(caveat);
        self
    }

    pub fn almond_type(&self) -> &[u8] {
        &self.almond_type[..]
    }

    pub fn generation(&self) -> u8 {
        self.generation
    }

    pub fn caveats(&self) -> &[Vec<u8>] {
        &self.caveats[..]
    }

    // pub fn caveat_map(&self) -> HashMap<&[u8], Option<&[u8]>> {
    //     let mut map = HashMap::with_capacity(self.caveats.len());
    //
    //     for caveat in &self.caveats() {
    //         let mut it = caveat.splitn(2, |c| *c == b' ');
    //
    //         // By definition this must have at least one item
    //         let key = it.next().unwrap();
    //         let value = it.next();
    //
    //         map.insert(key, value);
    //     }
    //
    //     map
    // }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result : Vec<u8> = Vec::new();

        result.push_all(&self.hash);
        result.push(self.generation);
        result.push_all(&self.almond_type);
        result.push(b'\n');

        for caveat in &self.caveats {
            result.push_all(&caveat[..]);
            result.push(b'\n');
        }

        result.pop();

        result
    }
}

impl base64::ToBase64 for Almond {
    fn to_base64(&self, config: base64::Config) -> String {
        let serialized = self.serialize();
        serialized[..].to_base64(config)
    }
}


fn add_to_hash(hash: &mut [u8], data: &[u8]) {
    let hasher = Sha256::new();
    let mut mac = Hmac::new(hasher, hash);
    mac.input(data);
    mac.raw_result(hash);
}



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
                    let key = it.next().unwrap();
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
    use super::*;
    use test::Bencher;

    #[test]
    fn basic_test() {
        use rustc_serialize::base64::{ToBase64, URL_SAFE};

        let key = b"this_is_a_secret";

        let mut almond = Almond::create(key, 1, b"login".to_vec());
        almond.add_caveat(b"user erikj".to_vec());
        let r = almond.to_base64(URL_SAFE);
        assert_eq!(
            r,
            concat!(
                "yyTNYc-CAXTVkgXkNnl8wdMzBTMgHyLRS",
                "lXrjdf5Uw0BbG9naW4KdXNlciBlcmlrag",
            )
        );

        Almond::parse_and_verify(key, &almond.serialize()[..]).unwrap();
    }


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

    #[bench]
    fn create(b: &mut Bencher) {
        let key = b"this_is_a_secret";
        b.iter(|| {
            let mut almond = Almond::create(key, 1, b"login".to_vec());
            almond.add_caveat(b"user erikj".to_vec());
            almond.add_caveat(b"fooo bar".to_vec());
            almond.add_caveat(b"testing".to_vec());
            almond.add_caveat(b"teeeeeeeeeeeest".to_vec());
            almond
        });
    }
}
