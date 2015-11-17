use crypto::mac::{Mac, MacResult};
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;
use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64, FromBase64};


/// The arbitrary 32 byte array used to seed the initial HMAC.
pub const ALMOND_HASH_SEED : &'static [u8; 32] = b"this_is_a_bit_of_arbitrary_data!";


/// A representation of a deserialized Almond.
///
/// Every Almond consists of:
///
/// - A `generation`, which is a simple version to allow upgrading the caveat
///   formats. This is an 8-bit unsigned integer.
/// - A `type`, which defines what this caveat is used for. For example,
///   general access vs. logging in a new client.
/// - A list of caveats that each *decrease* the level of authorization the
///   Almond allows
///
/// The type and caveats are serialized within the almond, so it is suggested
/// that they are not needlessly verbose.
///
/// A caveat is key (with optional value) that decreases the scope of the
/// Almond. An almond with no caveats grants full authorization to any and
/// all holders of the Almond. In practice, almost all almonds have at least
/// one caveat that scopes it to a particular user.
///
/// The exact format and interpretation of the caveats are application defined.
///
pub struct Almond {
    hash: [u8; 32],
    caveats: Vec<Vec<u8>>,
    generation: u8,
    almond_type: Vec<u8>,
}

impl Almond {
    /// Create a new Almond with given generation and type.
    pub fn create(key: &[u8], generation: u8, almond_type: Vec<u8>) -> Almond {
        let mut almond = Almond {
            hash: *ALMOND_HASH_SEED,
            caveats: Vec::new(),
            generation: generation,
            almond_type: almond_type,
        };

        add_to_hash(&mut almond.hash, key);
        add_to_hash(&mut almond.hash, &[generation]);
        add_to_hash(&mut almond.hash, &almond.almond_type);

        almond
    }

    /// Parse a binary serialized Almond, and validate that the hashes match.
    ///
    /// *Note: This expects a binary serialization rather than base64*
    pub fn parse_and_validate(key: &[u8], input: &[u8])
        -> Result<Almond, AlmondParseError>
    {
        if input.len() < 34 {
            return Err(AlmondParseError::InvalidAlmond);
        }

        let hash = &input[..32];
        let generation = input[32];

        let mut split_it = input[33..].split(|c| *c == b'\n');

        let almond_type = try!(
            split_it.next()
            .ok_or(AlmondParseError::InvalidAlmond)
        );

        let mut almond = Almond::create(key, generation, almond_type.to_vec());

        for caveat in split_it {
            almond.add_literal_caveat(caveat.to_vec());
        }

        // Always compare hashes using equality operators that are
        // resistent to timing attacks.
        if MacResult::new(hash) == MacResult::new(almond.hash()) {
            Ok(almond)
        } else {
            Err(AlmondParseError::IncorrectHash)
        }
    }

    /// Parse a Base64 serialized Almond, and validate that the hashes match.
    pub fn parse_base64_and_validate(key: &[u8], input: &[u8])
        -> Result<Almond, AlmondParseError>
    {
        let parsed = try!(
            input.from_base64()
            .or(Err(AlmondParseError::InvalidAlmond))
        );
        Almond::parse_and_validate(key, &parsed)
    }

    /// Add a new literal caveat.
    ///
    /// The interpretation of the caveat is either `<key>` or `<key> <value>`
    /// depending on if `caveat` has a space or not.
    pub fn add_literal_caveat(&mut self, caveat: Vec<u8>) -> &mut Self {
        add_to_hash(&mut self.hash, &caveat);
        self.caveats.push(caveat);
        self
    }

    /// Adds a caveat.
    ///
    /// The key must not include a space.
    pub fn add_caveat(&mut self, key: &[u8], value: Option<&[u8]>) -> &mut Self {
        let mut caveat = Vec::new();
        caveat.push_all(key);
        if let Some(val) = value {
            caveat.push(b' ');
            caveat.push_all(val);
        }
        add_to_hash(&mut self.hash, &caveat);
        self.caveats.push(caveat);
        self
    }

    /// Get the type of the Almond
    pub fn almond_type(&self) -> &[u8] {
        &self.almond_type
    }

    /// Get the generation of the Almond
    pub fn generation(&self) -> u8 {
        self.generation
    }

    /// Get the *current* caveats of the Almond
    pub fn caveats(&self) -> &[Vec<u8>] {
        &self.caveats
    }

    /// Get the *current* hash of the almond.
    ///
    /// # Safety
    /// Do not compare this directly with other hashes. Always use a specially
    /// designed constant time comparison function.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Serialize into a binary blob
    pub fn serialize_binary(&self) -> Vec<u8> {
        let mut result : Vec<u8> = Vec::new();

        result.push_all(&self.hash);
        result.push(self.generation);
        result.push_all(&self.almond_type);
        result.push(b'\n');

        for caveat in &self.caveats {
            result.push_all(&caveat);
            result.push(b'\n');
        }

        result.pop();

        result
    }

    /// Serialize into Base64.
    ///
    /// This is equivalent to Base64 encoding the binary serialization
    pub fn serialize_base64(&self) -> String {
        self.to_base64(base64::URL_SAFE)
    }
}

impl base64::ToBase64 for Almond {
    fn to_base64(&self, config: base64::Config) -> String {
        let serialized = self.serialize_binary();
        serialized.to_base64(config)
    }
}


fn add_to_hash(hash: &mut [u8], data: &[u8]) {
    let hasher = Sha256::new();
    let mut mac = Hmac::new(hasher, hash);
    mac.input(data);
    mac.raw_result(hash);
}


quick_error! {
    /// An error returned when we failed to parse a buffer as an almond.
    #[derive(Debug)]
    pub enum AlmondParseError {
        /// The buffer did not contain a valid almond. 
        InvalidAlmond {}

        /// The hash did not match the deserialized Almond.
        IncorrectHash {}
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};

    #[test]
    fn basic_test() {
        let key = b"this_is_a_secret";

        let mut almond = Almond::create(key, 1, b"login".to_vec());
        almond.add_caveat(b"user", Some(b"erikj"));
        let r = almond.to_base64(URL_SAFE);
        assert_eq!(
            r,
            "yyTNYc-CAXTVkgXkNnl8wdMzBTMgHyLRSlXrjdf5Uw0BbG9naW4KdXNlciBlcmlrag"
        );

        Almond::parse_and_validate(key, &almond.serialize_binary()).unwrap();
    }

    #[test]
    fn parse_and_serialize() {
        let key = b"this_is_a_secret";

        let input = "yyTNYc-CAXTVkgXkNnl8wdMzBTMgHyLRSlXrjdf5Uw0BbG9naW4KdXNlciBlcmlrag";
        let a = Almond::parse_and_validate(key, &input.from_base64().unwrap()).unwrap();

        assert_eq!(a.to_base64(URL_SAFE), input);
    }

    #[bench]
    fn create(b: &mut Bencher) {
        let key = b"this_is_a_secret";
        b.iter(|| {
            let mut almond = Almond::create(key, 1, b"login".to_vec());
            almond.add_caveat(b"user", Some(b"erikj"));
            almond.add_caveat(b"fooo", Some(b"bar"));
            almond.add_caveat(b"testing", None);
            almond.add_caveat(b"teeeeeeeeeeeest", None);
            almond
        });
    }

    #[bench]
    fn parse(b: &mut Bencher) {
        let key = b"this_is_a_secret";

        let b64 = concat!(
            "Rv31sT9t5d31LHPeBFjPewo0TJ1ARbDok7vOWBVNSM4BbG9naW4KdXN",
            "lciBlcmlragpmb29vIGJhcgp0ZXN0aW5nCnRlZWVlZWVlZWVlZWVzdA",
        );
        let parsed = b64.from_base64().unwrap();

        b.iter(|| {
            let almond = Almond::parse_and_validate(
                key,
                &parsed,
            );
            almond.unwrap();
        });
    }
}
