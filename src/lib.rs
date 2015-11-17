//! Almond is an implementation of the same concepts as Macaroons, but with
//! much smaller binary serializations.
//!
//! The primary use for Almond is to generate authorization tokens that can be
//! verified without storing any state.
//!
//! (Almond currently does not support Macaroons' style third party caveats.)
//!
//! # Examples
//!
//! Creating an Almond:
//!
//! ```
//! use almond::Almond;
//!
//! let secret_key = b"this_is_a_secret";
//! let generation = 1;
//! let almond_type =  b"login".to_vec();
//!
//! let mut almond = Almond::create(secret_key, generation, almond_type);
//! almond.add_caveat(b"user", Some(b"erikj"));
//! assert_eq!(
//!     almond.serialize_base64(),
//!     "yyTNYc-CAXTVkgXkNnl8wdMzBTMgHyLRSlXrjdf5Uw0BbG9naW4KdXNlciBlcmlrag"
//! );
//! ```
//!
//! Validating an Almond:
//!
//! ```
//! use almond::*;
//!
//! let secret_key = b"this_is_a_secret";
//! let expected_generation = 1;
//! let expected_almond_type =  b"login";
//!
//! let encoded_almond = b"yyTNYc-CAXTVkgXkNnl8wdMzBTMgHyLRSlXrjdf5Uw0BbG9naW4KdXNlciBlcmlrag";
//!
//! let almond = Almond::parse_base64_and_validate(
//!     secret_key, encoded_almond
//! ).unwrap();
//!
//! let mut v = Verifier::new(&almond, expected_generation, expected_almond_type);
//! v.satisfies_exact(b"user", Some(b"erikj"));
//! assert!(v.verify());
//! ```


#![feature(vec_push_all)]
#![feature(test)]

extern crate crypto;
extern crate rustc_serialize;
extern crate test;
#[macro_use] extern crate quick_error;

mod almond;
mod verifier;

pub use almond::{Almond, ALMOND_HASH_SEED, AlmondParseError};
pub use verifier::Verifier;
