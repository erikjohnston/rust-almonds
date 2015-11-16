#![feature(vec_push_all)]
#![feature(test)]

extern crate crypto;
extern crate rustc_serialize;
extern crate test;

mod almond;
mod verifier;

pub use almond::{Almond, ALMOND_HASH_SEED};
pub use verifier::Verifier;
