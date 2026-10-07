//! TPAP client protocol core for Tapo power strips.

pub mod auth;
pub mod client;
pub mod credentials;
pub mod error;
#[cfg(test)]
mod mock;
pub mod server;
pub mod session;
pub mod spake;
pub mod strip;
