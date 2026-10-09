//! The bitcoin API the crate is written against. Each backend implements
//! [`Backend`] over one bitcoin/miniscript release, so the `sp()` parsing and
//! encoding never name a concrete key expression type.

use core::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};

use crate::Error;

pub trait Backend {
    /// A private key expression (WIF or xprv, with origin and derivation).
    type DescriptorSecretKey: Clone + Eq + Debug + Display + FromStr<Err: Display>;
    /// A public key expression (hex pubkey or xpub, with origin and derivation).
    type DescriptorPublicKey: Clone + Eq + Debug + Display + FromStr<Err: Display>;
    /// Master fingerprint and derivation path of a key.
    type KeySource: Clone + Eq + Debug;

    /// Secret key of the expression. Rejects multipath, wildcard and uncompressed keys.
    fn derive_secret_key<C: Signing>(
        secp: &Secp256k1<C>,
        key: &Self::DescriptorSecretKey,
    ) -> Result<SecretKey, Error>;
    /// Public key of the expression. Rejects multipath, wildcard, hardened
    /// steps, uncompressed and x-only keys.
    fn derive_public_key<C: Verification>(
        secp: &Secp256k1<C>,
        key: &Self::DescriptorPublicKey,
    ) -> Result<PublicKey, Error>;
    /// True when the expression is a mainnet WIF or xprv.
    fn is_mainnet(key: &Self::DescriptorSecretKey) -> bool;
    /// Parse a key origin without its brackets: `fingerprint/path`.
    fn parse_key_origin(s: &str) -> Result<Self::KeySource, Error>;
    /// Write a key origin with its brackets: `[fingerprint/path]`.
    fn write_key_origin(f: &mut impl fmt::Write, origin: &Self::KeySource) -> fmt::Result;
    /// BIP-380 checksum of a descriptor string.
    fn checksum(desc: &str) -> Result<String, Error>;
}
