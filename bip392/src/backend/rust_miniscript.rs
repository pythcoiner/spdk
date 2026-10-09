//! [`Backend`] over rust-miniscript, shared by every supported release.

use core::{fmt, str::FromStr};

use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};

use crate::{
    Error,
    backend::Backend,
    miniscript::{
        bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource},
        descriptor::{
            DescriptorPublicKey, DescriptorSecretKey, SinglePubKey, Wildcard, checksum::Engine,
        },
    },
};

pub enum Miniscript {}

impl Backend for Miniscript {
    type DescriptorSecretKey = DescriptorSecretKey;
    type DescriptorPublicKey = DescriptorPublicKey;
    type KeySource = KeySource;

    fn derive_secret_key<C: Signing>(
        secp: &Secp256k1<C>,
        key: &DescriptorSecretKey,
    ) -> Result<SecretKey, Error> {
        let secret = match key {
            DescriptorSecretKey::MultiXPrv(_) => {
                return Err(Error::Unexpected(
                    "sp() spend key must not be multipath".to_string(),
                ));
            }
            DescriptorSecretKey::XPrv(xprv) => {
                if xprv.wildcard != Wildcard::None {
                    return Err(Error::Unexpected(
                        "sp() spend key must not contain a wildcard".to_string(),
                    ));
                }
                xprv.xkey
                    .derive_priv(secp, &xprv.derivation_path)
                    .map(|derived| derived.private_key)
                    .map_err(|e| Error::Unexpected(format!("sp() spend key: {e}")))?
            }
            DescriptorSecretKey::Single(s) if !s.key.compressed => {
                return Err(Error::Unexpected(
                    "sp() spend key must be compressed".to_string(),
                ));
            }
            DescriptorSecretKey::Single(s) => s.key.inner,
        };
        Ok(secret)
    }

    fn derive_public_key<C: Verification>(
        secp: &Secp256k1<C>,
        key: &DescriptorPublicKey,
    ) -> Result<PublicKey, Error> {
        match key {
            DescriptorPublicKey::MultiXPub(_) => Err(Error::Unexpected(
                "sp() spend key must not be multipath".to_string(),
            )),
            DescriptorPublicKey::XPub(xpub) => {
                if xpub.wildcard != Wildcard::None {
                    return Err(Error::Unexpected(
                        "sp() spend key must not contain a wildcard".to_string(),
                    ));
                }
                if xpub
                    .derivation_path
                    .as_ref()
                    .iter()
                    .any(ChildNumber::is_hardened)
                {
                    return Err(Error::Unexpected(
                        "sp() public spend key cannot use a hardened derivation step".to_string(),
                    ));
                }
                xpub.xkey
                    .derive_pub(secp, &xpub.derivation_path)
                    .map(|derived| derived.public_key)
                    .map_err(|e| Error::Unexpected(format!("sp() spend key: {e}")))
            }
            DescriptorPublicKey::Single(s) => match s.key {
                SinglePubKey::FullKey(full) if !full.compressed => Err(Error::Unexpected(
                    "sp() spend key must be compressed".to_string(),
                )),
                SinglePubKey::FullKey(full) => Ok(full.inner),
                SinglePubKey::XOnly(_) => Err(Error::Unexpected(
                    "sp() spend key must be compressed".to_string(),
                )),
            },
        }
    }

    fn is_mainnet(key: &DescriptorSecretKey) -> bool {
        match key {
            DescriptorSecretKey::Single(sk) => sk.key.network.is_mainnet(),
            DescriptorSecretKey::XPrv(xprv) => xprv.xkey.network.is_mainnet(),
            DescriptorSecretKey::MultiXPrv(xprv) => xprv.xkey.network.is_mainnet(),
        }
    }

    fn parse_key_origin(s: &str) -> Result<KeySource, Error> {
        let mut parts = s.split('/');
        let fingerprint_hex = parts.next().unwrap_or("");
        if fingerprint_hex.len() != 8 {
            return Err(Error::Unexpected(format!(
                "sp() key origin fingerprint must be 8 hex chars, got '{fingerprint_hex}'"
            )));
        }
        let fingerprint = Fingerprint::from_hex(fingerprint_hex)
            .map_err(|e| Error::Unexpected(format!("sp() key origin fingerprint: {e}")))?;
        let children = parts
            .map(ChildNumber::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Unexpected(format!("sp() key origin path: {e}")))?;
        Ok((fingerprint, DerivationPath::from(children)))
    }

    fn write_key_origin(f: &mut impl fmt::Write, origin: &KeySource) -> fmt::Result {
        f.write_str("[")?;
        for byte in origin.0.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        for child in &origin.1 {
            write!(f, "/{child:#}")?;
        }
        f.write_str("]")
    }

    fn checksum(desc: &str) -> Result<String, Error> {
        let mut engine = Engine::new();
        engine
            .input(desc)
            .map_err(|e| Error::Checksum(e.to_string()))?;
        Ok(engine.checksum())
    }
}
