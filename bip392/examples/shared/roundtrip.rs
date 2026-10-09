//! A downstream crate building an `sp()` descriptor from key expressions made
//! with its own `miniscript` dependency: it only compiles when bip392's
//! backend is that same release.

use std::str::FromStr;

use bip392::{DescriptorSpendKey, Sp};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorSecretKey};

const SCAN_KEY: &str = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
const SPEND_KEY: &str = "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";

fn main() {
    let scan = DescriptorSecretKey::from_str(SCAN_KEY).expect("valid scan key");
    let spend = DescriptorPublicKey::from_str(SPEND_KEY).expect("valid spend key");
    let descriptor =
        Sp::from_keys(scan, DescriptorSpendKey::Public(spend)).expect("valid sp() descriptor");

    let restored = Sp::from_str(&descriptor.to_string()).expect("parse sp() descriptor");
    assert_eq!(restored, descriptor);
}
