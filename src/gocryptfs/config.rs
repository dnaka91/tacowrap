use std::{collections::BTreeSet, path::Path};

use anyhow::Result;
use serde::Deserialize;

/// Name of the config file, located in the root of an encrypted directory.
pub const CONFIG_NAME: &str = "gocryptfs.conf";

/// Load the configuration from an encrypted directory.
pub fn load(base_dir: &Path) -> Result<Config> {
    let cfg = std::fs::read(base_dir.join(CONFIG_NAME))?;
    let cfg = serde_json::from_slice(&cfg)?;

    Ok(cfg)
}

/// Configuration of a single encrypted directory (located at the root).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub creator: String,
    /// AES encrypted master key that can be unlocked with an _Scrypt_-derived password.
    #[serde(with = "de::base64")]
    pub encrypted_key: Vec<u8>,
    /// Parameters for _Scrypt_ key derivation.
    pub scrypt_object: ScryptKdf,
    /// The on-disk-format version being used for the directory.
    pub version: u16,
    /// Set of features that are enabled.
    pub feature_flags: BTreeSet<Flag>,
}

/// Parameters for key derivation using _Scrypt_.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ScryptKdf {
    /// Random salt used as input.
    #[serde(with = "de::base64")]
    pub salt: Vec<u8>,
    /// CPU and memory cost.
    pub n: u32,
    /// Block size.
    pub r: u32,
    /// Parallelization level.
    pub p: u32,
    /// Output key length.
    pub key_len: usize,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize)]
pub enum Flag {
    /// Filenames are unencrypted.
    PlaintextNames,
    /// Per-directory IV file is used.
    #[serde(rename = "DirIV")]
    DirIv,
    /// Use EME (ECB-Mix-ECB) for filename encryption.
    #[serde(rename = "EMENames")]
    EmeNames,
    /// Use 128-bit IVs (nonces) for GCM cryptography.
    #[serde(rename = "GCMIV128")]
    GcmIv128,
    /// Allow filenames longer than 175 bytes.
    LongNames,
    /// Custom filename length limit used.
    LongNameMax,
    /// Use AES-SIV for content encryption.
    #[serde(rename = "AESSIV")]
    AesSiv,
    /// Use unpadded Base64 encoding for filenames.
    Raw64,
    /// Derive an extra cryptography key for content encryption (instead of using the master key
    /// directly).
    #[serde(rename = "HKDF")]
    Hkdf,
    /// The master key is protected with a FIDO2 token instead of a password.
    #[serde(rename = "FIDO2")]
    Fido2,
    /// Use XChacha20-Poly1305 for content encryption.
    XChaCha20Poly1305,
}

mod de {
    //! Custom deserializers for [`serde`].

    pub mod base64 {
        //! Deserialize [`base64`] strings back into raw byte vectors. Uses the standard character
        //! set **with** padding.

        use base64::prelude::*;
        use serde::Deserializer;

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(Visitor)
        }

        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("base64 encoded byte array")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                BASE64_STANDARD.decode(v).map_err(E::custom)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use super::*;

    #[test]
    fn load_config() -> Result<()> {
        let dir = tempfile::tempdir()?;

        let config = serde_json::json! {{
            "Creator": "",
            "EncryptedKey": BASE64_STANDARD.encode([0; 4]),
            "ScryptObject": {
                "Salt": BASE64_STANDARD.encode([0; 2]),
                "N": 1,
                "R": 1,
                "P": 1,
                "KeyLen": 32
            },
            "Version": 2,
            "FeatureFlags": [
                "PlaintextNames",
                "DirIV",
                "EMENames",
                "GCMIV128",
                "LongNames",
                "LongNameMax",
                "AESSIV",
                "Raw64",
                "HKDF",
                "FIDO2",
                "XChaCha20Poly1305"
            ]
        }};

        std::fs::write(dir.path().join(CONFIG_NAME), config.to_string())?;
        let config = load(dir.path())?;

        println!("{config:#?}");

        Ok(())
    }
}
