use std::{collections::BTreeSet, path::Path};

use anyhow::{ensure, Context, Result};
use serde::Deserialize;

/// Name of the config file, located in the root of an encrypted directory.
pub const CONFIG_NAME: &str = "gocryptfs.conf";

/// Load the configuration from an encrypted directory.
pub fn load(base_dir: &Path) -> Result<Config> {
    let cfg = std::fs::read(base_dir.join(CONFIG_NAME))?;
    let cfg = serde_json::from_slice::<Config>(&cfg)?;

    cfg.validate()?;

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

impl Config {
    fn validate(&self) -> Result<()> {
        let Self {
            scrypt_object,
            version,
            feature_flags,
            ..
        } = self;

        scrypt_object
            .validate()
            .context("invalid scrypt parameter")?;

        ensure!(
            *version == 2,
            "unknown on-disk format {version} (only v2 supported)",
        );

        if feature_flags.contains(&Flag::XChaCha20Poly1305) {
            ensure!(
                !feature_flags.contains(&Flag::AesSiv),
                "XChaCha20Poly1305 and AESSIV are mutually exclusive",
            );
            ensure!(
                !feature_flags.contains(&Flag::GcmIv128),
                "XChaCha20Poly1305 conflicts with GCMIV128",
            );
            ensure!(
                feature_flags.contains(&Flag::Hkdf),
                "XChaCha20Poly1305 requires HKDF",
            );
        } else if feature_flags.contains(&Flag::AesSiv) {
            ensure!(
                feature_flags.contains(&Flag::GcmIv128),
                "AESSIV requires GCMIV128",
            );
        } else {
            ensure!(
                feature_flags.contains(&Flag::GcmIv128),
                "AES-GCM requires GCMIV128",
            );
        }

        // custom stuff

        ensure!(
            !feature_flags.contains(&Flag::PlaintextNames),
            "plaintext file names not supported",
        );
        ensure!(
            !feature_flags.contains(&Flag::Fido2),
            "FIDO2 passwords not supported",
        );
        ensure!(
            !feature_flags.contains(&Flag::LongNameMax),
            "custom name length limit not supported",
        );
        ensure!(
            feature_flags.contains(&Flag::DirIv),
            "directory IV required",
        );
        ensure!(
            feature_flags.contains(&Flag::EmeNames),
            "EME encrypted names required",
        );
        ensure!(
            feature_flags.contains(&Flag::LongNames),
            "long name flag required",
        );
        ensure!(
            feature_flags.contains(&Flag::Raw64),
            "raw Base64 encoding flag required",
        );

        Ok(())
    }
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

impl ScryptKdf {
    fn validate(&self) -> Result<()> {
        ensure!(self.salt.len() >= 32, "salt is too short");
        ensure!(self.n.trailing_zeros() >= 10, "parameter N is too small");
        ensure!(self.r >= 8, "parameter R is too small");
        ensure!(self.p >= 1, "parameter P is too small");
        ensure!(self.key_len >= 32, "key length is too small");
        Ok(())
    }
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
                "Salt": BASE64_STANDARD.encode([0; 32]),
                "N": 1024,
                "R": 8,
                "P": 1,
                "KeyLen": 32
            },
            "Version": 2,
            "FeatureFlags": [
                "DirIV",
                "EMENames",
                "LongNames",
                "Raw64",
                "HKDF",
                "XChaCha20Poly1305"
            ]
        }};

        std::fs::write(dir.path().join(CONFIG_NAME), config.to_string())?;
        load(dir.path())?;

        Ok(())
    }
}
