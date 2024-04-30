use std::{collections::BTreeSet, ffi::OsStr, fs::FileType, path::Path};

use aead::{consts::U16, generic_array::typenum::Unsigned, Aead, AeadCore, KeyInit, Payload};
use aes::Aes256;
use aes_gcm::{AesGcm, Key, Nonce};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod config;
pub mod content;
pub mod names;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(Vec<u8>);

impl MasterKey {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self(vec![0; 32])
    }
}

pub fn decrypt_master_key(cfg: &config::Config, password: &str) -> Result<MasterKey> {
    let mut key_encryption_key = vec![0; cfg.scrypt_object.key_len];

    scrypt::scrypt(
        password.as_bytes(),
        &cfg.scrypt_object.salt,
        &scrypt::Params::new(
            cfg.scrypt_object.n.trailing_zeros().try_into()?,
            cfg.scrypt_object.r,
            cfg.scrypt_object.p,
            cfg.scrypt_object.key_len,
        )?,
        &mut key_encryption_key,
    )?;

    let hk = Hkdf::<Sha256>::new(None, &key_encryption_key);
    let mut key = Key::<Aes256>::default();
    hk.expand(AesGcmCipher::HKDF_INFO, &mut key)?;

    let cipher = AesGcm::<Aes256, U16>::new(&key);

    let nonce = Nonce::<U16>::from_slice(&cfg.encrypted_key[..U16::USIZE]);
    let ciphertext = &cfg.encrypted_key[nonce.len()..];
    let aad = 0_u64.to_be_bytes();

    let master_key = cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext,
            aad: &aad,
        },
    )?;

    Ok(MasterKey(master_key))
}

type AesGcmCipher = aes_gcm::AesGcm<Aes256, U16>;
type AesSivCipher = aes_siv::Aes256SivAead;
type XChaCha20Cipher = chacha20poly1305::XChaCha20Poly1305;

pub trait KeyDerive {
    const HKDF_INFO: &'static [u8];
}

impl KeyDerive for AesGcmCipher {
    const HKDF_INFO: &'static [u8] = b"AES-GCM file content encryption";
}

impl KeyDerive for AesSivCipher {
    const HKDF_INFO: &'static [u8] = b"AES-SIV file content encryption";
}

impl KeyDerive for XChaCha20Cipher {
    const HKDF_INFO: &'static [u8] = b"XChaCha20-Poly1305 file content encryption";
}

pub fn is_crypto_dir(ty: FileType, path: &Path) -> bool {
    ty.is_dir() && path.join(names::DIRIV_NAME).exists()
}

pub fn is_crypto_file(ty: FileType, name: &OsStr) -> bool {
    ty.is_file() && name != config::CONFIG_NAME && name != names::DIRIV_NAME
}

pub trait AeadSize {
    const NONCE: usize;
    const TAG: usize;

    const OVERHEAD: usize = Self::NONCE + Self::TAG;

    fn to_plain<const B: usize>(size: usize) -> (usize, usize) {
        let crypt_size = B + Self::OVERHEAD;

        let blocks = size / crypt_size;
        let remain = size % crypt_size;

        let last = if remain > 0 {
            remain - Self::OVERHEAD
        } else {
            0
        };

        let real_size = B * blocks + last;
        let real_blocks = real_size / B + 1;

        (real_size, real_blocks)
    }

    fn to_crypt<const B: usize>(size: usize) -> usize {
        let crypt_size = B + Self::OVERHEAD;

        let blocks = size / B;
        let remain = size % B;

        let last = if remain > 0 {
            remain + Self::OVERHEAD
        } else {
            0
        };

        blocks * crypt_size + last
    }
}

impl<T: AeadCore> AeadSize for T {
    const NONCE: usize = T::NonceSize::USIZE;
    const TAG: usize = T::TagSize::USIZE;
}

pub enum DynCipher {
    AesGcm,
    AesSiv,
    XChaCha20,
}

impl DynCipher {
    pub fn new(flags: &BTreeSet<config::Flag>) -> Self {
        if flags.contains(&config::Flag::XChaCha20Poly1305) {
            Self::XChaCha20
        } else if flags.contains(&config::Flag::AesSiv) {
            Self::AesSiv
        } else {
            Self::AesGcm
        }
    }

    pub const fn overhead(&self) -> usize {
        match self {
            Self::AesGcm => AesGcmCipher::OVERHEAD,
            Self::AesSiv => AesSivCipher::OVERHEAD,
            Self::XChaCha20 => XChaCha20Cipher::OVERHEAD,
        }
    }

    pub fn to_plain<const B: usize>(&self, size: usize) -> (usize, usize) {
        match self {
            Self::AesGcm => AesGcmCipher::to_plain::<B>(size),
            Self::AesSiv => AesSivCipher::to_plain::<B>(size),
            Self::XChaCha20 => XChaCha20Cipher::to_plain::<B>(size),
        }
    }

    pub fn to_crypt<const B: usize>(&self, size: usize) -> usize {
        match self {
            Self::AesGcm => AesGcmCipher::to_crypt::<B>(size),
            Self::AesSiv => AesSivCipher::to_crypt::<B>(size),
            Self::XChaCha20 => XChaCha20Cipher::to_crypt::<B>(size),
        }
    }

    pub fn decrypt(
        &self,
        master_key: &MasterKey,
        header: &content::FileHeader,
        data: &[u8],
        block_offset: usize,
    ) -> Result<Vec<u8>> {
        match self {
            Self::AesGcm => {
                content::decrypt::<AesGcmCipher>(master_key, header, data, block_offset)
            }
            Self::AesSiv => {
                content::decrypt::<AesSivCipher>(master_key, header, data, block_offset)
            }
            Self::XChaCha20 => {
                content::decrypt::<XChaCha20Cipher>(master_key, header, data, block_offset)
            }
        }
    }

    pub fn encrypt(
        &self,
        master_key: &MasterKey,
        header: &content::FileHeader,
        data: &[u8],
        block_offset: usize,
    ) -> Result<Vec<u8>> {
        match self {
            Self::AesGcm => {
                content::encrypt::<AesGcmCipher>(master_key, header, data, block_offset)
            }
            Self::AesSiv => {
                content::encrypt::<AesSivCipher>(master_key, header, data, block_offset)
            }
            Self::XChaCha20 => {
                content::encrypt::<XChaCha20Cipher>(master_key, header, data, block_offset)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSize;

    impl AeadSize for FakeSize {
        const NONCE: usize = 5;
        const TAG: usize = 5;
    }

    #[test]
    fn to_plain() {
        assert_eq!((10, 1), FakeSize::to_plain::<20>(20));
        assert_eq!((10, 2), FakeSize::to_plain::<10>(20));
        assert_eq!((10, 3), FakeSize::to_plain::<5>(30));
    }

    #[test]
    fn to_crypt() {
        assert_eq!(20, FakeSize::to_crypt::<20>(10));
        assert_eq!(20, FakeSize::to_crypt::<10>(10));
        assert_eq!(30, FakeSize::to_crypt::<5>(10));
    }
}
