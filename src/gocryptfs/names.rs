use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::Read,
    os::unix::prelude::*,
    path::Path,
};

use aes::{cipher::KeyIvInit, Aes256};
use anyhow::Result;
use base64::prelude::*;
use block_padding::Pkcs7;
use eme_mode::DynamicEme;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

use super::MasterKey;

pub const DIRIV_NAME: &str = "gocryptfs.diriv";

const HKDF_INFO: &[u8] = b"EME filename encryption";

pub type Key = aes::cipher::Key<Aes256>;
pub type Iv = aes::cipher::Iv<DynamicEme<Aes256>>;

pub fn load_iv(dir: &Path) -> Result<Iv> {
    let mut iv = Iv::default();
    let mut file = File::open(dir.join(DIRIV_NAME))?;
    file.read_exact(&mut iv)?;
    Ok(iv)
}

pub fn create_iv() -> Iv {
    let mut iv = Iv::default();
    rand::thread_rng().fill(iv.as_mut_slice());
    iv
}

pub fn decrypt(master_key: &MasterKey, iv: &Iv, name: &OsStr) -> Result<OsString> {
    let key = derive_key(master_key)?;
    let eme = DynamicEme::<Aes256>::new(&key, iv);

    let mut raw = BASE64_URL_SAFE_NO_PAD.decode(name.as_bytes())?;
    let raw = eme.decrypt_padded_mut::<Pkcs7>(&mut raw)?;
    let plain = OsStr::from_bytes(raw);

    Ok(plain.to_owned())
}

pub fn encrypt(master_key: &MasterKey, iv: &Iv, name: &OsStr) -> Result<OsString> {
    let key = derive_key(master_key)?;
    let mut eme = DynamicEme::<Aes256>::new(&key, iv);

    let raw = eme.encrypt_padded_vec_mut::<Pkcs7>(name.as_bytes());
    let crypt = BASE64_URL_SAFE_NO_PAD.encode(raw);

    Ok(OsString::from_vec(crypt.into_bytes()))
}

fn derive_key(master_key: &MasterKey) -> Result<Key> {
    let hk = Hkdf::<Sha256>::new(None, master_key.expose());
    let mut key = Key::default();
    hk.expand(HKDF_INFO, &mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() -> Result<()> {
        let mk = MasterKey::empty();
        let iv = Iv::default();
        let name = OsStr::from_bytes(b"test.txt");

        let crypt = encrypt(&mk, &iv, name)?;
        let plain = decrypt(&mk, &iv, &crypt)?;

        assert_eq!(name, plain);

        Ok(())
    }
}
