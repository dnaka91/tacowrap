use std::mem;

use aead::{AeadInPlace, Key, KeyInit, Nonce, Tag};
use anyhow::{ensure, Context, Result};
use hkdf::Hkdf;
use rand::prelude::*;
use rayon::prelude::*;
use sha2::Sha256;

use super::{AeadSize, KeyDerive, MasterKey};

pub const BLOCK_SIZE: usize = 4096;

pub struct FileHeader {
    version: u16,
    file_id: [u8; 16],
}

impl FileHeader {
    const FILE_ID_LEN: usize = mem::size_of::<[u8; 16]>();
    pub const LEN: usize = Self::VERSION_LEN + Self::FILE_ID_LEN;
    const VERSION_LEN: usize = mem::size_of::<u16>();

    pub fn read(data: &[u8]) -> Result<(Self, &[u8])> {
        ensure!(
            data.len() >= Self::LEN,
            "content too small to contain header"
        );

        let (version, data) = data.split_at(Self::VERSION_LEN);
        let (id, data) = data.split_at(Self::FILE_ID_LEN);

        let head = Self {
            version: u16::from_be_bytes(version.try_into()?),
            file_id: id.try_into()?,
        };

        ensure!(
            head.version == 2,
            "only format version 2 (not {}) supported",
            head.version
        );

        Ok((head, data))
    }

    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            version: 2,
            file_id: rand::thread_rng().gen(),
        }
    }

    #[allow(dead_code)]
    fn copy_to_slice<'a>(&self, dst: &'a mut [u8]) -> &'a mut [u8] {
        dst[..Self::LEN][..Self::VERSION_LEN].copy_from_slice(&self.version.to_be_bytes());
        dst[..Self::LEN][Self::VERSION_LEN..].copy_from_slice(&self.file_id);
        &mut dst[Self::LEN..]
    }
}

#[allow(clippy::cast_possible_truncation)]
pub fn decrypt<C>(
    master_key: &MasterKey,
    header: &FileHeader,
    data: &[u8],
    block_offset: usize,
) -> Result<Vec<u8>>
where
    C: AeadInPlace + AeadSize + KeyDerive + KeyInit + Send + Sync,
{
    if data.is_empty() {
        return Ok(Vec::default());
    }

    let cc = create_cipher::<C>(master_key)?;

    let mut output = vec![0; C::to_plain::<BLOCK_SIZE>(data.len()).0];

    let chunks_in = data.par_chunks(BLOCK_SIZE + C::OVERHEAD);
    let chunks_out = output.par_chunks_mut(BLOCK_SIZE);

    chunks_in
        .zip(chunks_out)
        .enumerate()
        .try_for_each(|(block_id, (chunk_in, chunk_out))| {
            decrypt_block(&cc, header, block_id + block_offset, chunk_in, chunk_out)
        })?;

    Ok(output)
}

fn decrypt_block<C>(
    cipher: &C,
    header: &FileHeader,
    block_id: usize,
    input: &[u8],
    output: &mut [u8],
) -> Result<()>
where
    C: AeadInPlace + AeadSize,
{
    let nonce = Nonce::<C>::from_slice(&input[..C::NONCE]);
    let aad = create_aad(header, block_id);

    let tag = Tag::<C>::from_slice(&input[C::NONCE + output.len()..]);
    output.copy_from_slice(&input[C::NONCE..][..output.len()]);

    cipher
        .decrypt_in_place_detached(nonce, &aad, output, tag)
        .with_context(|| {
            format!(
                "decryption failed (file_id: {:?}, block_id: {block_id})",
                header.file_id,
            )
        })?;

    Ok(())
}

#[allow(dead_code, clippy::cast_possible_truncation)]
pub fn encrypt<C>(master_key: &MasterKey, header: &FileHeader, data: &[u8]) -> Result<Vec<u8>>
where
    C: AeadInPlace + AeadSize + KeyDerive + KeyInit + Send + Sync,
{
    if data.is_empty() {
        return Ok(Vec::default());
    }

    let cc = create_cipher::<C>(master_key)?;

    let mut output = vec![0u8; C::to_crypt::<BLOCK_SIZE>(data.len())];

    let chunks_in = data.par_chunks(BLOCK_SIZE);
    let chunks_out = output.par_chunks_mut(BLOCK_SIZE + C::OVERHEAD);

    chunks_in
        .zip(chunks_out)
        .enumerate()
        .try_for_each(|(block_id, (chunk_in, chunk_out))| {
            encrypt_block(&cc, header, block_id, chunk_in, chunk_out)
        })?;

    Ok(output)
}

fn encrypt_block<C>(
    cipher: &C,
    header: &FileHeader,
    block_id: usize,
    input: &[u8],
    output: &mut [u8],
) -> Result<()>
where
    C: AeadInPlace,
{
    let nonce = C::generate_nonce(&mut rand::thread_rng());
    let aad = create_aad(header, block_id);

    output[..C::NONCE].copy_from_slice(&nonce);
    output[C::NONCE..][..input.len()].copy_from_slice(input);

    let tag = cipher
        .encrypt_in_place_detached(&nonce, &aad, &mut output[C::NONCE..][..input.len()])
        .with_context(|| {
            format!(
                "encryption failed (file_id: {:?}, block_id: {block_id})",
                header.file_id,
            )
        })?;

    output[C::NONCE + input.len()..].copy_from_slice(&tag);

    Ok(())
}

fn create_cipher<C>(master_key: &MasterKey) -> Result<C>
where
    C: KeyDerive + KeyInit,
{
    let hk = Hkdf::<Sha256>::new(None, master_key.expose());
    let mut key = Key::<C>::default();
    hk.expand(C::HKDF_INFO, &mut key)?;

    Ok(C::new(&key))
}

fn create_aad(header: &FileHeader, block_id: usize) -> [u8; 24] {
    let mut aad = [0; 24];
    aad[..mem::size_of::<u64>()].copy_from_slice(&(block_id as u64).to_be_bytes());
    aad[mem::size_of::<u64>()..].copy_from_slice(&header.file_id);
    aad
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::XChaCha20Poly1305;
    use yare::parameterized;

    use super::*;

    #[parameterized(
        short = { 10 },
        exact = { 4096 },
        large = { 4096 * 3 + 10 },
    )]
    fn roundtrip(size: usize) -> Result<()> {
        let mk = MasterKey::empty();
        let header = FileHeader::new();
        let content = vec![5; size];

        let crypt = encrypt::<XChaCha20Poly1305>(&mk, &header, &content)?;
        let plain = decrypt::<XChaCha20Poly1305>(&mk, &header, &crypt, 0)?;

        assert_eq!(content, &*plain);

        Ok(())
    }
}
