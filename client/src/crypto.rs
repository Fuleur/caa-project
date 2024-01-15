use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    sha2::Sha256,
    Oaep, RsaPrivateKey, RsaPublicKey,
};

pub fn rsa_encrypt(data: &[u8], pubkey: &[u8]) -> Result<Vec<u8>, rsa::Error> {
    let pubkey = RsaPublicKey::from_pkcs1_der(pubkey)?;
    let padding = Oaep::new::<Sha256>();

    pubkey.encrypt(&mut OsRng, padding, data)
}

pub fn rsa_decrypt(data: &[u8], privkey: &[u8]) -> Result<Vec<u8>, rsa::Error> {
    let privkey = RsaPrivateKey::from_pkcs1_der(privkey)?;
    let padding = Oaep::new::<Sha256>();

    privkey.decrypt(padding, data)
}

pub fn chacha_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let enc_data = cipher.encrypt(&nonce, data)?;

    Ok([nonce.to_vec(), enc_data].concat())
}

pub fn chacha_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    // 12 bytes nonce is concatened with data
    let nonce = &data[..12];
    let data = &data[12..];

    cipher.decrypt(GenericArray::from_slice(nonce), data)
}
