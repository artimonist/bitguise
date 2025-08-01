use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

pub trait AesEncryption {
    /// Encrypts data using AES-256 in ECB mode.
    fn aes_ecb_encrypt(&mut self, key: &[u8; 32]);

    /// Decrypts data using AES-256 in ECB mode.
    fn aes_ecb_decrypt(&mut self, key: &[u8; 32]);
}

impl AesEncryption for [u8; 16] {
    fn aes_ecb_encrypt(&mut self, key: &[u8; 32]) {
        let block = GenericArray::from_mut_slice(self);
        let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 32
        cipher.encrypt_block(block);
    }

    fn aes_ecb_decrypt(&mut self, key: &[u8; 32]) {
        let block = GenericArray::from_mut_slice(self);
        let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 32
        cipher.decrypt_block(block);
    }
}

impl AesEncryption for [u8; 32] {
    fn aes_ecb_encrypt(&mut self, key: &[u8; 32]) {
        let block = GenericArray::from_mut_slice(self);
        let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 32
        cipher.encrypt_block(block);
    }

    fn aes_ecb_decrypt(&mut self, key: &[u8; 32]) {
        let block = GenericArray::from_mut_slice(self);
        let cipher = aes::Aes256::new_from_slice(key).unwrap(); // fixed size 32
        cipher.decrypt_block(block);
    }
}
