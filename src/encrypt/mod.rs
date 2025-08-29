pub mod bip38;
pub mod mnemonic;
pub mod verify;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid verify word")]
    InvalidVerify,
    #[error("Invalid desired size")]
    InvalidSize,
    #[error("Invalid passphrase")]
    InvalidPass,
    #[error("Encrypt error: {0}")]
    EncryptError(String),
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] crate::MnemonicError),
    #[error("Infallible error: {0}")]
    Infallible(#[from] std::convert::Infallible),
}

macro_rules! derive_error {
    ($e:expr, $source:ty) => {
        impl From<$source> for Error {
            fn from(e: $source) -> Self {
                $e(e.to_string())
            }
        }
    };
}
derive_error!(Error::EncryptError, argon2::Error);
derive_error!(Error::EncryptError, scrypt::errors::InvalidOutputLen);
derive_error!(Error::EncryptError, scrypt::errors::InvalidParams);
derive_error!(Error::EncryptError, bitcoin::bip32::Error);
