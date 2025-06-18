extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;

pub type HashResult<T> = Result<T, HashError>;

#[async_trait]
pub trait SpdmHash {
    async fn hash<'a>(&mut self, hash_algo: HashAlgoType, data: &[u8], hash: &mut [u8]) -> HashResult<()>;
    async fn init<'a>(&mut self, hash_algo: HashAlgoType, data: Option<&[u8]>) -> HashResult<()>;
    async fn update<'a>(&mut self, data: &[u8]) -> HashResult<()>;
    async fn finalize<'a>(&mut self, hash: &mut [u8]) -> HashResult<()>;

    fn algo(&self) -> Option<HashAlgoType>;  
}

#[derive(Debug, PartialEq)]
pub enum HashError {
    HardwareError,
    BufferTooSmall,
    InvalidAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgoType {
    SHA384,
    SHA512,
}

impl From<HashAlgoType> for u32 {
    fn from(algo: HashAlgoType) -> Self {
        match algo {
            HashAlgoType::SHA384 => 2u32,
            HashAlgoType::SHA512 => 4u32,
        }
    }
}

impl HashAlgoType {
    pub fn hash_size(&self) -> usize {
        match self {
            HashAlgoType::SHA384 => 48,
            HashAlgoType::SHA512 => 64,
        }
    }
}