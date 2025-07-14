// Licensed under the Apache-2.0 license

mod cert_store;
mod device_cert_store;
mod endorsement_certs;

use core::fmt::Write;
use device_cert_store::{initialize_cert_store, SharedCertStore};
use embassy_executor::Spawner;
use libsyscall_caliptra::doe;
use libsyscall_caliptra::mctp;
use libapi_caliptra::error::CaliptraApiError;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::*;
use spdm_lib::transport::common::SpdmTransport;
use spdm_lib::transport::doe::DoeTransport;
use spdm_lib::transport::mctp::MctpTransport;

use spdm_lib::platform::hash::{SpdmHash, SpdmHashResult, SpdmHashAlgoType, SpdmHashError};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngError, SpdmRngResult};
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::crypto::rng::Rng;

extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;

// Maximum SPDM responder buffer size
const MAX_RESPONDER_BUF_SIZE: usize = 2048;

// Caliptra supported SPDM versions
const SPDM_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V12, SpdmVersion::V13];

// Calitra Crypto timeout exponent (2^20 us)
const CALIPTRA_SPDM_CT_EXPONENT: u8 = 20;

// Caliptra Hash Priority table
static HASH_PRIORITY_TABLE: &[BaseHashAlgoType] = &[
    BaseHashAlgoType::TpmAlgSha512,
    BaseHashAlgoType::TpmAlgSha384,
    BaseHashAlgoType::TpmAlgSha256,
];

struct LocalRng;

impl LocalRng {
    fn new() -> Self {
        LocalRng {}
    }

    fn translate_error(e: CaliptraApiError) -> SpdmRngError {
        match e {
            _ => SpdmRngError::InvalidSize, // Just map everything to this for now
        }
    }
}

#[async_trait]
impl SpdmRng for LocalRng {
    async fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()> {
        Rng::generate_random_number(random_number)
            .await
            .map_err(|e| Self::translate_error(e))
    }

    async fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        Ok(())
    }
}

struct LocalHash {
    spdm_hash_algo: SpdmHashAlgoType,
    local_hash_algo: HashAlgoType,
    ctx: HashContext,
}

impl LocalHash { 

    fn translate_algo(algo: SpdmHashAlgoType) -> HashAlgoType {
        match algo {
            SpdmHashAlgoType::SHA384 => HashAlgoType::SHA384,
            SpdmHashAlgoType::SHA512 => HashAlgoType::SHA512,
        }
    }

    fn new(hash_algo: SpdmHashAlgoType) -> Self {
        let ctx = HashContext::new();
        let algo = Self::translate_algo(hash_algo);

        LocalHash {
            ctx: ctx,
            spdm_hash_algo: hash_algo,
            local_hash_algo: algo
        }
    }

    fn translate_error(e: CaliptraApiError) -> SpdmHashError {
        match e {
            _ => SpdmHashError::PlatformError, // Just map everything to this for now
        }
    }
}

#[async_trait]
impl SpdmHash for LocalHash {
    async fn hash(&mut self, hash_algo: SpdmHashAlgoType, data: &[u8], hash: &mut [u8]) -> SpdmHashResult<()> {
        self.ctx.init(Self::translate_algo(hash_algo), Some(data))
            .await
            .map_err(|e| LocalHash::translate_error(e))?;

        self.ctx.update(data)
            .await
            .map_err(|e| LocalHash::translate_error(e))?;

        self.ctx
            .finalize(hash)
            .await
            .map_err(|e| LocalHash::translate_error(e))
    }

    async fn init(&mut self, hash_algo: SpdmHashAlgoType, data: Option<&[u8]>) -> SpdmHashResult<()> {
        self.ctx.init(Self::translate_algo(hash_algo), data)
            .await
            .map_err(|e| LocalHash::translate_error(e))
    }

    async fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        self.ctx.update(data)
            .await
            .map_err(|e| LocalHash::translate_error(e))
    }

    async fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()> {
        self.ctx.finalize(hash)
            .await
            .map_err(|e| LocalHash::translate_error(e))?;

        self.ctx = HashContext::new();

        Ok(())
    }

    fn reset(&mut self) {
        self.ctx = HashContext::new();
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.spdm_hash_algo
    }
}

#[embassy_executor::task]
pub(crate) async fn spdm_task(spawner: Spawner) {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "SPDM_TASK: Running SPDM-TASK...").unwrap();

    // Initialize the shared certificate store
    if let Err(e) = initialize_cert_store().await {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to initialize certificate store: {:?}",
            e
        )
        .unwrap();
        return;
    }

    if let Err(e) = spawner.spawn(spdm_mctp_responder()) {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to spawn spdm_mctp_responder: {:?}",
            e
        )
        .unwrap();
    }
    if let Err(e) = spawner.spawn(spdm_doe_responder()) {
        writeln!(
            console_writer,
            "SPDM_TASK: Failed to spawn spdm_doe_responder: {:?}",
            e
        )
        .unwrap();
    }
}

#[embassy_executor::task]
async fn spdm_mctp_responder() {
    let mut raw_buffer = [0; MAX_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut mctp_spdm_transport: MctpTransport = MctpTransport::new(mctp::driver_num::MCTP_SPDM);

    let mut spdm_hash = LocalHash::new(SpdmHashAlgoType::SHA384);
    let mut m1_hash = LocalHash::new(SpdmHashAlgoType::SHA384);
    let mut l1_hash = LocalHash::new(SpdmHashAlgoType::SHA384);
    let mut rng = LocalRng::new();

    let max_mctp_spdm_msg_size =
        (MAX_RESPONDER_BUF_SIZE - mctp_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: CapabilityFlags::default(),
        data_transfer_size: max_mctp_spdm_msg_size,
        max_spdm_msg_size: max_mctp_spdm_msg_size,
    };

    // Create a wrapper for the global certificate store
    let shared_cert_store = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut mctp_spdm_transport,
        local_capabilities,
        &shared_cert_store,
        &mut spdm_hash,
        &mut m1_hash,
        &mut l1_hash,
        &mut rng,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(
                cw,
                "SPDM_MCTP_RESPONDER: Failed to create SPDM context: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(&mut raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cw, "SPDM_MCTP_RESPONDER: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cw, "SPDM_MCTP_RESPONDER: Process message failed: {:?}", e).unwrap();
            }
        }
    }
}

#[embassy_executor::task]
async fn spdm_doe_responder() {
    let mut raw_buffer = [0; MAX_RESPONDER_BUF_SIZE];
    let mut cw = Console::<DefaultSyscalls>::writer();
    let mut doe_spdm_transport: DoeTransport = DoeTransport::new(doe::driver_num::DOE_SPDM);

    let mut spdm_hash = LocalHash::new(SpdmHashAlgoType::SHA384);
    let mut m1_hash = LocalHash::new(SpdmHashAlgoType::SHA384);
    let mut l1_hash = LocalHash::new(SpdmHashAlgoType::SHA384);

    let max_doe_spdm_msg_size = (MAX_RESPONDER_BUF_SIZE - doe_spdm_transport.header_size()) as u32;

    let local_capabilities = DeviceCapabilities {
        ct_exponent: CALIPTRA_SPDM_CT_EXPONENT,
        flags: CapabilityFlags::default(),
        data_transfer_size: max_doe_spdm_msg_size,
        max_spdm_msg_size: max_doe_spdm_msg_size,
    };

    // Create a wrapper for the global certificate store
    let shared_cert_store = SharedCertStore::new();

    let mut ctx = match SpdmContext::new(
        SPDM_VERSIONS,
        &mut doe_spdm_transport,
        local_capabilities,
        &shared_cert_store,
        &mut spdm_hash,
        &mut m1_hash,
        &mut l1_hash,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            writeln!(
                cw,
                "SPDM_DOE_RESPONDER: Failed to create SPDM context: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    let mut msg_buffer = MessageBuf::new(&mut raw_buffer);
    loop {
        let result = ctx.process_message(&mut msg_buffer).await;
        match result {
            Ok(_) => {
                writeln!(cw, "SPDM_DOE_RESPONDER: Process message successfully").unwrap();
            }
            Err(e) => {
                writeln!(cw, "SPDM_DOE_RESPONDER: Process message failed: {:?}", e).unwrap();
            }
        }
    }
}
