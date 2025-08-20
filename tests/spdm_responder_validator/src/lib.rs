// Licensed under the Apache-2.0 license
use std::sync::atomic::AtomicBool;

mod common;
pub mod doe;
pub mod mctp;
mod transport;

pub static EMULATOR_RUNNING: AtomicBool = AtomicBool::new(true);

pub fn wait_for_runtime_start() {

}

pub fn sleep_emulator_ticks(ticks: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ticks * 10));
}

#[cfg(test)]
mod test {
    use std::net::{SocketAddr, TcpStream, TcpListener};
    use std::io::{Read, Write};
    use std::thread;

    use emulator_periph::DynamicI3cAddress;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_builder::FirmwareBinaries;
    use mcu_rom_common::McuRomBootStatus;

    use mcu_hw_model::xi3c;

    const MAX_BUFFER_SIZE: usize = 2048;

    use crate::mctp::run_mctp_spdm_conformance_test;

    fn process_connection(i3c: , stream: &mut TcpStream) {
        // Handle the connection
        println!("New connection established: {:?}", stream.peer_addr());

        loop {
            let mut req_buffer: [u8; MAX_BUFFER_SIZE] = [0; MAX_BUFFER_SIZE];
            let mut rsp_buffer: [u8; MAX_BUFFER_SIZE] = [0; MAX_BUFFER_SIZE];
            match stream.read(&mut req_buffer[..MAX_BUFFER_SIZE]) {
                Ok(0) => {
                    // Connection closed
                    break;
                }
                Ok(n) => {
                    {
                        println!("Received {} bytes: {:?}", n, &req_buffer[..n]);
                        model.i3c_write(&mut req_buffer[..MAX_BUFFER_SIZE]);
                        model.i3c_read(&mut rsp_buffer[..MAX_BUFFER_SIZE]);
                        stream.write(&rsp_buffer);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from stream: {}", e);
                    break;
                }
            } 
        }
    }

    #[test]
    fn test_spdm_responder_validator_i3c() {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();
        let mut model = DefaultHwModel::new_unbooted(InitParams {
            caliptra_rom: &firmware_bundle.caliptra_rom,
            caliptra_firmware: &firmware_bundle.caliptra_fw,
            mcu_rom: &firmware_bundle.mcu_rom,
            mcu_firmware: &firmware_bundle.mcu_runtime,
            soc_manifest: &firmware_bundle.soc_manifest,
            active_mode: true,
            ..Default::default()
        })
        .unwrap();

        model.step_until(|m| m.mci_flow_status() == u32::from(McuRomBootStatus::I3cInitialized));

        let dynaddr: DynamicI3cAddress = DynamicI3cAddress::new(0x7C).expect("Unable to create DynamicI3cAddress");

        crate::mctp::run_mctp_spdm_conformance_test(
            2323,
            dynaddr,
            std::time::Duration::from_secs(9000), // timeout in seconds
        );

    let port: u16 = 42024;

    let tgt_addr = [SocketAddr::from(([127, 0, 0, 1], port))];
    let listener = TcpListener::bind(&tgt_addr[..]).expect("Could not bind to the SPDM listerner port");

    thread::spawn(move || {
        for mut stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    process_connection(mut stream);
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
    });

    let test_timeout_seconds = std::time::Duration::from_secs(9000);

    run_mctp_spdm_conformance_test(port, dynaddr, test_timeout_seconds);

    }
}

