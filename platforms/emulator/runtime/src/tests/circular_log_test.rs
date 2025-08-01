// Licensed under the Apache-2.0 license

// Based on Tock log test framework with modifications.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_emulator::logging::logging_flash as log;
use capsules_emulator::logging::logging_flash::{ENTRY_HEADER_SIZE, PAGE_HEADER_SIZE};
use core::cell::Cell;
use core::ptr::addr_of_mut;
use flash_driver::flash_ctrl;
use kernel::debug;
use kernel::hil::flash;
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::static_init;
use kernel::storage_volume;
use kernel::utilities::cells::{NumericCellExt, TakeCell};
use kernel::ErrorCode;
use mcu_platforms_common::{read_volatile_at, read_volatile_slice};
use mcu_tock_veer::timers::InternalTimers;

// Allocate 1KB storage volume for the circular log test. It resides on flash.
storage_volume!(CIRCULAR_TEST_LOG, 1);

const PAGE_SIZE: usize = 256;
// Buffer for reading from and writing to in the log tests.
static mut BUFFER: [u8; 64] = [0; 64];
// Length of buffer to actually use.
const BUFFER_LEN: usize = 64;
// Dummy buffer for testing bad writes.
static mut DUMMY_BUFFER: [u8; PAGE_SIZE * 2] = [0; PAGE_SIZE * 2];
// Time to wait in between log operations.
const WAIT_MS: u32 = 50;
// Number of entries to write per write operation.
const ENTRIES_PER_WRITE: u64 = 10;
const LOG_FLASH_BASE_ADDR: u32 = mcu_config_emulator::flash::LOGGING_FLASH_CONFIG.base_addr;

// Test's current state.
#[derive(Debug, Clone, Copy, PartialEq)]
enum TestState {
    Operate,
    CleanUp,
}

// A single operation within the test.
#[derive(Debug, Clone, Copy, PartialEq)]
enum TestOp {
    Read,
    BadRead,
    Write,
    BadWrite,
    Sync,
    SeekBeginning,
    BadSeek(usize),
    Erase,
}

pub unsafe fn run(
    mux_alarm: &'static MuxAlarm<'static, InternalTimers>,
    flash_controller: &'static flash_ctrl::EmulatedFlashCtrl,
) -> Option<u32> {
    flash_controller.init();
    let pagebuffer = static_init!(
        flash_ctrl::EmulatedFlashPage,
        flash_ctrl::EmulatedFlashPage::default()
    );
    // Create actual log storage abstraction on top of flash.
    let log: &'static mut Log = static_init!(
        Log,
        log::Log::new(&CIRCULAR_TEST_LOG, flash_controller, pagebuffer, true)
    );
    // Set up the flash base address for the log storage
    log.set_flash_base_address(LOG_FLASH_BASE_ADDR);

    kernel::deferred_call::DeferredCallClient::register(log);
    flash::HasClient::set_client(flash_controller, log);

    let alarm = static_init!(
        VirtualMuxAlarm<'static, InternalTimers>,
        VirtualMuxAlarm::new(mux_alarm)
    );
    alarm.setup();

    // Create and run test for log storage.
    let test = static_init!(
        LogTest<VirtualMuxAlarm<'static, InternalTimers>>,
        LogTest::new(log, &mut *addr_of_mut!(BUFFER), alarm, &TEST_OPS)
    );
    log.set_read_client(test);
    log.set_append_client(test);
    test.alarm.set_alarm_client(test);

    test.run();
    Some(0)
}

static TEST_OPS: [TestOp; 25] = [
    // Read back any existing entries.
    TestOp::BadRead,
    TestOp::Read,
    // Write multiple pages, but don't fill log.
    TestOp::BadWrite,
    TestOp::Write,
    TestOp::Read,
    TestOp::BadWrite,
    TestOp::Write,
    TestOp::Read,
    // Seek to beginning and re-verify entire log.
    TestOp::SeekBeginning,
    TestOp::Read,
    // Write multiple pages, over-filling log and overwriting oldest entries.
    TestOp::SeekBeginning,
    TestOp::Write,
    // Read offset should be incremented since it was invalidated by previous write.
    TestOp::BadRead,
    TestOp::Read,
    // Write multiple pages and sync. Read offset should be invalidated due to sync clobbering
    // previous read offset.
    TestOp::Write,
    TestOp::Sync,
    TestOp::Read,
    // Try bad seeks, should fail and not change read entry ID.
    TestOp::Write,
    TestOp::BadSeek(0),
    TestOp::BadSeek(usize::MAX),
    TestOp::Read,
    // Try bad write, nothing should change.
    TestOp::BadWrite,
    TestOp::Read,
    // Sync log before finishing test so that all changes persist for next test iteration.
    TestOp::Sync,
    TestOp::Erase,
];

type Log = log::Log<'static, flash_ctrl::EmulatedFlashCtrl<'static>>;
struct LogTest<A: 'static + Alarm<'static>> {
    log: &'static Log,
    buffer: TakeCell<'static, [u8]>,
    alarm: &'static A,
    state: Cell<TestState>,
    ops: &'static [TestOp],
    op_index: Cell<usize>,
    op_start: Cell<bool>,
    read_val: Cell<u64>,
    write_val: Cell<u64>,
}

impl<A: 'static + Alarm<'static>> LogTest<A> {
    fn new(
        log: &'static Log,
        buffer: &'static mut [u8],
        alarm: &'static A,
        ops: &'static [TestOp],
    ) -> LogTest<A> {
        // Recover test state.
        let read_val = entry_id_to_test_value(log.next_read_entry_id());
        let write_val = entry_id_to_test_value(log.log_end());

        romtime::println!(
            "Log recovered from flash (Start and end entry IDs: {:?} to {:?}; read and write values: {} and {})",
            log.next_read_entry_id(),
            log.log_end(),
            read_val,
            write_val
        );

        LogTest {
            log,
            buffer: TakeCell::new(buffer),
            alarm,
            state: Cell::new(TestState::Operate),
            ops,
            op_index: Cell::new(0),
            op_start: Cell::new(true),
            read_val: Cell::new(read_val),
            write_val: Cell::new(write_val),
        }
    }

    fn run(&self) {
        match self.state.get() {
            TestState::Operate => {
                let op_index = self.op_index.get();

                if op_index == self.ops.len() {
                    self.state.set(TestState::CleanUp);
                    let _ = self.log.seek(self.log.log_start());
                    return;
                }

                match self.ops[op_index] {
                    TestOp::Read => self.read(),
                    TestOp::BadRead => self.bad_read(),
                    TestOp::Write => self.write(),
                    TestOp::BadWrite => self.bad_write(),
                    TestOp::Sync => self.sync(),
                    TestOp::SeekBeginning => self.seek_beginning(),
                    TestOp::BadSeek(entry_id) => self.bad_seek(entry_id),
                    TestOp::Erase => self.erase(),
                }
                // Integration tests are executed before kernel loop starts.
                // Explicitly advance the kernel to handle deferred calls and interrupt processing.
                #[cfg(feature = "test-log-flash-circular")]
                crate::board::run_kernel_op(200);
            }
            TestState::CleanUp => {
                romtime::println!(
                    "Circular Log Storage test succeeded! (Final log start and end entry IDs: {:?} to {:?})",
                    self.log.next_read_entry_id(),
                    self.log.log_end()
                );
            }
        }
    }

    fn next_op(&self) {
        self.op_index.increment();
        self.op_start.set(true);
    }

    fn erase(&self) {
        match self.log.erase() {
            Ok(()) => (),
            Err(ErrorCode::BUSY) => {
                self.wait();
            }
            _ => panic!("Could not erase log storage!"),
        }
        // Integration tests are executed before kernel loop.
        // Explicitly advance the kernel to handle deferred calls and interrupt processing.
        #[cfg(feature = "test-log-flash-circular")]
        crate::board::run_kernel_op(200);
    }

    fn read(&self) {
        // Update read value if clobbered by previous operation.
        if self.op_start.get() {
            let next_read_val = entry_id_to_test_value(self.log.next_read_entry_id());
            if self.read_val.get() < next_read_val {
                romtime::println!(
                    "Increasing read value from {} to {} due to clobbering (read entry ID is {:?})!",
                    self.read_val.get(),
                    next_read_val,
                    self.log.next_read_entry_id()
                );
                self.read_val.set(next_read_val);
            }
        }

        self.buffer.take().map_or_else(
            || panic!("NO BUFFER"),
            move |buffer| {
                // Clear buffer first to make debugging more sane.
                buffer.fill(0);

                if let Err((error, original_buffer)) = self.log.read(buffer, BUFFER_LEN) {
                    self.buffer.replace(original_buffer);
                    match error {
                        ErrorCode::FAIL => {
                            // No more entries, start writing again.
                            romtime::println!(
                                "READ DONE: READ OFFSET: {:?} / WRITE OFFSET: {:?}",
                                self.log.next_read_entry_id(),
                                self.log.log_end()
                            );
                            self.next_op();
                            self.run();
                        }
                        ErrorCode::BUSY => {
                            romtime::println!("Flash busy, waiting before reattempting read");
                            self.wait();
                        }
                        _ => panic!("READ #{} FAILED: {:?}", self.read_val.get(), error),
                    }
                }
            },
        );
    }

    fn bad_read(&self) {
        // Ensure failure if buffer is smaller than provided max read length.
        self.buffer
            .take()
            .map(
                move |buffer| match self.log.read(buffer, buffer.len() + 1) {
                    Ok(()) => panic!("Read with too-large max read length succeeded unexpectedly!"),
                    Err((error, original_buffer)) => {
                        self.buffer.replace(original_buffer);
                        assert_eq!(error, ErrorCode::INVAL);
                    }
                },
            )
            .unwrap();

        // Ensure failure if buffer is too small to hold entry.
        self.buffer
            .take()
            .map(move |buffer| match self.log.read(buffer, BUFFER_LEN - 1) {
                Ok(()) => panic!("Read with too-small buffer succeeded unexpectedly!"),
                Err((error, original_buffer)) => {
                    self.buffer.replace(original_buffer);
                    if self.read_val.get() == self.write_val.get() {
                        assert_eq!(error, ErrorCode::FAIL);
                    } else {
                        assert_eq!(error, ErrorCode::SIZE);
                    }
                }
            })
            .unwrap();

        self.next_op();
        self.run();
    }

    fn write(&self) {
        self.buffer
            .take()
            .map(move |buffer| {
                // Set buffer value.
                buffer.iter_mut().enumerate().for_each(|(i, byte)| {
                    *byte = if i < BUFFER_LEN { i as u8 } else { 0 };
                });

                if let Err((error, original_buffer)) = self.log.append(buffer, BUFFER_LEN) {
                    self.buffer.replace(original_buffer);

                    match error {
                        ErrorCode::BUSY => self.wait(),
                        _ => panic!("WRITE FAILED: {:?}", error),
                    }
                }
            })
            .unwrap();
    }

    fn bad_write(&self) {
        let original_offset = self.log.log_end();

        // Ensure failure if entry length is 0.
        self.buffer
            .take()
            .map(move |buffer| match self.log.append(buffer, 0) {
                Ok(()) => panic!("Appending entry of size 0 succeeded unexpectedly!"),
                Err((error, original_buffer)) => {
                    self.buffer.replace(original_buffer);
                    assert_eq!(error, ErrorCode::INVAL);
                }
            })
            .unwrap();

        // Ensure failure if proposed entry length is greater than buffer length.
        self.buffer
            .take()
            .map(
                move |buffer| match self.log.append(buffer, buffer.len() + 1) {
                    Ok(()) => panic!("Appending with too-small buffer succeeded unexpectedly!"),
                    Err((error, original_buffer)) => {
                        self.buffer.replace(original_buffer);
                        assert_eq!(error, ErrorCode::INVAL);
                    }
                },
            )
            .unwrap();

        // Ensure failure if entry is too large to fit within a single flash page.
        unsafe {
            let dummy_buffer = &mut *addr_of_mut!(DUMMY_BUFFER);
            let len = dummy_buffer.len();
            match self.log.append(dummy_buffer, len) {
                Ok(()) => panic!("Appending with too-small buffer succeeded unexpectedly!"),
                Err((ecode, _original_buffer)) => assert_eq!(ecode, ErrorCode::SIZE),
            }
        }

        // Make sure that append offset was not changed by failed writes.
        assert_eq!(original_offset, self.log.log_end());
        self.next_op();
        self.run();
    }

    fn sync(&self) {
        match self.log.sync() {
            Ok(()) => (),
            error => panic!("Sync failed: {:?}", error),
        }
    }

    fn seek_beginning(&self) {
        let entry_id = self.log.log_start();
        match self.log.seek(entry_id) {
            Ok(()) => romtime::println!("Seeking to {:?}...", entry_id),
            error => panic!("Seek failed: {:?}", error),
        }
    }

    fn bad_seek(&self, entry_id: usize) {
        // Make sure seek fails with INVAL.
        let original_offset = self.log.next_read_entry_id();
        match self.log.seek(entry_id) {
            Err(ErrorCode::INVAL) => (),
            Ok(()) => panic!(
                "Seek to invalid entry ID {:?} succeeded unexpectedly!",
                entry_id
            ),
            error => panic!(
                "Seek to invalid entry ID {:?} failed with unexpected error {:?}!",
                entry_id, error
            ),
        }

        // Make sure that read offset was not changed by failed seek.
        assert_eq!(original_offset, self.log.next_read_entry_id());
        self.next_op();
        self.run();
    }

    fn wait(&self) {
        let delay = self.alarm.ticks_from_ms(WAIT_MS);
        let now = self.alarm.now();
        self.alarm.set_alarm(now, delay);
    }
}

impl<A: Alarm<'static>> LogReadClient for LogTest<A> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize, error: Result<(), ErrorCode>) {
        match error {
            Ok(()) => {
                // Verify correct number of bytes were read.
                if length != BUFFER_LEN {
                    panic!(
                        "{} bytes read, expected {} on read number {} (offset {:?}). Value read was {:?}",
                        length,
                        BUFFER_LEN,
                        self.read_val.get(),
                        self.log.next_read_entry_id(),
                        &buffer[0..length],
                    );
                }

                // Verify correct value was read.
                for i in 0..BUFFER_LEN {
                    if buffer[i] != i as u8 {
                        panic!(
                            "Expected {:?}, read {:?} on read number {} (offset {:?})",
                            i as u8,
                            &buffer[0..BUFFER_LEN],
                            self.read_val.get(),
                            self.log.next_read_entry_id(),
                        );
                    }
                }

                self.buffer.replace(buffer);
                self.read_val.set(self.read_val.get() + 1);
                self.op_start.set(false);
                self.wait();
            }
            _ => {
                panic!("Read failed unexpectedly!");
            }
        }
    }

    fn seek_done(&self, error: Result<(), ErrorCode>) {
        if error == Ok(()) {
            romtime::println!("Seeked");
            self.read_val
                .set(entry_id_to_test_value(self.log.next_read_entry_id()));
        } else {
            panic!("Seek failed: {:?}", error);
        }

        if self.state.get() == TestState::Operate {
            self.next_op();
        }
        self.run();
    }
}

impl<A: Alarm<'static>> LogWriteClient for LogTest<A> {
    fn append_done(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        self.buffer.replace(buffer);
        self.op_start.set(false);

        match error {
            Ok(()) => {
                if length != BUFFER_LEN {
                    panic!(
                        "Appended {} bytes, expected {} (write #{}, offset {:?})!",
                        length,
                        BUFFER_LEN,
                        self.write_val.get(),
                        self.log.log_end()
                    );
                }
                let expected_records_lost =
                    self.write_val.get() > entry_id_to_test_value(CIRCULAR_TEST_LOG.len());
                if records_lost && records_lost != expected_records_lost {
                    panic!("Append callback states records_lost = {}, expected {} (write #{}, offset {:?})!",
                           records_lost,
                           expected_records_lost,
                           self.write_val.get(),
                           self.log.log_end()
                    );
                }

                // Stop writing after `ENTRIES_PER_WRITE` entries have been written.
                if (self.write_val.get() + 1) % ENTRIES_PER_WRITE == 0 {
                    romtime::println!(
                        "WRITE DONE: READ OFFSET: {:?} / WRITE OFFSET: {:?}",
                        self.log.next_read_entry_id(),
                        self.log.log_end()
                    );
                    self.next_op();
                }

                self.write_val.set(self.write_val.get() + 1);
            }
            Err(ErrorCode::FAIL) => {
                assert_eq!(length, 0);
                assert!(!records_lost);
                romtime::println!("Append failed due to flash error, retrying...");
            }
            error => panic!("UNEXPECTED APPEND FAILURE: {:?}", error),
        }

        self.wait();
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        if error == Ok(()) {
            romtime::println!(
                "SYNC DONE: READ OFFSET: {:?} / WRITE OFFSET: {:?}",
                self.log.next_read_entry_id(),
                self.log.log_end()
            );
        } else {
            panic!("Sync failed: {:?}", error);
        }

        self.next_op();
        self.run();
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        match error {
            Ok(()) => {
                // Reset test state.
                // self.op_index.set(0);
                //self.op_start.set(true);
                self.read_val.set(0);
                self.write_val.set(0);

                // Make sure that flash has been erased.
                for i in 0..CIRCULAR_TEST_LOG.len() {
                    let byte = read_volatile_at!(&CIRCULAR_TEST_LOG, i);
                    assert_eq!(
                        byte, 0xFF,
                        "Log not fully erased at index {} byte {}",
                        i, byte
                    );
                }

                // Make sure that a read on an empty log fails normally.
                self.buffer.take().map(move |buffer| {
                    if let Err((error, original_buffer)) = self.log.read(buffer, BUFFER_LEN) {
                        self.buffer.replace(original_buffer);
                        match error {
                            ErrorCode::FAIL => (),
                            ErrorCode::BUSY => {
                                self.wait();
                            }
                            _ => panic!("Read on empty log did not fail as expected: {:?}", error),
                        }
                    } else {
                        panic!("Read on empty log succeeded! (it shouldn't)");
                    }
                });

                // Move to next operation.
                romtime::println!("Log Storage erased");
                //self.state.set(TestState::Operate);
                self.next_op();
                self.run();
            }
            Err(ErrorCode::BUSY) => {
                // Flash busy, try again.
                self.wait();
            }
            _ => {
                panic!("Erase failed: {:?}", error);
            }
        }
    }
}

impl<A: Alarm<'static>> AlarmClient for LogTest<A> {
    fn alarm(&self) {
        self.run();
    }
}

fn entry_id_to_test_value(entry_id: usize) -> u64 {
    let pages_written = entry_id / PAGE_SIZE;
    let entry_size = ENTRY_HEADER_SIZE + BUFFER_LEN;
    let entries_per_page = (PAGE_SIZE - PAGE_HEADER_SIZE) / entry_size;
    let entries_last_page = if entry_id % PAGE_SIZE >= PAGE_HEADER_SIZE {
        (entry_id % PAGE_SIZE - PAGE_HEADER_SIZE) / entry_size
    } else {
        0
    };
    (pages_written * entries_per_page + entries_last_page) as u64
}
