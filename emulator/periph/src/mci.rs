// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{ActionHandle, Clock, ReadWriteRegister, Timer, TimerAction};
use caliptra_emu_types::RvData;
use emulator_registers_generated::mci::MciPeripheral;
use registers_generated::mci::bits::{
    Error0IntrT, WdtStatus, WdtTimer1Ctrl, WdtTimer1En, WdtTimer2Ctrl, WdtTimer2En,
};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub struct Mci {
    cptra_wdt_timer1_en: ReadWriteRegister<u32, WdtTimer1En::Register>,
    cptra_wdt_timer1_ctrl: ReadWriteRegister<u32, WdtTimer1Ctrl::Register>,
    cptra_wdt_timer1_timeout_period: [u32; 2],

    cptra_wdt_timer2_en: ReadWriteRegister<u32, WdtTimer2En::Register>,
    cptra_wdt_timer2_ctrl: ReadWriteRegister<u32, WdtTimer2Ctrl::Register>,
    cptra_wdt_timer2_timeout_period: [u32; 2],

    cptra_wdt_status: ReadWriteRegister<u32, WdtStatus::Register>,
    cptra_wdt_cfg: [u32; 2],

    error0_internal_intr_r: ReadWriteRegister<u32, Error0IntrT::Register>,

    timer: Timer,
    op_wdt_timer1_expired_action: Option<ActionHandle>,
    op_wdt_timer2_expired_action: Option<ActionHandle>,
}

impl Mci {
    pub const CPTRA_WDT_TIMER1_EN_START: u32 = 0xb0;
    pub const CPTRA_WDT_TIMER1_CTRL_START: u32 = 0xb4;
    pub const CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START: u32 = 0xb8;
    pub const CPTRA_WDT_TIMER2_EN_START: u32 = 0xc0;
    pub const CPTRA_WDT_TIMER2_CTRL_START: u32 = 0xc4;
    pub const CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START: u32 = 0xc8;
    pub const CPTRA_WDT_STATUS_START: u32 = 0xd0;

    pub fn new(clock: &Clock) -> Self {
        Self {
            cptra_wdt_timer1_en: ReadWriteRegister::new(0),
            cptra_wdt_timer1_ctrl: ReadWriteRegister::new(0),
            cptra_wdt_timer1_timeout_period: [0xffff_ffff; 2],
            cptra_wdt_timer2_en: ReadWriteRegister::new(0),
            cptra_wdt_timer2_ctrl: ReadWriteRegister::new(0),
            cptra_wdt_timer2_timeout_period: [0xffff_ffff; 2],
            cptra_wdt_status: ReadWriteRegister::new(0),
            cptra_wdt_cfg: [0x0; 2],
            error0_internal_intr_r: ReadWriteRegister::new(0),
            timer: Timer::new(clock),
            op_wdt_timer1_expired_action: None,
            op_wdt_timer2_expired_action: None,
        }
    }
}

impl MciPeripheral for Mci {
    fn read_mci_reg_wdt_timer1_en(&mut self) -> ReadWriteRegister<u32, WdtTimer1En::Register> {
        ReadWriteRegister::new(self.cptra_wdt_timer1_en.reg.get())
    }

    fn read_mci_reg_wdt_timer1_ctrl(&mut self) -> ReadWriteRegister<u32, WdtTimer1Ctrl::Register> {
        ReadWriteRegister::new(self.cptra_wdt_timer1_ctrl.reg.get())
    }

    fn read_mci_reg_wdt_timer1_timeout_period(&mut self, index: usize) -> RvData {
        self.cptra_wdt_timer1_timeout_period[index]
    }

    fn read_mci_reg_wdt_timer2_en(&mut self) -> ReadWriteRegister<u32, WdtTimer2En::Register> {
        ReadWriteRegister::new(self.cptra_wdt_timer2_en.reg.get())
    }

    fn read_mci_reg_wdt_timer2_ctrl(&mut self) -> ReadWriteRegister<u32, WdtTimer2Ctrl::Register> {
        ReadWriteRegister::new(self.cptra_wdt_timer2_ctrl.reg.get())
    }

    fn read_mci_reg_wdt_timer2_timeout_period(&mut self, index: usize) -> RvData {
        self.cptra_wdt_timer2_timeout_period[index]
    }

    fn read_mci_reg_wdt_status(&mut self) -> ReadWriteRegister<u32, WdtStatus::Register> {
        ReadWriteRegister::new(self.cptra_wdt_status.reg.get())
    }

    fn read_mci_reg_wdt_cfg(&mut self, index: usize) -> RvData {
        self.cptra_wdt_cfg[index]
    }

    fn write_mci_reg_wdt_timer1_en(&mut self, val: ReadWriteRegister<u32, WdtTimer1En::Register>) {
        self.cptra_wdt_timer1_en.reg.set(val.reg.get());

        self.cptra_wdt_status
            .reg
            .modify(WdtStatus::T1Timeout::CLEAR);

        // If timer is enabled, schedule a callback on expiry.
        if self.cptra_wdt_timer1_en.reg.is_set(WdtTimer1En::Timer1En) {
            let timer_period: u64 = (self.cptra_wdt_timer1_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer1_timeout_period[0] as u64;

            self.op_wdt_timer1_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        } else {
            self.op_wdt_timer1_expired_action = None;
        }
    }

    fn write_mci_reg_wdt_timer1_ctrl(
        &mut self,
        val: ReadWriteRegister<u32, WdtTimer1Ctrl::Register>,
    ) {
        self.cptra_wdt_timer1_ctrl.reg.set(val.reg.get());

        if self.cptra_wdt_timer1_en.reg.is_set(WdtTimer1En::Timer1En)
            && self
                .cptra_wdt_timer1_ctrl
                .reg
                .is_set(WdtTimer1Ctrl::Timer1Restart)
        {
            self.cptra_wdt_status
                .reg
                .modify(WdtStatus::T1Timeout::CLEAR);

            let timer_period: u64 = (self.cptra_wdt_timer1_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer1_timeout_period[0] as u64;

            self.op_wdt_timer1_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        }
    }

    fn write_mci_reg_wdt_timer1_timeout_period(&mut self, val: RvData, index: usize) {
        self.cptra_wdt_timer1_timeout_period[index] = val;
    }

    fn write_mci_reg_wdt_timer2_en(&mut self, val: ReadWriteRegister<u32, WdtTimer2En::Register>) {
        self.cptra_wdt_timer2_en.reg.set(val.reg.get());

        self.cptra_wdt_status
            .reg
            .modify(WdtStatus::T2Timeout::CLEAR);

        // If timer is enabled, schedule a callback on expiry.
        if self.cptra_wdt_timer2_en.reg.is_set(WdtTimer2En::Timer2En) {
            let timer_period: u64 = (self.cptra_wdt_timer2_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer2_timeout_period[0] as u64;

            self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        } else {
            self.op_wdt_timer2_expired_action = None;
        }
    }

    fn write_mci_reg_wdt_timer2_ctrl(
        &mut self,
        val: ReadWriteRegister<u32, WdtTimer2Ctrl::Register>,
    ) {
        self.cptra_wdt_timer2_ctrl.reg.set(val.reg.get());

        if self.cptra_wdt_timer2_en.reg.is_set(WdtTimer2En::Timer2En)
            && self
                .cptra_wdt_timer2_ctrl
                .reg
                .is_set(WdtTimer2Ctrl::Timer2Restart)
        {
            self.cptra_wdt_status
                .reg
                .modify(WdtStatus::T2Timeout::CLEAR);

            let timer_period: u64 = (self.cptra_wdt_timer2_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer2_timeout_period[0] as u64;

            self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        }
    }

    fn write_mci_reg_wdt_timer2_timeout_period(&mut self, val: RvData, index: usize) {
        self.cptra_wdt_timer2_timeout_period[index] = val;
    }

    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_wdt_timer1_expired_action) {
            self.cptra_wdt_status.reg.modify(WdtStatus::T1Timeout::SET);
            self.error0_internal_intr_r
                .reg
                .modify(Error0IntrT::ErrorWdtTimer1TimeoutSts::SET);

            // If WDT2 is disabled, schedule a callback on it's expiry.
            if !self.cptra_wdt_timer2_en.reg.is_set(WdtTimer2En::Timer2En) {
                self.cptra_wdt_status
                    .reg
                    .modify(WdtStatus::T2Timeout::CLEAR);
                self.error0_internal_intr_r
                    .reg
                    .modify(Error0IntrT::ErrorWdtTimer2TimeoutSts::CLEAR);

                let timer_period: u64 = (self.cptra_wdt_timer2_timeout_period[1] as u64) << 32
                    | self.cptra_wdt_timer2_timeout_period[0] as u64;

                self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
            }
        }

        if self.timer.fired(&mut self.op_wdt_timer2_expired_action) {
            self.cptra_wdt_status.reg.modify(WdtStatus::T2Timeout::SET);

            // If WDT2 was not scheduled due to WDT1 expiry (i.e WDT2 is disabled), schedule an NMI.
            // Else, do nothing.
            if self.cptra_wdt_timer2_en.reg.is_set(WdtTimer2En::Timer2En) {
                self.error0_internal_intr_r
                    .reg
                    .modify(Error0IntrT::ErrorWdtTimer2TimeoutSts::SET);
                return;
            }

            // Raise an NMI. NMIs don't fire immediately; a couple instructions is a fairly typicaly delay on VeeR.
            const NMI_DELAY: u64 = 2;

            // From RISC-V_VeeR_EL2_PRM.pdf
            const NMI_CAUSE_WDT_TIMEOUT: u32 = 0x0000_0000; // [TODO] Need correct mcause value.

            self.timer.schedule_action_in(
                NMI_DELAY,
                TimerAction::Nmi {
                    mcause: NMI_CAUSE_WDT_TIMEOUT,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::mci::MciBus;
    use tock_registers::registers::InMemoryRegister;

    fn next_action(clock: &Clock) -> Option<TimerAction> {
        let mut actions = clock.increment(4);
        match actions.len() {
            0 => None,
            1 => actions.drain().next(),
            _ => panic!("More than one action scheduled; unexpected"),
        }
    }

    #[test]
    fn test_wdt() {
        let clock = Clock::new();

        let mci_reg: Mci = Mci::new(&clock);
        let mut mci_bus = MciBus {
            periph: Box::new(mci_reg),
        };
        mci_bus
            .write(RvSize::Word, Mci::CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START, 4)
            .unwrap();
        mci_bus
            .write(
                RvSize::Word,
                Mci::CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START + 4,
                0,
            )
            .unwrap();
        mci_bus
            .write(RvSize::Word, Mci::CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START, 1)
            .unwrap();
        mci_bus
            .write(
                RvSize::Word,
                Mci::CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START + 4,
                0,
            )
            .unwrap();
        mci_bus
            .write(RvSize::Word, Mci::CPTRA_WDT_TIMER1_EN_START, 1)
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, WdtStatus::Register>::new(
                mci_bus
                    .read(RvSize::Word, Mci::CPTRA_WDT_STATUS_START)
                    .unwrap(),
            );
            if status.is_set(WdtStatus::T2Timeout) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut mci_bus);
        }

        assert_eq!(
            next_action(&clock),
            Some(TimerAction::Nmi {
                mcause: 0x0000_0000,
            })
        );
    }
}
