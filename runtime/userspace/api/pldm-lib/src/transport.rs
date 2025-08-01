// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mctp::{Mctp, MessageInfo};
use pldm_common::util::mctp_transport::{
    MctpCommonHeader, MCTP_COMMON_HEADER_OFFSET, MCTP_PLDM_MSG_TYPE,
};

pub enum PldmTransportType {
    Mctp,
}

#[derive(Debug)]
pub enum TransportError {
    DriverError,
    BufferTooSmall,
    UnexpectedMessageType,
    ReceiveError,
    SendError,
    ResponseNotExpected,
    NoRequestInFlight,
}

pub struct MctpTransport {
    mctp: Mctp,
    cur_resp_ctx: Option<MessageInfo>,
    cur_req_ctx: Option<MessageInfo>,
}

impl MctpTransport {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mctp: Mctp::new(drv_num),
            cur_resp_ctx: None,
            cur_req_ctx: None,
        }
    }

    pub async fn send_request(&mut self, dest_eid: u8, req: &[u8]) -> Result<(), TransportError> {
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        let tag = self
            .mctp
            .send_request(dest_eid, req)
            .await
            .map_err(|_| TransportError::SendError)?;

        self.cur_req_ctx = Some(MessageInfo { eid: dest_eid, tag });

        Ok(())
    }

    pub async fn receive_response(&mut self, rsp: &mut [u8]) -> Result<(), TransportError> {
        // Reset msg buffer
        rsp.fill(0);
        let (rsp_len, _msg_info) = if let Some(msg_info) = &self.cur_req_ctx {
            self.mctp
                .receive_response(rsp, msg_info.tag, msg_info.eid)
                .await
                .map_err(|_| TransportError::ReceiveError)
        } else {
            Err(TransportError::ResponseNotExpected)
        }?;

        if rsp_len == 0 {
            Err(TransportError::BufferTooSmall)?;
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(rsp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        self.cur_req_ctx = None;
        Ok(())
    }

    pub async fn receive_request(&mut self, req: &mut [u8]) -> Result<(), TransportError> {
        // Reset msg buffer
        req.fill(0);
        let (req_len, msg_info) = self
            .mctp
            .receive_request(req)
            .await
            .map_err(|_| TransportError::ReceiveError)?;

        if req_len == 0 {
            Err(TransportError::BufferTooSmall)?;
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        self.cur_resp_ctx = Some(msg_info);

        Ok(())
    }

    pub async fn send_response(&mut self, resp: &[u8]) -> Result<(), TransportError> {
        let mctp_hdr = MctpCommonHeader(resp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(TransportError::UnexpectedMessageType)?;
        }

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(resp, msg_info)
                .await
                .map_err(|_| TransportError::SendError)?
        } else {
            Err(TransportError::NoRequestInFlight)?;
        }

        self.cur_resp_ctx = None;

        Ok(())
    }
}
