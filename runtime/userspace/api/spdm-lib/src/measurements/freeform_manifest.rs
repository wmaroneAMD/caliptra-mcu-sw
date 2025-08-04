// Licensed under the Apache-2.0 license

use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::protocol::{algorithms::AsymAlgo, SHA384_HASH_SIZE};
use crate::platform::hash::SpdmHash;
use crate::platform::evidence::{SpdmEvidence, SpdmEvidenceError, PCR_QUOTE_BUFFER_SIZE};
use libapi_caliptra::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
use zerocopy::IntoBytes;

const MAX_MEASUREMENT_RECORD_SIZE: usize =
    PCR_QUOTE_BUFFER_SIZE + size_of::<DmtfMeasurementBlockMetadata>();

/// Structure to hold the Freeform manifest data
/// The measurement record consists of 1 measurement block whose value is the PCR quote from Caliptra.
/// The strucuture of the measurement record is as follows:
/// _________________________________________________________________________________________________
/// | - index: SPDM_MEASUREMENT_MANIFEST_INDEX                                                      |
/// | - MeasurementSpecification: 01h (DMTF)                                                        |
/// |           - DMTFSpecMeasurementValueType[6:0]: 04h (Freeform Manifest)                        |
/// |           - DMTFSpecMeasurementValueType[7]  : 1b  (raw bit-stream)                           |
/// | - MeasurementSize: 2 bytes (size of the PCR Quote in DMTF measurement specification format)   |
/// | - MeasurementBlock: measurement block (PCR Quote in DMTF measurement specification format)    |
/// ________________________________________________________________________________________________|
pub struct FreeformManifest {
    measurement_record: [u8; MAX_MEASUREMENT_RECORD_SIZE],
    data_size: usize,
}

impl Default for FreeformManifest {
    fn default() -> Self {
        FreeformManifest {
            measurement_record: [0; MAX_MEASUREMENT_RECORD_SIZE],
            data_size: 0,
        }
    }
}

impl From<SpdmEvidenceError> for MeasurementsError {
    fn from(err: SpdmEvidenceError) -> Self {
        match err {
            _ => MeasurementsError::InvalidIndex, // fallback for unmapped variants
        }
    }
}

#[allow(dead_code)]
impl FreeformManifest {
    pub(crate) fn total_measurement_count(&self) -> usize {
        1
    }

    pub(crate) async fn measurement_block_size(
        &mut self,
        evidence: &dyn SpdmEvidence,
        asym_algo: AsymAlgo,
        index: u8,
        _raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.data_size == 0 {
                self.refresh_measurement_record(evidence, asym_algo).await?;
            }
            Ok(self.data_size)
        } else {
            Err(MeasurementsError::InvalidIndex)
        }
    }

    pub(crate) async fn measurement_block(
        &mut self,
        evidence: &dyn SpdmEvidence,
        asym_algo: AsymAlgo,
        index: u8,
        _raw_bit_stream: bool,
        offset: usize,
        measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<usize> {
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.data_size == 0 {
                self.refresh_measurement_record(evidence, asym_algo).await?;
            }
            if offset >= self.data_size {
                return Err(MeasurementsError::InvalidOffset);
            }

            let end = self
                .measurement_record
                .len()
                .min(offset + measurement_chunk.len());
            let chunk_size = end - offset;
            measurement_chunk[..chunk_size].copy_from_slice(&self.measurement_record[offset..end]);

            Ok(chunk_size)
        } else {
            Err(MeasurementsError::InvalidIndex)
        }
    }

    pub(crate) async fn measurement_summary_hash(
        &mut self,
        evidence: &dyn SpdmEvidence,
        hash_ctx: &mut dyn SpdmHash,
        asym_algo: AsymAlgo,
        _measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
        self.refresh_measurement_record(evidence, asym_algo).await?;

        let mut offset = 0;

        while offset < self.measurement_record.len() {
            let chunk_size = MAX_CRYPTO_MBOX_DATA_SIZE.min(self.measurement_record.len() - offset);

            if offset == 0 {
                hash_ctx
                    .init(
                        hash_ctx.algo(),
                        Some(&self.measurement_record[..chunk_size]),
                    )
                    .await
                    .map_err(|e| MeasurementsError::Hash(e))?;
            } else {
                let chunk = &self.measurement_record[offset..offset + chunk_size];
                hash_ctx
                    .update(chunk)
                    .await
                    .map_err(|e| MeasurementsError::Hash(e))?;
            }

            offset += chunk_size;
        }

        hash_ctx
            .finalize(hash)
            .await
            .map_err(|e| MeasurementsError::Hash(e))
    }

    async fn refresh_measurement_record(&mut self, evidence: &dyn SpdmEvidence, asym_algo: AsymAlgo) -> MeasurementsResult<()> {
        let with_pqc_sig = asym_algo != AsymAlgo::EccP384;
        let measurement_record = &mut self.measurement_record;
        let measurement_value_size = evidence.pcr_quote_size(with_pqc_sig)?;
        measurement_record.fill(0);
        let metadata = DmtfMeasurementBlockMetadata::new(
            SPDM_MEASUREMENT_MANIFEST_INDEX,
            measurement_value_size as u16,
            false,
            MeasurementValueType::FreeformManifest,
        )?;

        const METADATA_SIZE: usize = size_of::<DmtfMeasurementBlockMetadata>();

        measurement_record[0..METADATA_SIZE].copy_from_slice(metadata.as_bytes());

        let quote_slice =
            &mut measurement_record[METADATA_SIZE..METADATA_SIZE + PCR_QUOTE_BUFFER_SIZE];

        let copied_len = evidence.pcr_quote(quote_slice, with_pqc_sig)
                                            .await
                                            .map_err(|e| MeasurementsError::Evidence(e))?;
        if copied_len != measurement_value_size {
            return Err(MeasurementsError::MeasurementSizeMismatch);
        }

        self.data_size = METADATA_SIZE + measurement_value_size;

        Ok(())
    }
}
