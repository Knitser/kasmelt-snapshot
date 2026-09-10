//! Six-field state codec for the pinned snapshot token.
//! Adapted from Kascov's kcc0020 module; see NOTICE.md.

pub const OWNER_P2PK_SCHNORR: u8 = 0x00;
pub const OWNER_P2SH: u8 = 0x03;
pub const OWNER_COVENANT_ID: u8 = 0x04;
pub const STATE_LEN: usize = 112;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub amount: i64,
    pub owner: [u8; 32],
    pub owner_scheme: u8,
    pub borrow_scheme: u8,
    pub borrow_guard: [u8; 32],
    pub extension_commitment: [u8; 32],
}

impl State {
    pub fn encode(&self) -> Option<[u8; STATE_LEN]> {
        if self.amount < 0 {
            return None;
        }
        let mut out = [0u8; STATE_LEN];
        for (offset, opcode) in [(0, 8), (9, 32), (42, 1), (44, 1), (46, 32), (79, 32)] {
            out[offset] = opcode;
        }
        out[1..9].copy_from_slice(&self.amount.to_le_bytes());
        out[10..42].copy_from_slice(&self.owner);
        out[43] = self.owner_scheme;
        out[45] = self.borrow_scheme;
        out[47..79].copy_from_slice(&self.borrow_guard);
        out[80..112].copy_from_slice(&self.extension_commitment);
        Some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != STATE_LEN || bytes[8] & 0x80 != 0 {
            return None;
        }
        for (offset, opcode) in [(0, 8), (9, 32), (42, 1), (44, 1), (46, 32), (79, 32)] {
            if bytes[offset] != opcode {
                return None;
            }
        }
        Some(Self {
            amount: i64::from_le_bytes(bytes[1..9].try_into().ok()?),
            owner: bytes[10..42].try_into().ok()?,
            owner_scheme: bytes[43],
            borrow_scheme: bytes[45],
            borrow_guard: bytes[47..79].try_into().ok()?,
            extension_commitment: bytes[80..112].try_into().ok()?,
        })
    }
}

/// Candidate offsets only; callers must authenticate the complete program.
pub fn locate_state_cuts(program: &[u8]) -> Vec<usize> {
    if program.len() < STATE_LEN {
        return vec![];
    }
    (0..=program.len() - STATE_LEN)
        .filter(|&offset| State::decode(&program[offset..offset + STATE_LEN]).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_rejects_noncanonical_state_and_preserves_amount_limits() {
        for amount in [0, 1, 127, 128, i64::MAX] {
            let state = State {
                amount,
                owner: [3; 32],
                owner_scheme: OWNER_P2SH,
                borrow_scheme: 0,
                borrow_guard: [0; 32],
                extension_commitment: [5; 32],
            };
            let bytes = state.encode().unwrap();
            assert_eq!(State::decode(&bytes), Some(state));
            let mut negative_zero = bytes;
            negative_zero[8] |= 0x80;
            assert!(State::decode(&negative_zero).is_none());
            for offset in [0, 9, 42, 44, 46, 79] {
                let mut malformed = bytes;
                malformed[offset] ^= 1;
                assert!(State::decode(&malformed).is_none());
            }
            assert!(State::decode(&bytes[..111]).is_none());
            assert!(State {
                amount: -1,
                ..state
            }
            .encode()
            .is_none());
        }
    }
}
