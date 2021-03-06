//  Copyright (C) 2020 Éloïs SANCHEZ.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Manage random generation.

use byteorder::ByteOrder;
use ring::rand::{generate, SystemRandom};

/// An error with absolutely no details.
///
/// *dup-crypto* uses this unit type as the error type in most of its results
/// because (a) usually the specific reasons for a failure are obvious or are
/// not useful to know, and/or (b) providing more details about a failure might
/// provide a dangerous side channel, and/or (c) it greatly simplifies the
/// error handling logic.
///
/// Experience with using and implementing other crypto libraries like has
/// shown that sophisticated error reporting facilities often cause significant
/// bugs themselves, both within the crypto library and within users of the
/// crypto library. This approach attempts to minimize complexity in the hopes
/// of avoiding such problems. In some cases, this approach may be too extreme,
/// and it may be important for an operation to provide some details about the
/// cause of a failure. Users of *dup-crypto* are encouraged to report such cases so
/// that they can be addressed individually.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct UnspecifiedRandError;

/// Secure random bytes generator
pub fn gen_random_bytes(buffer: &mut [u8]) -> Result<(), UnspecifiedRandError> {
    let mut cursor = 0;
    let mut remaining_len = buffer.len();

    while remaining_len >= 32 {
        buffer[cursor..(cursor + 32)].copy_from_slice(&gen_32_bytes()?[..]);
        cursor += 32;
        remaining_len -= 32;
    }
    while remaining_len >= 16 {
        buffer[cursor..(cursor + 16)].copy_from_slice(&gen_16_bytes()?[..]);
        cursor += 16;
        remaining_len -= 16;
    }
    if remaining_len > 0 {
        buffer[cursor..].copy_from_slice(&gen_16_bytes()?[..remaining_len]);
    }

    Ok(())
}

#[inline]
/// Generate random u32
pub fn gen_u32() -> Result<u32, UnspecifiedRandError> {
    let random_bytes =
        generate::<[u8; 4]>(&SystemRandom::new()).map_err(|_| UnspecifiedRandError)?;

    Ok(byteorder::BigEndian::read_u32(&random_bytes.expose()))
}

#[inline]
/// Generate random 16 bytes
pub fn gen_16_bytes() -> Result<[u8; 16], UnspecifiedRandError> {
    let random_bytes =
        generate::<[u8; 16]>(&SystemRandom::new()).map_err(|_| UnspecifiedRandError)?;

    Ok(random_bytes.expose())
}

#[inline]
/// Generate random 32 bytes
pub fn gen_32_bytes() -> Result<[u8; 32], UnspecifiedRandError> {
    let random_bytes =
        generate::<[u8; 32]>(&SystemRandom::new()).map_err(|_| UnspecifiedRandError)?;

    Ok(random_bytes.expose())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_gen_u32() -> Result<(), UnspecifiedRandError> {
        assert_ne!(gen_u32()?, gen_u32()?);
        Ok(())
    }

    #[test]
    fn test_gen_random_bytes() -> Result<(), UnspecifiedRandError> {
        let mut buffer = [0u8; 51];
        gen_random_bytes(buffer.as_mut())?;
        let mut buffer = [0u8; 48];
        gen_random_bytes(buffer.as_mut())?;
        Ok(())
    }
}
