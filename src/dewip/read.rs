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

//! Read [DEWIP](https://git.duniter.org/nodes/common/doc/blob/dewif/rfc/0013_Duniter_Encrypted_Wallet_Import_Format.md) file content

use crate::keys::ed25519::{KeyPairFromSeed32Generator, PublicKey, PUBKEY_SIZE_IN_BYTES};
use crate::keys::KeyPairEnum;
use crate::seeds::Seed32;
use arrayvec::ArrayVec;
use byteorder::ByteOrder;
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

const MAX_KEYPAIRS_COUNT: usize = 2;

/// Error when try to read DEWIP file content
#[derive(Clone, Debug, Error)]
pub enum DewipReadError {
    /// DEWIP file content is corrupted
    #[error("DEWIP file content is corrupted")]
    CorruptedContent,
    /// Invalid base 64 string
    #[error("Invalid base 64 string: {0}")]
    InvalidBase64Str(base64::DecodeError),
    /// Invalid format
    #[error("Invalid format")]
    InvalidFormat,
    /// Too short content
    #[error("Too short content")]
    TooShortContent,
    /// Too long content
    #[error("Too long content")]
    TooLongContent,
    /// Unsupported version
    #[error("Version {actual:?} is not supported. Supported versions: [1, 2].")]
    UnsupportedVersion {
        /// Actual version
        actual: u32,
    },
}

/// read dewip file content with user passphrase
pub fn read_dewip_file_content(
    file_content: &str,
    passphrase: &str,
) -> Result<impl IntoIterator<Item = KeyPairEnum>, DewipReadError> {
    let mut bytes = base64::decode(file_content).map_err(DewipReadError::InvalidBase64Str)?;

    if bytes.len() < 4 {
        return Err(DewipReadError::TooShortContent);
    }

    let version = byteorder::BigEndian::read_u32(&bytes[0..4]);

    match version {
        1 => Ok({
            let mut array_keypairs = ArrayVec::new();
            array_keypairs.push(read_dewip_v1(&mut bytes[4..], passphrase)?);
            array_keypairs
        }),
        2 => read_dewip_v2(&mut bytes[4..], passphrase),
        other_version => Err(DewipReadError::UnsupportedVersion {
            actual: other_version,
        }),
    }
}

fn read_dewip_v1(bytes: &mut [u8], passphrase: &str) -> Result<KeyPairEnum, DewipReadError> {
    match bytes.len() {
        len if len < super::V1_ENCRYPTED_BYTES_LEN => return Err(DewipReadError::TooShortContent),
        len if len > super::V1_ENCRYPTED_BYTES_LEN => return Err(DewipReadError::TooLongContent),
        _ => (),
    }

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::decrypt::decrypt_n_blocks(&cipher, bytes, super::V1_AES_BLOCKS_COUNT);

    // Get checked keypair
    bytes_to_checked_keypair(bytes)
}

fn read_dewip_v2(
    bytes: &mut [u8],
    passphrase: &str,
) -> Result<ArrayVec<[KeyPairEnum; MAX_KEYPAIRS_COUNT]>, DewipReadError> {
    let mut array_keypairs = ArrayVec::new();

    match bytes.len() {
        len if len < super::V2_ENCRYPTED_BYTES_LEN => return Err(DewipReadError::TooShortContent),
        len if len > super::V2_ENCRYPTED_BYTES_LEN => return Err(DewipReadError::TooLongContent),
        _ => (),
    }

    // Decrypt bytes
    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::decrypt::decrypt_8_blocks(&cipher, bytes);

    array_keypairs.push(bytes_to_checked_keypair(&bytes[..64])?);
    array_keypairs.push(bytes_to_checked_keypair(&bytes[64..])?);

    Ok(array_keypairs)
}

fn bytes_to_checked_keypair(bytes: &[u8]) -> Result<KeyPairEnum, DewipReadError> {
    // Wrap bytes into Seed32 and PublicKey
    let seed = Seed32::new(
        (&bytes[..PUBKEY_SIZE_IN_BYTES])
            .try_into()
            .expect("dev error"),
    );
    let expected_pubkey = PublicKey::try_from(&bytes[PUBKEY_SIZE_IN_BYTES..]).expect("dev error");

    // Get keypair
    let keypair = KeyPairFromSeed32Generator::generate(seed);

    // Check pubkey
    if keypair.pubkey() != expected_pubkey {
        Err(DewipReadError::CorruptedContent)
    } else {
        Ok(KeyPairEnum::Ed25519(keypair))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn read_unsupported_version() -> Result<(), ()> {
        if let Err(DewipReadError::UnsupportedVersion { .. }) = read_dewip_file_content(
            "ABAAAfKjMzOFfhwgypF3mAx0QDXyozMzhX4cIMqRd5gMdEA1WZwQjCR49iZDK2QhYfdTbPz9AGB01edt4iRSzdTp3c4=",
            "toto"
        ) {
            Ok(())
        } else {
            panic!("Read must be fail with error UnsupportedVersion.")
        }
    }

    #[test]
    fn read_too_short_content() -> Result<(), ()> {
        if let Err(DewipReadError::TooShortContent) = read_dewip_file_content("AAA", "toto") {
            Ok(())
        } else {
            panic!("Read must be fail with error TooShortContent.")
        }
    }

    #[test]
    fn tmp() {
        use crate::keys::{KeyPair, Signator};

        // Get DEWIP file content (Usually from disk)
        let dewip_file_content = "AAAAATHfJ3vTvEPcXm22NwhJtnNdGuSjikpSYIMgX96Z9xVT0y8GoIlBL1HaxaWpu0jVDfuwtCGSP9bu2pj6HGbuYVA=";

        // Get user passphrase for DEWIF decryption (from cli prompt or gui)
        let encryption_passphrase = "toto titi tata";

        // Read DEWIP file content
        // If the file content is correct, we get a key-pair iterator.
        let mut key_pair_iter = read_dewip_file_content(dewip_file_content, encryption_passphrase)
            .expect("invalid DEWIF file.")
            .into_iter();

        // Get first key-pair
        let key_pair = key_pair_iter
            .next()
            .expect("DEWIF file must contain at least one keypair");

        assert_eq!(
            "2cC9FrvRiN3uHHcd8S7wuureDS8CAmD5y4afEgSCLHtU",
            &key_pair.public_key().to_string()
        );

        // Generate signator
        // `Signator` is a non-copiable and non-clonable type,
        // so only generate it when you are in the scope where you effectively sign.
        let signator = key_pair.generate_signator();

        // Sign a message with keypair
        let sig = signator.sign(b"message");

        assert_eq!(
            "nCWl7jtCa/nCMKKnk2NJN7daVxd/ER+e1wsFbofdh/pUvDuHxFaa7S5eUMGiqPTJ4uJQOvrmF/BOfOsYIoI2Bg==",
            &sig.to_string()
        )
    }
}
