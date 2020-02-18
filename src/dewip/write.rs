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

//! Write [DEWIP](https://git.duniter.org/nodes/common/doc/blob/dewif/rfc/0013_Duniter_Encrypted_Wallet_Import_Format.md) file content

use crate::keys::ed25519::Ed25519KeyPair;
use arrayvec::ArrayVec;
use unwrap::unwrap;

/// Write dewip v1 file content with user passphrase
pub fn write_dewif_v1_content(keypair: &Ed25519KeyPair, passphrase: &str) -> String {
    let mut bytes = ArrayVec::<[u8; super::V1_BYTES_LEN]>::new();
    unwrap!(bytes.try_extend_from_slice(super::VERSION_V1));
    unwrap!(bytes.try_extend_from_slice(keypair.seed().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair.pubkey().as_ref()));

    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::encrypt::encrypt_n_blocks(&cipher, &mut bytes[4..], super::V1_AES_BLOCKS_COUNT);

    base64::encode(bytes.as_ref())
}

/// Write dewip v2 file content with user passphrase
pub fn write_dewif_v2_content(
    keypair1: &Ed25519KeyPair,
    keypair2: &Ed25519KeyPair,
    passphrase: &str,
) -> String {
    let mut bytes = ArrayVec::<[u8; super::V2_BYTES_LEN]>::new();
    unwrap!(bytes.try_extend_from_slice(super::VERSION_V2));
    unwrap!(bytes.try_extend_from_slice(keypair1.seed().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair1.pubkey().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair2.seed().as_ref()));
    unwrap!(bytes.try_extend_from_slice(keypair2.pubkey().as_ref()));

    let cipher = crate::aes256::new_cipher(super::gen_aes_seed(passphrase));
    crate::aes256::encrypt::encrypt_8_blocks(&cipher, &mut bytes[super::VERSION_BYTES..]);

    base64::encode(bytes.as_ref())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::keys::ed25519::KeyPairFromSeed32Generator;
    use crate::seeds::Seed32;

    #[test]
    fn write_dewif_v1() {
        let keypair = KeyPairFromSeed32Generator::generate(Seed32::new([0u8; 32]));

        let dewif_content = write_dewif_v1_content(&keypair, "toto");
        println!("{}", dewif_content);
        assert_eq!(
            "AAAAAb30ng3kI9QGMbR7TYCqPhS99J4N5CPUBjG0e02Aqj4UElionaHOt0kv+eaWgGSGkrP1LQfuwivuvg7+9n0gd18=",
            dewif_content
        )
    }
}
