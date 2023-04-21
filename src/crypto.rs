use ring::{
    aead::{Aad, LessSafeKey, Nonce, NonceSequence, UnboundKey, AES_256_GCM},
    agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    hkdf::{Salt, HKDF_SHA256},
    rand::SecureRandom,
};

use crate::schema::{OpenBox, SealedBox, Vault};

struct OpenBoxPublicKey(UnparsedPublicKey<Vec<u8>>);

impl From<OpenBox> for OpenBoxPublicKey {
    fn from(value: OpenBox) -> Self {
        OpenBoxPublicKey(UnparsedPublicKey::new(&X25519, value.public_key))
    }
}

struct NonceGen<'a>(&'a dyn SecureRandom);

impl NonceSequence for NonceGen<'_> {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let mut nonce_bytes = [0; 12];
        self.0.fill(&mut nonce_bytes)?;
        Ok(Nonce::assume_unique_for_key(nonce_bytes))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to read from the provided CSPRNG")]
    Csprng,
    #[error("Error generating the public key from the private key")]
    GeneratingPubKey,
    #[error("Could not parse the Peer's public key as X25519")]
    ParsingPeerKey,
    #[error("Could not expand the computed shared secret into a key")]
    KeyExpansion,
    #[error("Failed to seal the vault with the computed symmetric key")]
    Sealing,
    #[error("Failed to open the sealed vault with the computed symmetric key")]
    Opening,
    #[error("Failed to decode the vault json: {0}")]
    Decoding(serde_json::Error),
}

pub struct LocalKeyPair(EphemeralPrivateKey);

impl LocalKeyPair {
    /// Return None when theres an issue comunicating with the `SecureRandom` elements.
    pub fn new(rng: &dyn SecureRandom) -> Option<Self> {
        EphemeralPrivateKey::generate(&X25519, rng)
            .ok()
            .map(LocalKeyPair)
    }

    pub fn to_open_box(&self) -> Option<OpenBox> {
        self.0.compute_public_key().ok().map(|pub_key| OpenBox {
            public_key: pub_key.as_ref().to_vec(),
        })
    }

    pub fn seal(
        self,
        open_box: OpenBox,
        vault: Vault,
        rng: &dyn SecureRandom,
    ) -> Result<SealedBox, Error> {
        let mut salt_bytes = [0; 32];
        rng.fill(&mut salt_bytes).map_err(|_| Error::Csprng)?;
        let salt = Salt::new(HKDF_SHA256, &salt_bytes);
        let public_key = self
            .0
            .compute_public_key()
            .map_err(|_| Error::GeneratingPubKey)?;
        let peer_key = OpenBoxPublicKey::from(open_box);

        let mut nonce_bytes = [0; 12];
        rng.fill(&mut nonce_bytes).map_err(|_| Error::Csprng)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let key = agree_ephemeral(
            self.0,
            &peer_key.0,
            Error::ParsingPeerKey,
            |shared_secret| hkdf(shared_secret, salt),
        )?;

        let mut encoded_vault = serde_json::to_vec(&vault).expect("This is a schema error");

        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut encoded_vault)
            .map_err(|_| Error::Sealing)?;

        Ok(SealedBox {
            public_key: public_key.as_ref().to_vec(),
            encrypted_vault: encoded_vault,
            encryption_nonce: nonce_bytes.into(),
            authentication_tag: tag.as_ref().to_vec(),
            key_derivation_salt: salt_bytes.to_vec(),
        })
    }

    pub fn open(self, sealed: SealedBox) -> Result<Vault, Error> {
        let salt = Salt::new(HKDF_SHA256, &sealed.key_derivation_salt);
        let peer_key = UnparsedPublicKey::new(&X25519, sealed.public_key);

        let nonce = Nonce::try_assume_unique_for_key(&sealed.encryption_nonce)
            .expect("Garanteed to be 12 due to split above");

        let key = agree_ephemeral(self.0, &peer_key, Error::KeyExpansion, |shared_secret| {
            hkdf(shared_secret, salt)
        })?;
        let mut in_out: Vec<u8> = sealed
            .encrypted_vault
            .into_iter()
            .chain(sealed.authentication_tag)
            .collect();

        let decrypted_vault = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| Error::Opening)?;

        serde_json::from_slice(decrypted_vault).map_err(Error::Decoding)
    }
}

fn hkdf(shared_secret: &[u8], salt: Salt) -> Result<LessSafeKey, Error> {
    let prk = salt.extract(shared_secret);
    let okm = prk
        .expand(&[], &AES_256_GCM)
        .map_err(|_| Error::KeyExpansion)?;
    let unbound_key = UnboundKey::from(okm);
    Ok(LessSafeKey::new(unbound_key))
}

#[cfg(test)]
pub fn mock_vault() -> Vault {
    Vault {
        passkeys: vec![
            crate::schema::Passkey {
                credential_id: "AFTS_7DYRxzc0MnH6novvg".into(),
                relying_party_id: "future.1password.com".into(),
                relying_party_name: "1Password's future".into(),
                user_handle: "qj2Mza8VpfeyGUQ7DsjrNA".into(),
                user_display_name: "wendy@1password.com".into(),
                counter: "0".into(),
                key_algorithm: "-7".into(),
                private_key: vec![
                    218, 32, 172, 102, 165, 240, 198, 99, 5, 244, 84, 124, 112, 8, 78, 139, 17,
                    171, 147, 13, 27, 190, 226, 169, 8, 68, 234, 22, 250, 62, 22, 67,
                ],
            },
            crate::schema::Passkey {
                credential_id: "Y4MwpGtlC5WtHHf2bGZ5JhWvKq8nyJd8C2hUyANZfCo".into(),
                relying_party_id: "ebay.com".into(),
                relying_party_name: "Ebay".into(),
                user_handle: "AyTX4-DemFSn19IWC9EDd_AvDFsUUi4vSd6EhiwoaFg".into(),
                user_display_name: "wendy.appleseed@gmail.com".into(),
                counter: "42".into(),
                key_algorithm: "-7".into(),
                private_key: vec![
                    202, 71, 46, 146, 44, 45, 13, 148, 133, 153, 77, 20, 30, 227, 113, 91, 58, 245,
                    139, 188, 126, 95, 171, 140, 5, 119, 13, 69, 229, 100, 84, 142,
                ],
            },
        ],
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn round_trip_sanity_check() {
        let rng = ring::rand::SystemRandom::new();
        let importing = LocalKeyPair::new(&rng).unwrap();
        let open_box = importing.to_open_box().unwrap();
        let vault = mock_vault();
        let encoded_vault = serde_json::to_vec(&vault).unwrap();

        let exporting = LocalKeyPair::new(&rng).unwrap();
        let sealed_box = exporting
            .seal(open_box, vault.clone(), &rng)
            .expect("failed to seal vault");

        assert!(!sealed_box.encrypted_vault.starts_with(&encoded_vault));

        let decrypted_vault = importing
            .open(sealed_box)
            .expect("Could not decrypt sealed vault");

        assert_eq!(decrypted_vault, vault);
    }
}
