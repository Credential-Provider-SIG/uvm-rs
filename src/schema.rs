use data_encoding::{Specification, BASE64, BASE64URL, BASE64_NOPAD};
use serde::{Deserialize, Serialize};
use tabled::Tabled;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenBox {
    #[serde(with = "base64")]
    pub public_key: Vec<u8>,
}

pub trait ToFileExtension {
    const FILE_EXT: &'static str;
}
impl ToFileExtension for OpenBox {
    const FILE_EXT: &'static str = "openbox";
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SealedBox {
    #[serde(with = "base64")]
    pub public_key: Vec<u8>,

    #[serde(with = "base64")]
    pub encrypted_vault: Vec<u8>,

    #[serde(with = "base64")]
    pub key_derivation_salt: Vec<u8>,

    #[serde(with = "base64")]
    pub encryption_nonce: Vec<u8>,

    #[serde(with = "base64")]
    pub authentication_tag: Vec<u8>,
}

impl ToFileExtension for SealedBox {
    const FILE_EXT: &'static str = "sealedbox";
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Vault {
    pub passkeys: Vec<Passkey>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Tabled)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    #[tabled(skip)]
    pub credential_id: String,

    #[tabled(skip)]
    pub relying_party_id: String,

    #[tabled(rename = "Website")]
    pub relying_party_name: String,

    #[tabled(skip)]
    pub user_handle: String,

    #[tabled(rename = "Username")]
    pub user_display_name: String,

    // Shouldn't this be a Uint?
    #[tabled(skip)]
    pub counter: String,

    #[tabled(skip)]
    pub key_algorithm: String,

    #[serde(with = "base64")]
    #[tabled(skip)]
    pub private_key: Vec<u8>,
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("credential_id", &self.credential_id)
            .field("relying_party_id", &self.relying_party_id)
            .field("relying_party_name", &self.relying_party_name)
            .field("user_handle", &self.user_handle)
            .field("user_display_name", &self.user_display_name)
            .field("counter", &self.counter)
            .field("key_algorithm", &self.key_algorithm)
            .field("private_key", &"<Redacted>")
            .finish()
    }
}

mod base64 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    use super::{base64, try_from_base64, try_from_base64url};

    pub fn serialize<S>(input: &[u8], ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&base64(input))
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(de).and_then(|encoded| {
            try_from_base64(&encoded)
                .or_else(|| try_from_base64url(&encoded))
                .ok_or_else(|| D::Error::custom("could not decode as base64 or base64url"))
        })
    }
}

/// Convert bytes to base64 without padding
pub fn base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Try parsing from base64 with or without padding
pub(crate) fn try_from_base64(input: &str) -> Option<Vec<u8>> {
    let padding = BASE64.specification().padding.unwrap();
    let sane_string = input.trim_end_matches(padding);
    BASE64_NOPAD.decode(sane_string.as_bytes()).ok()
}

/// Try parsing from base64url with or without padding
pub fn try_from_base64url(input: &str) -> Option<Vec<u8>> {
    let specs = BASE64URL.specification();
    let padding = specs.padding.unwrap();
    let specs = Specification {
        check_trailing_bits: false,
        padding: None,
        ..specs
    };
    let encoding = specs.encoding().unwrap();
    let sane_string = input.trim_end_matches(padding);
    encoding.decode(sane_string.as_bytes()).ok()
}
