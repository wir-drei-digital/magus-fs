//! Service identities are separate from the frozen canonical revision format.
use crate::FsError;
use serde::{Deserialize, Serialize};
pub const SERVICE_PROTOCOL: &str = "magus-fs/service-v1";
pub const MAX_CONTROL: usize = 65_536;
pub const MAX_SESSION_BYTES: i64 = 512 * 1024 * 1024;
pub const MAX_SESSION_OBJECTS: i64 = 4096;
pub const UPLOAD_LEASE_SECONDS: i64 = 900;
macro_rules! opaque_id {
    ($($name:ident),*) => {$ (
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from="String", into="String")]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, FsError> {
                let value=value.into();
                if value.len()!=32 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(FsError::InvalidId); }
                Ok(Self(value))
            }
            pub fn random() -> Result<Self, FsError> {
                let mut bytes=[0;16]; getrandom::fill(&mut bytes).map_err(|_|FsError::InvalidId)?;
                Self::parse(bytes.iter().map(|b|format!("{b:02x}")).collect::<String>())
            }
            pub fn as_str(&self)->&str { &self.0 }
        }
        impl TryFrom<String> for $name { type Error=FsError; fn try_from(s:String)->Result<Self,FsError> {Self::parse(s)} }
        impl From<$name> for String {fn from(id:$name)->Self {id.0}}
    )*}
}
opaque_id!(
    NamespaceId,
    UploadId,
    ViewId,
    ReceiptId,
    HeadToken,
    RemoteSourceId
);
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BranchName(String);
impl BranchName {
    pub fn parse(s: String) -> Result<Self, FsError> {
        let valid = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if s.is_empty()
            || s.len() > 64
            || !valid(s.as_bytes()[0])
            || !s.bytes().all(|b| valid(b) || b == b'_' || b == b'-')
        {
            return Err(FsError::InvalidId);
        }
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for BranchName {
    type Error = FsError;
    fn try_from(s: String) -> Result<Self, FsError> {
        Self::parse(s)
    }
}
impl From<BranchName> for String {
    fn from(b: BranchName) -> Self {
        b.0
    }
}
