use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, io};

pub const FORMAT: &str = "magus-fs/v1";
pub const HASH: &str = "sha256";
pub const LAYOUT: &str = "fixed262144";
pub const MAX_CHUNK: u64 = 1_048_576;
pub const MAX_DESCRIPTOR: usize = 16 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_EXTENTS: usize = 100_000;
pub const MAX_FILE: u64 = 1_099_511_627_776;

#[derive(Debug)]
pub enum FsError {
    InvalidId,
    UnsupportedFormat,
    InvalidDescriptor,
    InvalidTree,
    InvalidPath,
    LimitExceeded,
    CorruptObject,
    UnsafeStorage,
    StorageOverlap,
    Io(io::Error),
}
impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl FsError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidId => "invalid_id",
            Self::UnsupportedFormat => "unsupported_format",
            Self::InvalidDescriptor => "invalid_descriptor",
            Self::InvalidTree => "invalid_tree",
            Self::InvalidPath => "invalid_path",
            Self::LimitExceeded => "limit_exceeded",
            Self::CorruptObject => "corrupt_object",
            Self::UnsafeStorage => "unsafe_storage",
            Self::StorageOverlap => "storage_overlap",
            Self::Io(_) => "io_error",
        }
    }
}
impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

macro_rules! id {
    ($name:ident, $prefix:literal, $len:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, FsError> {
                let value = value.into();
                let hex = value.strip_prefix($prefix).ok_or(FsError::InvalidId)?;
                if hex.len() != $len
                    || !hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(FsError::InvalidId);
                }
                Ok(Self(value))
            }
            fn prefix() -> &'static str {
                $prefix
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = FsError;
            fn try_from(v: String) -> Result<Self, FsError> {
                Self::parse(v)
            }
        }
        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}
id!(ObjectId, "sha256:", 64);
id!(RevisionId, "sha256:", 64);
id!(EntryId, "entry:", 32);
id!(ReplicaId, "replica:", 32);
id!(OperationId, "operation:", 32);
id!(PrincipalId, "principal:", 32);
id!(GroupId, "group:", 32);
macro_rules! random_id { ($($name:ident),*) => { $(impl $name { pub fn random()->Result<Self,FsError> {
    let mut bytes=[0u8;16]; getrandom::fill(&mut bytes).map_err(|e|FsError::Io(io::Error::other(e.to_string())))?;
    Self::parse(format!("{}{}",Self::prefix(),hex(&bytes)))
} })* }; }
random_id!(EntryId, ReplicaId, OperationId, PrincipalId, GroupId);
impl ObjectId {
    pub fn for_bytes(bytes: &[u8]) -> Result<Self, FsError> {
        if bytes.len() as u64 > MAX_CHUNK {
            return Err(FsError::LimitExceeded);
        }
        Self::parse(format!("{}{}", Self::prefix(), hex(&Sha256::digest(bytes))))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub format: String,
    pub hash: String,
    pub layout: String,
    #[serde(deserialize_with = "bounded_vec")]
    pub parents: Vec<RevisionId>,
    pub operation: OperationId,
    pub replica: ReplicaId,
    pub principal: PrincipalId,
    pub captured_at_ns: u64,
    #[serde(deserialize_with = "bounded_vec")]
    pub coverage: Vec<String>,
    pub provenance: String,
    pub tree: Tree,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub root: Root,
    #[serde(deserialize_with = "bounded_vec")]
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub id: EntryId,
    pub owner: PrincipalId,
    pub group: GroupId,
    pub mode: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub id: EntryId,
    pub parent: EntryId,
    pub owner: PrincipalId,
    pub group: GroupId,
    pub mode: u16,
    pub content: EntryContent,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntryContent {
    Directory,
    File { version: FileVersion },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileVersion {
    pub size: u64,
    #[serde(deserialize_with = "bounded_vec")]
    pub extents: Vec<Extent>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Extent {
    Chunk {
        object: ObjectId,
        object_size: u64,
        offset: u64,
        length: u64,
    },
    Hole {
        length: u64,
    },
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl RevisionId {
    pub(crate) fn digest(bytes: &[u8]) -> Result<Self, FsError> {
        Self::parse(format!("{}{}", Self::prefix(), hex(&Sha256::digest(bytes))))
    }
}

fn bounded_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("at most 100000 items")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while result.len() < 100_000 {
                match seq.next_element()? {
                    Some(v) => {
                        if result.len() == result.capacity() {
                            let next = (result.capacity().max(4) * 2).min(100_000);
                            result.reserve_exact(next - result.len());
                        }
                        result.push(v)
                    }
                    None => return Ok(result),
                }
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("limit_exceeded"));
            }
            Ok(result)
        }
    }
    d.deserialize_seq(Bounded(std::marker::PhantomData))
}

impl<'de> Deserialize<'de> for EntryContent {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: String,
            #[serde(default, deserialize_with = "present_version")]
            version: Option<FileVersion>,
        }
        fn present_version<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<Option<FileVersion>, D::Error> {
            FileVersion::deserialize(d).map(Some)
        }
        let wire = Wire::deserialize(d)?;
        match (wire.kind.as_str(), wire.version) {
            ("directory", None) => Ok(Self::Directory),
            ("file", Some(version)) => Ok(Self::File { version }),
            _ => Err(serde::de::Error::custom("invalid entry kind/version")),
        }
    }
}
