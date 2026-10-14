//! Authenticated continuation metadata; never a historical read grant.
use crate::{protocol::*, *};
use serde::{Deserialize, Deserializer, Serialize};
pub const CONTINUATION_PROOF_FORMAT: &str = "magus-fs/continuation-proof/v1";
pub const MAX_CONTINUATION_RESPONSE: usize = MAX_DESCRIPTOR + 16384;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationRequestV1 {
    pub receipt: SharedReceipt,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationProofV1 {
    #[serde(deserialize_with = "proof_format")]
    pub format: String,
    pub namespace: NamespaceId,
    pub request: ContinuationRequestV1,
    pub principal: PrincipalId,
    pub published_revision: RevisionId,
    pub current_revision: RevisionId,
    pub view: ViewBinding,
    pub descriptor_digest: RevisionId,
    pub complete_projection: bool,
}
fn proof_format<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if value != CONTINUATION_PROOF_FORMAT {
        return Err(serde::de::Error::custom("unsupported continuation format"));
    }
    Ok(value)
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationResponseV1 {
    pub proof: ContinuationProofV1,
    pub descriptor: Revision,
}
impl ContinuationResponseV1 {
    pub fn validate(&self) -> Result<(), FsError> {
        let p = &self.proof;
        if p.format != CONTINUATION_PROOF_FORMAT {
            return Err(FsError::UnsupportedFormat);
        }
        let id = revision_id(&self.descriptor)?;
        if !p.complete_projection
            || !self.descriptor.parents.is_empty()
            || self.descriptor.coverage != [String::new()]
            || p.descriptor_digest != id
            || p.view.revision != id
        {
            return Err(FsError::InvalidDescriptor);
        }
        Ok(())
    }
}
/// Validate the larger inline-descriptor envelope independently of 64-KiB requests.
pub fn decode_continuation_response(bytes: &[u8]) -> Result<ContinuationResponseV1, FsError> {
    if bytes.len() > MAX_CONTINUATION_RESPONSE {
        return Err(FsError::LimitExceeded);
    }
    let response: ContinuationResponseV1 =
        serde_json::from_slice(bytes).map_err(|_| FsError::InvalidDescriptor)?;
    response.validate()?;
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_wire_rejects_unknown_format_and_oversize() {
        assert!(decode_continuation_response(&vec![b' '; MAX_CONTINUATION_RESPONSE + 1]).is_err());
        let proof = serde_json::json!({"format":"future", "namespace":"1".repeat(32),
          "request":{"receipt":{"receipt":"2".repeat(32),"operation":format!("operation:{}", "3".repeat(32)),
          "replica":format!("replica:{}", "4".repeat(32)),"submitted_revision":format!("sha256:{}", "5".repeat(64)),"branch":"main","head":"6".repeat(32)}},
          "principal":format!("principal:{}", "7".repeat(32)), "published_revision":format!("sha256:{}", "5".repeat(64)),
          "current_revision":format!("sha256:{}", "5".repeat(64)),"view":{"view":"8".repeat(32),"head":"6".repeat(32),"revision":format!("sha256:{}", "5".repeat(64))},
          "descriptor_digest":format!("sha256:{}", "5".repeat(64)),"complete_projection":true});
        assert!(serde_json::from_value::<ContinuationProofV1>(proof.clone()).is_err());
        let mut valid = proof;
        valid["format"] = CONTINUATION_PROOF_FORMAT.into();
        assert!(serde_json::from_value::<ContinuationProofV1>(valid.clone()).is_ok());
        valid["unexpected"] = true.into();
        assert!(serde_json::from_value::<ContinuationProofV1>(valid).is_err());
    }
    #[test]
    fn inline_descriptor_is_strict_and_can_exceed_control_limit() {
        let principal = PrincipalId::parse(format!("principal:{}", "1".repeat(32))).unwrap();
        let group = GroupId::parse(format!("group:{}", "2".repeat(32))).unwrap();
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o700,
        };
        let entries = (0..500)
            .map(|i| Entry {
                path: format!("file{i:04}"),
                id: EntryId::random().unwrap(),
                parent: root.id.clone(),
                owner: principal.clone(),
                group: group.clone(),
                mode: 0o600,
                content: EntryContent::Directory,
            })
            .collect();
        let descriptor = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: ReplicaId::random().unwrap(),
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec![String::new()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree { root, entries },
        };
        let id = revision_id(&descriptor).unwrap();
        let receipt = SharedReceipt {
            receipt: ReceiptId::random().unwrap(),
            operation: OperationId::random().unwrap(),
            replica: descriptor.replica.clone(),
            submitted_revision: id.clone(),
            branch: BranchName::parse("main".into()).unwrap(),
            head: HeadToken::random().unwrap(),
        };
        let mut response = ContinuationResponseV1 {
            proof: ContinuationProofV1 {
                format: CONTINUATION_PROOF_FORMAT.into(),
                namespace: NamespaceId::random().unwrap(),
                request: ContinuationRequestV1 {
                    receipt: receipt.clone(),
                },
                principal,
                published_revision: id.clone(),
                current_revision: id.clone(),
                view: ViewBinding {
                    view: ViewId::random().unwrap(),
                    head: receipt.head,
                    revision: id.clone(),
                },
                descriptor_digest: id,
                complete_projection: true,
            },
            descriptor,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        assert!(bytes.len() > MAX_CONTROL);
        assert_eq!(decode_continuation_response(&bytes).unwrap(), response);
        response.proof.descriptor_digest =
            RevisionId::parse(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert!(decode_continuation_response(&serde_json::to_vec(&response).unwrap()).is_err());
    }
}
