use super::transport::{Failure, Transport};
use magus_fs_core::{protocol::MAX_CONTROL, *};
use std::time::Instant;

pub(crate) fn fetch_proof(
    transport: &Transport,
    request: &ContinuationRequestV1,
    deadline: Instant,
) -> Result<ContinuationResponseV1, Failure> {
    if request.receipt.replica != transport.replica
        || request.receipt.branch != transport.binding.branch
    {
        return Err(FsError::ConfigMismatch.into());
    }
    let credential = transport.credential_stamp()?;
    let body =
        serde_json::to_vec(request).map_err(|_| Failure::from(FsError::InvalidDescriptor))?;
    if body.len() > MAX_CONTROL {
        return Err(FsError::LimitExceeded.into());
    }
    let bytes = transport.bytes(
        "POST",
        "/continuations/proof",
        body,
        MAX_DESCRIPTOR + 16384,
        deadline,
        false,
    )?;
    let response = decode_continuation_response(&bytes)?;
    if response.proof.namespace != transport.binding.id
        || response.proof.request != *request
        || response.proof.view.head == request.receipt.head
            && response.proof.published_revision != response.proof.current_revision
        || credential != transport.credential_stamp()?
    {
        return Err(FsError::OperationMismatch.into());
    }
    Ok(response)
}

#[cfg(target_os = "linux")]
pub(crate) fn current_credential_stamp(
    rep: &Replica,
    binding: &SyncBinding,
) -> Result<ObjectId, FsError> {
    Transport::new(binding.clone(), &rep.configuration()?)?.credential_stamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::transport::pool_tests::Fixture;
    use magus_fs_core::protocol::*;
    use std::time::{Duration, Instant};
    #[test]
    fn proof_inline_descriptor_exceeds_control_cap_but_is_bounded() {
        let fixture = Fixture::new();
        let transport = &fixture.transport;
        let principal = PrincipalId::random().unwrap();
        let group = GroupId::random().unwrap();
        let root = Root {
            id: EntryId::random().unwrap(),
            owner: principal.clone(),
            group: group.clone(),
            mode: 0o700,
        };
        let descriptor = Revision {
            format: FORMAT.into(),
            hash: HASH.into(),
            layout: LAYOUT.into(),
            parents: vec![],
            operation: OperationId::random().unwrap(),
            replica: transport.replica.clone(),
            principal: principal.clone(),
            captured_at_ns: 0,
            coverage: vec![String::new()],
            provenance: "explicit".into(),
            restoration: None,
            tree: Tree {
                entries: (0..500)
                    .map(|i| Entry {
                        path: format!("file{i:04}"),
                        id: EntryId::random().unwrap(),
                        parent: root.id.clone(),
                        owner: principal.clone(),
                        group: group.clone(),
                        mode: 0o600,
                        content: EntryContent::File {
                            version: FileVersion {
                                size: 0,
                                extents: vec![],
                            },
                        },
                    })
                    .collect(),
                root,
            },
        };
        let revision = revision_id(&descriptor).unwrap();
        let request = ContinuationRequestV1 {
            receipt: SharedReceipt {
                receipt: ReceiptId::random().unwrap(),
                operation: OperationId::random().unwrap(),
                replica: transport.replica.clone(),
                submitted_revision: revision.clone(),
                branch: transport.binding.branch.clone(),
                head: HeadToken::random().unwrap(),
            },
        };
        let response = ContinuationResponseV1 {
            proof: ContinuationProofV1 {
                format: CONTINUATION_PROOF_FORMAT.into(),
                namespace: transport.binding.id.clone(),
                request: request.clone(),
                principal,
                published_revision: revision.clone(),
                current_revision: revision.clone(),
                view: ViewBinding {
                    view: ViewId::random().unwrap(),
                    head: request.receipt.head.clone(),
                    revision: revision.clone(),
                },
                descriptor_digest: revision,
                complete_projection: true,
            },
            descriptor,
        };
        let body = serde_json::to_vec(&response).unwrap();
        assert!(body.len() > MAX_CONTROL);
        fixture.response(200, &body);
        assert_eq!(
            fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3)).unwrap(),
            response
        );
        fixture.response(404, b"");
        assert_eq!(
            fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3))
                .unwrap_err()
                .code,
            "continuation_capability_unavailable"
        );
        fixture.response(404, br#"{"code":"denied"}"#);
        assert_eq!(
            fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3))
                .unwrap_err()
                .code,
            "denied"
        );
        fixture.response(200, &body[..body.len() - 1]);
        assert!(fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3)).is_err());
        let mut mismatch = response.clone();
        mismatch.descriptor.tree.root.mode ^= 0o100;
        fixture.response(200, &serde_json::to_vec(&mismatch).unwrap());
        assert!(fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3)).is_err());
        fixture.response(200, &vec![b' '; MAX_DESCRIPTOR + 16385]);
        assert!(fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3)).is_err());
        let mut wrong = response;
        wrong.proof.request.receipt.operation = OperationId::random().unwrap();
        fixture.response(200, &serde_json::to_vec(&wrong).unwrap());
        assert!(fetch_proof(transport, &request, Instant::now() + Duration::from_secs(3)).is_err());
    }
}
