use crate::{
    auth::{authenticate, digest, AuthContext},
    config::Config,
    db::{lock_namespace, Database},
    Error, Result,
};
use axum::body::Bytes;
use futures_util::TryStreamExt;
use magus_fs_core::{
    protocol::{NamespaceId, UploadId, MAX_SESSION_BYTES, MAX_SESSION_OBJECTS},
    ObjectId, MAX_CHUNK,
};
use object_store::{
    aws::AmazonS3Builder,
    client::{ClientOptions, HttpClient, HttpConnector},
    path::Path,
    ObjectStore, ObjectStoreExt, PutMode, PutOptions, RetryConfig,
};
use std::{sync::Arc, time::Duration};

#[derive(Debug, Clone)]
struct ExplicitTransport(reqwest::Client);
impl HttpConnector for ExplicitTransport {
    fn connect(&self, _: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(self.0.clone()))
    }
}
pub struct VerifiedObjects {
    db: Arc<Database>,
    store: Arc<dyn ObjectStore>,
}
impl VerifiedObjects {
    pub fn open(config: &Config, db: Arc<Database>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| Error::backend())?;
        let store = AmazonS3Builder::new()
            .with_endpoint(&config.s3_endpoint)
            .with_region("us-east-1")
            .with_bucket_name(&config.s3_bucket)
            .with_access_key_id(&config.s3_access_key)
            .with_secret_access_key(&config.s3_secret_key)
            .with_allow_http(config.private_backend_http)
            .with_virtual_hosted_style_request(false)
            .with_http_connector(ExplicitTransport(client))
            .with_retry(RetryConfig {
                max_retries: 0,
                retry_timeout: Duration::from_secs(5),
                ..Default::default()
            })
            .build()
            .map_err(|_| Error::backend())?;
        Ok(Self {
            db,
            store: Arc::new(store),
        })
    }
    /// Namespace lock precedes object lock. Reservation commits before S3 I/O;
    /// a durable session lease protects the immutable generation until expiry.
    pub async fn install(
        &self,
        context: &AuthContext,
        session: &UploadId,
        id: &ObjectId,
        bytes: Bytes,
    ) -> Result<()> {
        if bytes.len() as u64 > MAX_CHUNK {
            return Err(Error::limit());
        }
        if id.as_str() != format!("sha256:{}", digest(&bytes)) {
            return Err(Error::invalid("hash_mismatch"));
        }
        let (key, generation) = {
            let mut db = self.db.acquire().await?;
            let bytes = &bytes;
            db.run(|db| Box::pin(async move {
            let tx = db.transaction().await?;
            lock_namespace(&tx, &context.namespace).await?;
            let current = authenticate(&tx, &context.token_hash, &context.namespace).await?;
            current.action("write")?;
            check_session(&tx, &current, session).await?;
            let row=tx.query_opt("SELECT generation,storage_key,size,state FROM objects WHERE namespace=$1 AND object_id=$2 FOR UPDATE",&[&context.namespace,&id.as_str()]).await?;
            let (generation, key) = if let Some(row) = row {
                if row.get::<_, i64>("size") != bytes.len() as i64
                    || !matches!(row.get::<_, &str>("state"), "uploading" | "ready")
                {
                    return Err(Error::conflict());
                }
                (
                    row.get::<_, String>("generation"),
                    row.get::<_, String>("storage_key"),
                )
            } else {
                let generation = NamespaceId::random()
                    .map_err(|_| Error::backend())?
                    .as_str()
                    .to_owned();
                let key = format!("{}/{}/{}", context.namespace, &id.as_str()[7..], generation);
                tx.execute("INSERT INTO objects(namespace,object_id,generation,storage_key,size,state,lease_until) SELECT $1,$2,$3,$4,$5,'uploading',expires FROM upload_sessions WHERE id=$6",&[&context.namespace,&id.as_str(),&generation,&key,&(bytes.len() as i64),&session.as_str()]).await?;
                (generation, key)
            };
            let inserted=tx.execute("INSERT INTO session_objects(upload,namespace,object_id,generation) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",&[&session.as_str(),&context.namespace,&id.as_str(),&generation]).await?;
            if inserted == 1 {
                let updated=tx.execute("UPDATE upload_sessions SET reserved_bytes=reserved_bytes+$2,reserved_objects=reserved_objects+1 WHERE id=$1 AND reserved_bytes+$2<=$3 AND reserved_objects<$4",&[&session.as_str(),&(bytes.len() as i64),&MAX_SESSION_BYTES,&MAX_SESSION_OBJECTS]).await?;
                if updated != 1 {
                    return Err(Error::limit());
                }
            }
            tx.execute("UPDATE objects SET lease_until=GREATEST(lease_until,(SELECT expires FROM upload_sessions WHERE id=$3)) WHERE namespace=$1 AND object_id=$2",&[&context.namespace,&id.as_str(),&session.as_str()]).await?;
            tx.commit().await?;
            Ok((key, generation))
            })).await?
        };
        let path = Path::from(key);
        // Conditional create never overwrites an installed generation. An uncertain
        // acknowledgement or concurrent identical PUT is resolved by readback.
        let put = self
            .store
            .put_opts(
                &path,
                bytes.clone().into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await;
        match put {
            Ok(_) => {}
            Err(object_store::Error::AlreadyExists { .. })
            | Err(object_store::Error::Precondition { .. }) => {}
            Err(_) => return Err(Error::backend()),
        }
        let readback = self.read_verified(&path, id, bytes.len()).await;
        let corrupt = readback.as_ref().is_err_and(|e| e.code == "corrupt_object")
            || readback.as_ref().is_ok_and(|stored| stored != &bytes);
        if corrupt {
            let mut db = self.db.acquire().await?;
            db.run(|db| Box::pin(async move {
            let tx = db.transaction().await?;
            lock_namespace(&tx, &context.namespace).await?;
            tx.execute("UPDATE objects SET state='corrupt' WHERE namespace=$1 AND object_id=$2 AND generation=$3 AND state IN ('uploading','ready')", &[&context.namespace, &id.as_str(), &generation]).await?;
            tx.commit().await?;
            Ok(())
            })).await?;
            return Err(Error::invalid("corrupt_object"));
        }
        readback?;
        #[cfg(feature = "test-faults")]
        if std::path::Path::new("/control/pause-install").is_file() {
            let _ = std::fs::write("/tmp/fs2-install-barrier", b"installed");
            std::future::pending::<()>().await;
        }
        let mut db = self.db.acquire().await?;
        db.run(|db| Box::pin(async move {
        let tx = db.transaction().await?;
        lock_namespace(&tx, &context.namespace).await?;
        let current = authenticate(&tx, &context.token_hash, &context.namespace).await?;
        current.action("write")?;
        check_session(&tx, &current, session).await?;
        let n=tx.execute("UPDATE objects SET state='ready' WHERE namespace=$1 AND object_id=$2 AND generation=$3 AND state IN ('uploading','ready') AND lease_until>clock_timestamp()",&[&context.namespace,&id.as_str(),&generation]).await?;
        if n != 1 {
            return Err(Error::conflict());
        }
        tx.execute("UPDATE session_objects SET completed=true WHERE upload=$1 AND object_id=$2 AND generation=$3",&[&session.as_str(),&id.as_str(),&generation]).await?;
        tx.commit().await?;
        Ok(())
        })).await
    }
    pub async fn read_authorized(
        &self,
        context: &AuthContext,
        view: &magus_fs_core::protocol::ViewId,
        id: &ObjectId,
    ) -> Result<Bytes> {
        let (snapshot, key, generation, size) =
            crate::views::object_record(&self.db, context, view, id).await?;
        let bytes = self.read_verified(&Path::from(key), id, size).await;
        if bytes.as_ref().is_err_and(|e| e.code == "corrupt_object") {
            self.db.acquire().await?.run(|db|Box::pin(async move {
                let tx=db.transaction().await?;lock_namespace(&tx,&context.namespace).await?;
                tx.execute("UPDATE objects SET state='corrupt' WHERE namespace=$1 AND object_id=$2 AND generation=$3",&[&context.namespace,&id.as_str(),&generation]).await?;
                tx.commit().await?;Ok(())
            })).await?;
        }
        let bytes = bytes?;
        crate::revisions::final_read(&self.db, &snapshot).await?;
        Ok(bytes)
    }
    async fn read_verified(&self, path: &Path, id: &ObjectId, size: usize) -> Result<Bytes> {
        let result = self.store.get(path).await.map_err(|_| Error::backend())?;
        if result.meta.size != size as u64 {
            return Err(Error::invalid("corrupt_object"));
        }
        let mut stream = result.into_stream();
        let mut out = Vec::with_capacity(size);
        while let Some(chunk) = stream.try_next().await.map_err(|_| Error::backend())? {
            if out.len() + chunk.len() > size {
                return Err(Error::invalid("corrupt_object"));
            }
            out.extend_from_slice(&chunk);
        }
        if out.len() != size || id.as_str() != format!("sha256:{}", digest(&out)) {
            return Err(Error::invalid("corrupt_object"));
        }
        Ok(out.into())
    }
}
pub async fn check_session<C: tokio_postgres::GenericClient + Sync>(
    db: &C,
    context: &AuthContext,
    session: &UploadId,
) -> Result<()> {
    if db.query_opt("SELECT id FROM upload_sessions WHERE id=$1 AND namespace=$2 AND credential=$3 AND generation=$4 AND replica=$5 AND principal=$6 AND expires>clock_timestamp()",&[&session.as_str(),&context.namespace,&context.credential,&context.generation,&context.replica,&context.principal]).await?.is_none(){return Err(Error::not_found());}
    Ok(())
}
