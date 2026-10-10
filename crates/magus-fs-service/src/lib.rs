//! Standalone authenticated upload authority. Upload readiness is not publication.
pub mod auth;
mod changes;
pub mod config;
mod conflicts;
pub mod db;
pub mod policy;
mod publication;
pub mod reconciliation;
mod revisions;
pub mod storage;
mod submission;
pub mod views;
use auth::{authenticate, digest, AuthContext};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use magus_fs_core::{
    protocol::{NamespaceId, UploadId, MAX_CONTROL, SERVICE_PROTOCOL, UPLOAD_LEASE_SECONDS},
    ObjectId, MAX_CHUNK,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use std::{sync::Arc, time::Duration};
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Copy)]
pub struct Error {
    pub status: StatusCode,
    pub code: &'static str,
}
impl Error {
    pub fn invalid(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }
    pub fn pressure() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "backpressure",
        }
    }
    pub fn backend() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "backend_unavailable",
        }
    }
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_credential",
        }
    }
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
        }
    }
    pub fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
        }
    }
    pub fn limit() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "limit_exceeded",
        }
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::backend()
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"code":self.code}))).into_response()
    }
}
#[derive(Clone)]
pub struct ServiceState {
    pub db: Arc<db::Database>,
    pub objects: Arc<storage::VerifiedObjects>,
    requests: Arc<tokio::sync::Semaphore>,
    revision_work: Arc<tokio::sync::Semaphore>,
}
impl ServiceState {
    pub async fn open(config: config::Config) -> Result<Self> {
        let db = db::Database::open(config.database.clone()).await?;
        let objects = Arc::new(storage::VerifiedObjects::open(&config, db.clone())?);
        Ok(Self {
            db,
            objects,
            requests: Arc::new(tokio::sync::Semaphore::new(32)),
            revision_work: Arc::new(tokio::sync::Semaphore::new(2)),
        })
    }
    pub(crate) fn revision_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.revision_work
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::pressure())
    }
    async fn auth(
        &self,
        headers: &HeaderMap,
        namespace: &str,
        action: &str,
    ) -> Result<AuthContext> {
        let bearer = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or(Error::unauthorized())?;
        if bearer.len() != 64
            || !bearer
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::unauthorized());
        }
        let mut db = self.db.acquire().await?;
        db.run(|db| {
            Box::pin(async move {
                let context = authenticate(db, &digest(bearer.as_bytes()), namespace).await?;
                context.action(action)?;
                Ok(context)
            })
        })
        .await
    }
}
async fn bounded(State(state): State<ServiceState>, req: Request, next: Next) -> Response {
    let Ok(_permit) = state.requests.try_acquire() else {
        return Error::backend().into_response();
    };
    // Admission precedes body allocation and descriptor work. No detached work
    // escapes this scope; WSS acquires separately for each bounded paging tick.
    let path = req.uri().path();
    let expensive = path.contains("/revisions/")
        || path.contains("/views/")
        || path.contains("/operations/")
        || path.contains("/conflicts")
        || [
            "/seed",
            "/views",
            "/candidates",
            "/integrations",
            "/resolutions",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix));
    let _revision_permit = if expensive {
        match state.revision_permit() {
            Ok(p) => Some(p),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    let seconds = if req.uri().path().ends_with("/candidates")
        || req.uri().path().ends_with("/integrations")
        || req.uri().path().ends_with("/resolutions")
        || req.uri().path().ends_with("/seed")
    {
        60
    } else {
        10
    };
    match tokio::time::timeout(Duration::from_secs(seconds), next.run(req)).await {
        Ok(r) => r,
        Err(_) => Error::backend().into_response(),
    }
}
pub fn router(state: ServiceState) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"protocol":SERVICE_PROTOCOL,"status":"ok"})) }),
        )
        .route("/v1/n/{namespace}/uploads", post(create_upload))
        .route("/v1/n/{namespace}/uploads/{upload}", get(list_upload))
        .route(
            "/v1/n/{namespace}/uploads/{upload}/objects/{object}",
            put(install),
        )
        .route("/v1/n/{namespace}/grants", post(grants))
        .route(
            "/v1/n/{namespace}/uploads/{upload}/revisions/{revision}",
            put(submission::stage),
        )
        .route("/v1/n/{namespace}/seed", post(publication::seed))
        .route("/v1/n/{namespace}/views", post(views::create))
        .route(
            "/v1/n/{namespace}/views/{view}/descriptor",
            get(views::descriptor),
        )
        .route(
            "/v1/n/{namespace}/views/{view}/objects/{object}",
            get(views::object),
        )
        .route(
            "/capabilities",
            get(|| async {
                Json(magus_fs_core::Capabilities {
                    protocol: SERVICE_PROTOCOL.into(),
                    capabilities: vec![magus_fs_core::COLLABORATION_CAPABILITY.into()],
                })
            }),
        )
        .route("/v1/n/{namespace}/conflicts", get(conflicts::list))
        .route(
            "/v1/n/{namespace}/conflicts/{conflict}",
            get(conflicts::detail),
        )
        .route(
            "/v1/n/{namespace}/conflicts/{conflict}/alternatives/{alternative}",
            get(conflicts::alternative),
        )
        .route("/v1/n/{namespace}/resolutions", post(conflicts::resolve))
        .route("/v1/n/{namespace}/candidates", post(submission::candidate))
        .route(
            "/v1/n/{namespace}/integrations",
            post(publication::integrate),
        )
        .route(
            "/v1/n/{namespace}/operations/{replica}/{operation}",
            get(submission::get_operation),
        )
        .route("/v1/n/{namespace}/changes", get(changes::changes))
        .route(
            "/v1/n/{namespace}/notifications",
            get(changes::notifications),
        )
        .fallback(|| async { Error::not_found() })
        .layer(middleware::from_fn_with_state(state.clone(), bounded))
        .with_state(state)
}
pub async fn serve(
    state: ServiceState,
    listener: std::net::TcpListener,
    tls: axum_server::tls_rustls::RustlsConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let handle = axum_server::Handle::new();
    let stopping = handle.clone();
    let task = tokio::spawn(async move {
        shutdown.await;
        stopping.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    let result = axum_server::from_tcp_rustls(listener, tls)?
        .handle(handle)
        .serve(router(state).into_make_service())
        .await;
    task.abort();
    result
}
async fn body_bytes(body: Body, headers: &HeaderMap, limit: usize) -> Result<Bytes> {
    if headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > limit)
    {
        return Err(Error::limit());
    }
    tokio::time::timeout(Duration::from_secs(3), axum::body::to_bytes(body, limit))
        .await
        .map_err(|_| Error {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "body_timeout",
        })?
        .map_err(|error| {
            if std::error::Error::source(&error)
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
            {
                Error::limit()
            } else {
                Error::invalid("invalid_body")
            }
        })
}
async fn json_body<T: DeserializeOwned>(body: Body, headers: &HeaderMap) -> Result<T> {
    serde_json::from_slice(&body_bytes(body, headers, MAX_CONTROL).await?)
        .map_err(|_| Error::invalid("invalid_request"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn create_upload(
    State(state): State<ServiceState>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<impl IntoResponse> {
    let context = state.auth(&headers, &namespace, "write").await?;
    let _: Empty = json_body(body, &headers).await?;
    let upload = UploadId::random().map_err(|_| Error::backend())?;
    let mut db = state.db.acquire().await?;
    db.run(|db| Box::pin(async move {
    let tx = db.transaction().await?;
    db::lock_namespace(&tx, &namespace).await?;
    let current = authenticate(&tx, &context.token_hash, &namespace).await?;
    current.action("write")?;
    tx.execute("INSERT INTO upload_sessions(id,namespace,credential,generation,principal,replica,expires) SELECT $1,$2,id,generation,principal,replica,LEAST(expires,clock_timestamp()+make_interval(secs=>$4::double precision)) FROM credentials WHERE id=$3",&[&upload.as_str(),&namespace,&current.credential,&(UPLOAD_LEASE_SECONDS as f64)]).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"upload":upload}))))
    })).await
}
async fn list_upload(
    State(state): State<ServiceState>,
    Path((namespace, upload)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let context = state.auth(&headers, &namespace, "write").await?;
    let upload = UploadId::parse(upload).map_err(|_| Error::not_found())?;
    let mut db = state.db.acquire().await?;
    db.run(|db| Box::pin(async move {
    let tx = db.transaction().await?;
    db::lock_namespace(&tx, &namespace).await?;
    let current = authenticate(&tx, &context.token_hash, &namespace).await?;
    current.action("write")?;
    storage::check_session(&tx, &current, &upload).await?;
    let rows=tx.query("SELECT o.object_id,o.size FROM session_objects s JOIN objects o ON o.namespace=s.namespace AND o.object_id=s.object_id AND o.generation=s.generation WHERE s.upload=$1 AND s.completed AND o.state='ready' ORDER BY o.object_id",&[&upload.as_str()]).await?;
    let objects: Vec<_> = rows
        .iter()
        .map(|r| json!({"object":r.get::<_,String>(0),"size":r.get::<_,i64>(1)}))
        .collect();
    tx.commit().await?;
    Ok(Json(json!({"upload":upload,"objects":objects})))
    })).await
}
async fn install(
    State(state): State<ServiceState>,
    Path((namespace, upload, object)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>> {
    let context = state.auth(&headers, &namespace, "write").await?;
    let upload = UploadId::parse(upload).map_err(|_| Error::not_found())?;
    let object = ObjectId::parse(object).map_err(|_| Error::invalid("invalid_id"))?;
    let bytes = body_bytes(body, &headers, MAX_CHUNK as usize).await?;
    let size = bytes.len();
    state
        .objects
        .install(&context, &upload, &object, bytes)
        .await?;
    Ok(Json(json!({"object":object,"size":size,"ready":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    revoke: Option<String>,
    delegate: Option<Delegation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    replica: magus_fs_core::ReplicaId,
    expires: i64,
    actions: Vec<String>,
    branches: Vec<String>,
    prefixes: Vec<String>,
}
async fn grants(
    State(state): State<ServiceState>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>> {
    let context = state.auth(&headers, &namespace, "admin").await?;
    let request: GrantRequest = json_body(body, &headers).await?;
    let mut db = state.db.acquire().await?;
    db.run(|db| Box::pin(async move {
    let tx = db.transaction().await?;
    db::lock_namespace(&tx, &namespace).await?;
    let current = authenticate(&tx, &context.token_hash, &namespace).await?;
    current.action("admin")?;
    let (target, action, response) = match (request.revoke, request.delegate) {
        (Some(id), None) => {
            let target=tx.query_opt("SELECT c.principal,g.actions,g.branches,g.prefixes FROM credentials c JOIN grants g ON c.id=g.credential WHERE c.id=$1 AND c.namespace=$2",&[&id,&namespace]).await?.ok_or(Error::not_found())?;
            if target.get::<_, String>("principal") != current.principal
                || !narrower(
                    &current,
                    &target.get::<_, Vec<String>>("actions"),
                    &target.get::<_, Vec<String>>("branches"),
                    &target.get::<_, Vec<String>>("prefixes"),
                )
            {
                return Err(Error::not_found());
            }
            tx.execute(
                "UPDATE credentials SET revoked=true,generation=generation+1 WHERE id=$1",
                &[&id],
            )
            .await?;
            (id, "revoke", json!({"revoked":true}))
        }
        (None, Some(d)) => {
            if !narrower(&current, &d.actions, &d.branches, &d.prefixes) {
                return Err(Error::not_found());
            }
            let valid:bool=tx.query_one("SELECT to_timestamp($2::bigint)<=expires AND to_timestamp($2::bigint)>clock_timestamp() FROM credentials WHERE id=$1",&[&current.credential,&d.expires]).await?.get(0);
            if !valid {
                return Err(Error::invalid("invalid_grant"));
            }
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes).map_err(|_| Error::backend())?;
            let token = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let r = auth::Provision {
                authority: None, root_policy: None, merge_policy: None,
                namespace: NamespaceId::parse(namespace.clone()).map_err(|_| Error::not_found())?,
                principal: magus_fs_core::PrincipalId::parse(current.principal.clone())
                    .map_err(|_| Error::not_found())?,
                replica: d.replica,
                token: token.clone(),
                expires: d.expires,
                actions: d.actions,
                branches: d.branches,
                prefixes: d.prefixes,
            };
            r.validate()?;
            let id = auth::insert_credential(&tx, &r, Some(&current)).await?;
            (
                id.clone(),
                "delegate",
                json!({"credential":id,"token":token}),
            )
        }
        _ => return Err(Error::invalid("invalid_request")),
    };
    tx.execute(
        "INSERT INTO grant_audit(namespace,actor,target,action) VALUES($1,$2,$3,$4)",
        &[&namespace, &current.credential, &target, &action],
    )
    .await?;
    tx.commit().await?;
    Ok(Json(response))
    })).await
}
fn narrower(c: &AuthContext, actions: &[String], branches: &[String], prefixes: &[String]) -> bool {
    actions.iter().all(|a| c.actions.contains(a))
        && branches.iter().all(|b| c.branches.contains(b))
        && prefixes
            .iter()
            .all(|p| c.prefixes.iter().any(|parent| auth::within(p, parent)))
}
