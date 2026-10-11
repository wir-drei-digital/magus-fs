use crate::{auth, db, revisions as r, Error, Result, ServiceState};
use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, Message, WebSocketUpgrade},
        Path, RawQuery, State,
    },
    http::HeaderMap,
    response::Response,
    Json,
};
use futures_util::{SinkExt, StreamExt};
use magus_fs_core::{authorize_tree_read, protocol::*};
struct Query {
    branch: BranchName,
    after: i64,
    limit: usize,
    snapshot: bool,
}
fn query(raw: Option<String>) -> Result<Query> {
    let mut values = std::collections::BTreeMap::new();
    for pair in raw.unwrap_or_default().split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or(Error::invalid("invalid_request"))?;
        if !["branch", "after", "limit", "snapshot"].contains(&key)
            || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(Error::invalid("invalid_request"));
        }
    }
    let branch = BranchName::parse(
        values
            .remove("branch")
            .ok_or(Error::invalid("invalid_request"))?,
    )
    .map_err(|_| Error::invalid("invalid_request"))?;
    let after = values
        .remove("after")
        .unwrap_or_else(|| "0".into())
        .parse::<i64>()
        .map_err(|_| Error::invalid("invalid_cursor"))?;
    let limit = values
        .remove("limit")
        .unwrap_or_else(|| "128".into())
        .parse::<usize>()
        .map_err(|_| Error::limit())?;
    if !(1..=128).contains(&limit) {
        return Err(Error::limit());
    }
    if after < 0 {
        return Err(Error::invalid("cursor_expired"));
    }
    let snapshot = values
        .remove("snapshot")
        .map(|v| v == "true")
        .unwrap_or(false);
    Ok(Query {
        snapshot,
        branch,
        after,
        limit,
    })
}
async fn page(state: &ServiceState, c: &auth::AuthContext, q: &Query) -> Result<ChangePage> {
    let _permit = state.revision_permit()?;
    let s = r::snapshot(&state.db, c, q.branch.as_str(), None).await?;
    s.context.action("read")?;
    let current = s.current.as_ref().ok_or(Error::not_found())?;
    let a = s.authority()?;
    let (rows,max)=state.db.acquire().await?.run(|db|Box::pin(async move {
  let tx=db.transaction().await?;db::lock_namespace(&tx,&c.namespace).await?;let context=auth::authenticate(&tx,&c.token_hash,&c.namespace).await?;context.action("read")?;
  let max=tx.query_one("SELECT COALESCE(max(sequence),0)::bigint FROM changes WHERE namespace=$1 AND branch=$2",&[&c.namespace,&q.branch.as_str()]).await?.get::<_,i64>(0);
  if q.after>max{return Err(Error::invalid("invalid_cursor"))}
  let floor=tx.query_opt("SELECT floor FROM change_retention WHERE namespace=$1 AND branch=$2",&[&c.namespace,&q.branch.as_str()]).await?.map(|r|r.get::<_,i64>(0)).unwrap_or(0);
  if !q.snapshot && q.after<floor{return Err(Error::invalid("cursor_expired"))}
  let after=if q.snapshot {max}else{q.after};
  let rows=tx.query("SELECT sequence,head,paths FROM changes WHERE namespace=$1 AND branch=$2 AND sequence>$3 ORDER BY sequence LIMIT $4",&[&c.namespace,&q.branch.as_str(),&after,&(q.limit as i64)]).await?.into_iter().map(|r|(r.get::<_,i64>(0),r.get::<_,String>(1),r.get::<_,Vec<String>>(2))).collect::<Vec<_>>();tx.commit().await?;Ok((rows,max))
 })).await?;
    let cursor = rows.last().map(|r| r.0).unwrap_or(max.max(q.after));
    let mut events = vec![];
    for (sequence, head, paths) in rows {
        if paths.iter().any(|path| {
            if !s.context.permits("read", q.branch.as_str(), path) {
                return false;
            }
            let mut path = path.as_str();
            loop {
                let id = if path.is_empty() {
                    Some(&current.tree.root.id)
                } else {
                    current
                        .tree
                        .entries
                        .iter()
                        .find(|e| e.path == path)
                        .map(|e| &e.id)
                };
                if let Some(id) = id {
                    return authorize_tree_read(&current.tree, id, a).is_ok();
                }
                path = path.rsplit_once('/').map(|p| p.0).unwrap_or("");
            }
        }) {
            events.push(ChangeEvent {
                sequence,
                head: HeadToken::parse(head).map_err(|_| Error::backend())?,
            });
        }
    }
    r::final_read(&state.db, &s).await?;
    Ok(ChangePage { events, cursor })
}
pub(crate) async fn changes(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Json<ChangePage>> {
    let c = state.auth(&headers, &ns, "read").await?;
    Ok(Json(page(&state, &c, &query(raw)?).await?))
}
pub(crate) async fn notifications(
    State(state): State<ServiceState>,
    Path(ns): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    ws: std::result::Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response> {
    let c = state.auth(&headers, &ns, "read").await?;
    let ws = ws.map_err(|_| Error::invalid("invalid_request"))?;
    let mut q = query(raw)?;
    page(&state, &c, &q).await?;
    Ok(ws.max_message_size(1024).max_frame_size(1024).on_upgrade(move|socket|async move {
  let (mut sink,mut stream)=socket.split();let mut tick=tokio::time::interval(std::time::Duration::from_secs(1));
  loop{tokio::select!{
   message=stream.next()=>{match message{Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,_=>{}}},
   _=tick.tick()=>{match page(&state,&c,&q).await{Ok(page)=>{q.after=page.cursor;if !page.events.is_empty(){let hint=format!("{{\"cursor\":{}}}",page.cursor);if sink.send(Message::Text(hint.into())).await.is_err(){break}}},Err(_)=>{let _=sink.send(Message::Close(None)).await;break}}}
  }}
 }))
}
