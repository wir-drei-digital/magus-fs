//! Bounded opt-in diagnostic windows, independent of authorization and callback threads.
use crate::*;
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
#[derive(Clone, Debug, Default, Serialize)]
pub struct MetadataProfile {
    pub window: u64,
    pub revision: String,
    pub callback_count: u64,
    pub load_count: u64,
    pub revision_load_count: u64,
    pub copy_count: u64,
    pub decoded_bytes: u64,
    pub cpu_inclusive_ns: BTreeMap<String, Option<u64>>,
    pub cpu_exclusive_ns: BTreeMap<String, Option<u64>>,
    pub ambiguous: bool,
}
#[derive(Default)]
pub(crate) struct Profiler {
    enabled: bool,
    next: u64,
    active: Vec<Arc<Mutex<MetadataProfile>>>,
}
pub struct MetadataProfileGuard {
    core: Option<std::sync::Weak<Mutex<crate::engine::Core>>>,
    profiler: Arc<Mutex<Profiler>>,
    window: Option<Arc<Mutex<MetadataProfile>>>,
}
impl MetadataProfileGuard {
    pub fn finish(mut self) -> MetadataProfile {
        // Close the window only after any already attributed locked operation finishes.
        let core = self.core.as_ref().and_then(std::sync::Weak::upgrade);
        let _locked = core.as_ref().and_then(|core| core.lock().ok());
        let Some(w) = self.window.take() else {
            return MetadataProfile::default();
        };
        self.profiler
            .lock()
            .unwrap()
            .active
            .retain(|v| !Arc::ptr_eq(v, &w));
        let result = w.lock().unwrap().clone();
        result
    }
}
impl Drop for MetadataProfileGuard {
    fn drop(&mut self) {
        if let Some(w) = &self.window {
            self.profiler
                .lock()
                .unwrap()
                .active
                .retain(|v| !Arc::ptr_eq(v, w));
        }
    }
}
impl Profiler {
    fn begin(profiler: &Arc<Mutex<Self>>, revision: &RevisionId) -> MetadataProfileGuard {
        let mut p = profiler.lock().unwrap();
        let window = if p.enabled {
            p.next += 1;
            let ambiguous = !p.active.is_empty();
            for w in &p.active {
                w.lock().unwrap().ambiguous = true;
            }
            let w = Arc::new(Mutex::new(MetadataProfile {
                window: p.next,
                revision: revision.as_str().to_owned(),
                ambiguous,
                ..Default::default()
            }));
            p.active.push(w.clone());
            Some(w)
        } else {
            None
        };
        MetadataProfileGuard {
            core: None,
            profiler: profiler.clone(),
            window,
        }
    }
}
impl Replica {
    /// Diagnostic collection is off unless explicitly enabled by the owning client.
    pub fn set_metadata_profile_enabled(&self, enabled: bool) -> Result<(), FsError> {
        let core = crate::engine::lock(&self.core)?;
        let mut p = core
            .metadata_profiler
            .lock()
            .map_err(|_| FsError::ReplicaBusy)?;
        if !p.active.is_empty() {
            return Err(FsError::ReplicaBusy);
        }
        p.enabled = enabled;
        Ok(())
    }
    pub fn begin_metadata_profile(
        &self,
        revision: &RevisionId,
    ) -> Result<MetadataProfileGuard, FsError> {
        let core = crate::engine::lock(&self.core)?;
        let mut guard = Profiler::begin(&core.metadata_profiler, revision);
        guard.core = Some(Arc::downgrade(&self.core));
        Ok(guard)
    }
}
/// Thread CPU is optional: never replace an unavailable clock with wall time.
pub fn metadata_thread_cpu_ns() -> Option<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) } != 0 {
        return None;
    }
    Some(t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64)
}
type Window = Arc<Mutex<MetadataProfile>>;
thread_local! {static ACTIVE:RefCell<Option<(Window,Vec<u64>)>>=const{RefCell::new(None)};}
pub(crate) struct Callback {
    previous: Option<(Window, Vec<u64>)>,
    span: Option<Span>,
}
impl Callback {
    pub(crate) fn begin(profiler: &Arc<Mutex<Profiler>>) -> Self {
        let p = profiler.lock().unwrap();
        let window = if p.enabled && p.active.len() == 1 {
            Some(p.active[0].clone())
        } else {
            None
        };
        drop(p);
        let previous = ACTIVE.with(|a| a.replace(window.map(|w| (w, Vec::new()))));
        count("callback", 1);
        let span = Span::begin("callback");
        Self {
            previous,
            span: Some(span),
        }
    }
}
impl Drop for Callback {
    fn drop(&mut self) {
        drop(self.span.take());
        ACTIVE.with(|a| {
            a.replace(self.previous.take());
        });
    }
}
pub(crate) fn count(kind: &str, n: u64) {
    ACTIVE.with(|a| {
        if let Some((w, _)) = &*a.borrow() {
            let mut w = w.lock().unwrap();
            match kind {
                "callback" => w.callback_count += n,
                "authority_load" => w.load_count += n,
                "revision_load" => w.revision_load_count += n,
                "copy" => w.copy_count += n,
                "bytes" => w.decoded_bytes += n,
                _ => {}
            }
        }
    });
}
pub(crate) struct Span {
    kind: &'static str,
    started: Option<u64>,
    active: bool,
}
impl Span {
    pub(crate) fn begin(kind: &'static str) -> Self {
        let active = ACTIVE.with(|a| {
            if let Some((_, stack)) = &mut *a.borrow_mut() {
                stack.push(0);
                true
            } else {
                false
            }
        });
        Self {
            kind,
            started: if active {
                metadata_thread_cpu_ns()
            } else {
                None
            },
            active,
        }
    }
}
fn add(map: &mut BTreeMap<String, Option<u64>>, kind: &str, n: Option<u64>) {
    let v = map.entry(kind.to_owned()).or_insert(Some(0));
    *v = match (*v, n) {
        (Some(a), Some(b)) => Some(a + b),
        _ => None,
    };
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let elapsed = self
            .started
            .zip(metadata_thread_cpu_ns())
            .map(|(a, b)| b.saturating_sub(a));
        ACTIVE.with(|a| {
            if let Some((w, stack)) = &mut *a.borrow_mut() {
                let children = stack.pop().unwrap();
                if let (Some(parent), Some(elapsed)) = (stack.last_mut(), elapsed) {
                    *parent += elapsed
                }
                let mut w = w.lock().unwrap();
                add(&mut w.cpu_inclusive_ns, self.kind, elapsed);
                add(
                    &mut w.cpu_exclusive_ns,
                    self.kind,
                    elapsed.map(|e| e.saturating_sub(children)),
                );
            }
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_window_counts_callback_thread() {
        let p = Arc::new(Mutex::new(Profiler {
            enabled: true,
            ..Default::default()
        }));
        let revision = RevisionId::digest(b"profile").unwrap();
        let g = Profiler::begin(&p, &revision);
        let q = p.clone();
        std::thread::spawn(move || {
            let _scope = Callback::begin(&q);
        })
        .join()
        .unwrap();
        assert_eq!(g.finish().callback_count, 1);
    }
    #[test]
    fn profile_disabled_is_quiet() {
        let p = Arc::new(Mutex::new(Profiler::default()));
        let g = Profiler::begin(&p, &RevisionId::digest(b"profile").unwrap());
        {
            let _scope = Callback::begin(&p);
        }
        assert!(g.window.is_none());
        assert!(p.lock().unwrap().active.is_empty());
        assert_eq!(g.finish().callback_count, 0);
    }
    #[test]
    fn profile_overlapping_windows_are_ambiguous() {
        let p = Arc::new(Mutex::new(Profiler {
            enabled: true,
            ..Default::default()
        }));
        let r = RevisionId::digest(b"profile").unwrap();
        let a = Profiler::begin(&p, &r);
        let b = Profiler::begin(&p, &r);
        assert!(a.finish().ambiguous);
        assert!(b.finish().ambiguous);
    }
}

#[cfg(test)]
mod span_tests {
    use super::*;
    #[test]
    fn profile_nested_spans_are_inclusive() {
        let p = Arc::new(Mutex::new(Profiler {
            enabled: true,
            ..Default::default()
        }));
        let g = Profiler::begin(&p, &RevisionId::digest(b"nested").unwrap());
        {
            let _c = Callback::begin(&p);
            let _d = Span::begin("decode");
            {
                let _h = Span::begin("hash");
                std::hint::black_box((0..10000).sum::<u64>());
            }
        }
        let w = g.finish();
        assert!(w.cpu_inclusive_ns["callback"] >= w.cpu_inclusive_ns["decode"]);
        assert!(w.cpu_inclusive_ns["decode"] >= w.cpu_exclusive_ns["decode"]);
        assert!(w.cpu_inclusive_ns.contains_key("hash"));
    }
}
