//! Bounded process-local advisory scheduling, never a durability or authority decision.
use std::{
    sync::{Condvar, Mutex},
    time::Instant,
};
#[derive(Default)]
pub(crate) struct Wakeup {
    epoch: Mutex<u64>,
    changed: Condvar,
}
impl Wakeup {
    pub(crate) fn epoch(&self) -> u64 {
        *self.epoch.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn notify(&self) {
        let mut epoch = self.epoch.lock().unwrap_or_else(|e| e.into_inner());
        *epoch = epoch.wrapping_add(1);
        self.changed.notify_all();
    }
    pub(crate) fn wait_until(&self, observed: u64, deadline: Instant) {
        let mut epoch = self.epoch.lock().unwrap_or_else(|e| e.into_inner());
        while *epoch == observed && Instant::now() < deadline {
            let (next, _) = self
                .changed
                .wait_timeout(epoch, deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|e| e.into_inner());
            epoch = next;
        }
    }
}
/// CLOCK_MONOTONIC is shared across Linux processes on one VM. Native clocks stay separate.
/// No path, content or credential enters opt-in diagnostics.
pub(crate) fn trace(stage: &str, replica: &str, operation: &str, revision: &str, head: &str) {
    if std::env::var_os("MAGUS_LATENCY_TRACE").is_none() {
        return;
    }
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut stamp) } != 0 {
        return;
    }
    let ns = stamp.tv_sec as u128 * 1_000_000_000 + stamp.tv_nsec as u128;
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "latency stage={stage} monotonic_ns={ns} replica={replica} operation={operation} revision={revision} head={head}");
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn notify_before_wait_is_not_lost() {
        let wake = Wakeup::default();
        let observed = wake.epoch();
        wake.notify();
        let start = Instant::now();
        wake.wait_until(observed, start + Duration::from_millis(150));
        assert!(
            start.elapsed() < Duration::from_millis(75),
            "durable admission waited for fallback"
        );
    }
    #[test]
    fn duplicate_hints_coalesce_into_one_observation() {
        let wake = Wakeup::default();
        let observed = wake.epoch();
        for _ in 0..100 {
            wake.notify();
        }
        assert_ne!(
            observed,
            wake.epoch(),
            "100 hints must wake one durable poll"
        );
        let latest = wake.epoch();
        let start = Instant::now();
        wake.wait_until(latest, start + Duration::from_millis(30));
        assert!(
            start.elapsed() >= Duration::from_millis(20),
            "hints must not queue 100 followup polls"
        );
    }
    #[test]
    fn notify_interrupts_an_existing_wait() {
        let wake = std::sync::Arc::new(Wakeup::default());
        let observed = wake.epoch();
        let worker = wake.clone();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            worker.wait_until(observed, Instant::now() + Duration::from_secs(1))
        });
        std::thread::sleep(Duration::from_millis(25));
        wake.notify();
        waiter.join().unwrap();
        assert!(started.elapsed() < Duration::from_millis(300));
    }
    #[test]
    fn missed_hint_has_periodic_fallback() {
        let wake = Wakeup::default();
        let start = Instant::now();
        wake.wait_until(wake.epoch(), start + Duration::from_secs(1));
        assert!(start.elapsed() >= Duration::from_millis(900));
        assert!(start.elapsed() < Duration::from_millis(1400));
    }
}
