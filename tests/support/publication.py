"""Bounded final reporting after the coordinator's owned-resource cleanup."""
import json

INTERRUPTED = 'parent interrupted; inspect retained owned profile resources'


def publish_result(result, path, interrupts) -> int:
    """Publish at most twice, sampling scalar interruption state before each write.

    A signal during the first encoding/write earns one reconciliation. The last
    pre-encoding sample is the reporting boundary: signals after it may increase
    the handler's scalar count, but cannot trigger another publication or alter
    the sampled result. Handlers must only record scalar state. Cleanup belongs
    to the caller and retained-resource evidence is preserved verbatim.
    """
    for attempt in range(2):
        observed = interrupts.count
        if observed:
            result.update(state='failed', passed=False, exit_code=1,
                          parent_interrupts=observed)
            failures = result.setdefault('failures', [])
            if INTERRUPTED not in failures:
                failures.append(INTERRUPTED)
        path.write_text(json.dumps(result, indent=2) + '\n')
        if attempt == 1 or interrupts.count == observed:
            return result['exit_code']
    raise AssertionError('unreachable')
