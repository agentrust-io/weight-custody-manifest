# Bounded custody sequence checks

`tests/test_custody_sequences.py` explores all 7,776 length-five sequences over
advance, tick, trusted-caller re-attestation, use, authorize and stop. An integer
clock/counter model independently predicts the next error, operation count,
deadline, terminal state and one-time stop notification. A longer targeted
history exercises renewal followed by exact expiry; a supervised monitor test
checks cancellation and refusal to resume afterwards.

The model describes serialized calls on one software owner. It does not model
signed renewal appraisal, hardware time, copies of Python key bytes, concurrent
thread access or external serving effects. Existing signed-renewal tests cover a
separate boundary. There is no trusted erasure or hardware qualification claim.

Run from python/: `python -m pytest -q tests/test_custody_sequences.py`.
