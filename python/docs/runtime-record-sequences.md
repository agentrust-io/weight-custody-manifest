# Runtime-record sequence validation

RuntimeRecord requires a non-negative integer sequence. Booleans and other
non-integer values raise TypeError; negative integers raise ValueError.
Non-Boolean integer subclasses remain accepted. Valid integer payloads and
their signed bytes are unchanged.

Construction, deserialization with RuntimeRecord(**payload), and
dataclasses.replace(record, sequence=...) run the same construction check.
Malformed records therefore raise before a caller can invoke verify(). A loader
must treat those exceptions as invalid input. Verification still checks sequence
shape because an in-memory caller can bypass the frozen dataclass invariant.
Signing also validates a predecessor before arithmetic or hash-chain extension.

The original Boolean signing bug requires a predecessor: sequence=True with no
predecessor was already refused by the first-record rule. An authentically
signed malformed record could still pass the old verifier. The regression
controls re-sign False at index zero and True at index one, checking individual
and partial-chain refusal independently of signature validity.
