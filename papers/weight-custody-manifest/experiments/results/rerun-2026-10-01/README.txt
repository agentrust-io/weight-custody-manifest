WCM software rerun, 2026-10-01
==============================

Host: Windows 11 (10.0.26200), Python 3.12.10, fresh virtual environment per
revision, `pip install -e ".[dev]"` from python/ at each revision.
Dependencies resolved on 2026-10-01 (not pinned to 2026-09-03):
  cryptography 50.0.2, fastapi 0.142.2, httpx 0.28.1, jsonschema 4.26.0,
  model-signing 1.1.1, pydantic 2.13.5, pytest 9.1.1, rfc8785 0.1.4,
  starlette 1.7.0

1. Evaluated revision 2acedfa883204f7d1fd457d3ee603198d85be82c (WCM 0.28.0)
   pytest -q -rs (from python/)        618 passed, 3 skipped   pytest-0.28.0.log
   wcm conformance (reference self-test)  L1 32/32, L2 37/37, L3 12/12,
                                          L4 10/10 (91 vectors)  conformance-0.28.0.log
   The three skips are the symlink tests (privilege on Windows), as in the
   paper. Every number in the paper's E1 matches.
   wcm conformance --list-codes lists 41 WCM-* codes and all 41 occur in the
   vector corpus, so "each reportable error code is exercised" holds.

2. Regression tests added after 0.28.0, run against 0.28.0 source
   (copied from the fixing commits into python/tests/, not part of the
   evaluated suite)                                   regressions-at-0.28.0.log
   0628848 (0.29.0) test_unapproved_signed_measurement_is_refused...  FAILS:
       a correctly signed SNP report whose launch measurement is NOT in
       accepted_measurements receives the key (sealed to the caller's own
       transport key) when the unsigned serving_image_measurement field names
       an approved value. KBS configured with require_channel_binding=True and
       require_cpu_quote_verification=True.
   c8a2f72 (0.28.5) test_one_key_cannot_sign_as_both_builder_and_custodian
       and test_builder_key_cannot_stand_in_for_the_sovereign  FAIL: one key
       satisfies two required roles.
   c8a2f72 test_end_entity_certificate_cannot_issue  FAILS: a leaf under a
       trusted root can issue a further certificate that verify_cert_chain
       accepts.
   c8a2f72 test_concurrent_presentations_of_one_nonce_release_once  FAILS:
       two concurrent consumers of one nonce both succeed.
   The GHSA-j665-99rh-w85h test (596ca42) needs a provider keyword that does
   not exist at 0.28.0 and was not ported; the advisory is already in the paper.
   Renewal binding (0628848) was checked by reading custody.apply_renewal at
   0.28.0: it never compares the decision's evidence or nonce hash with the
   session's own submission.

3. Current main 5ef8c12 (0.29.0 plus the unreleased Azure vTPM exponent fix)
   pytest -q                            1244 passed, 39 skipped
   wcm conformance                       L1 32/32, L2 43/43, L3 12/12,
                                          L4 10/10 (97 vectors), plus one real
                                          AMD SEV-SNP vendor vector  conformance-main-5ef8c12.log

Not repeated: the Azure SEV-SNP protected-runtime run (E2) and the August 27
memory-sweep receipt (E3). No confidential-computing hardware is available on
this host, and the raw E3 report was not retained.
