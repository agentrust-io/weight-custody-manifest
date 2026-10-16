# Weight Custody Manifest: Portable, Attestation-Gated Custody for Proprietary Model Weights

Technical report, version 2, October 1, 2026. Not peer reviewed. Patent Pending.
Version 2 adds the verification defects fixed in WCM 0.28.5 and 0.29.0 to the post-evaluation
findings, attributes the attestation break on patched SEV-SNP systems to Battering RAM, states
that sealed release is a broker setting, and corrects bibliography metadata.

Build: `tectonic paper.tex` (prepared with Tectonic 0.16.9; set SOURCE_DATE_EPOCH=1790812800
to reproduce the published PDF byte for byte).

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/weight-custody-manifest.

This package contains the manuscript source and the records of the software reruns made for
version 1 (`experiments/results/rerun-2026-09-27.txt`) and version 2
(`experiments/results/rerun-2026-10-01/`). The evaluated code is commit
2acedfa883204f7d1fd457d3ee603198d85be82c (WCM 0.28.0): 618 passed, 3 skipped, 91 of 91
conformance vectors on both dates. The October 1 record also runs later regression tests against
0.28.0 and the suite at main 5ef8c12. Dependencies were resolved on the rerun date. The SEV-SNP
hardware runs were not repeated, and their captured receipts are not included.

The evaluated version is affected by GHSA-j665-99rh-w85h and by the defects fixed in 0.28.5 and
0.29.0. Use a patched release for any deployment.
Current implementation guidance: https://wcm.agentrust-io.com/
