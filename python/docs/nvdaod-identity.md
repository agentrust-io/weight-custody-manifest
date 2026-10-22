# Versioned NVIDIA GPU identity parsing

The GPU identity reader accepts the legacy opaque entries and NVDAOD profile 0
through major version 2. Minor and patch changes remain compatible. The new
versioned path is **provisional**: a vendor structural vector and synthetic
signed controls validate parsing and KBS composition, not a live CUDA 13.5+
GPU/driver appraisal. The existing captured legacy H100 validation is separate.

The 12-byte header carries `NVDAOD`, a little-endian profile, then byte-ordered
major/minor/patch/padding. Packed versioned entries carry little-endian
`dataType`, `dataValueType`, and `dataSize`. The parser retains the value type
internally, including unknown types; the existing `parse_gpu_opaque_fields`
payload-only return shape is preserved. Identity extraction accepts the driver
and VBIOS entries only with their documented raw version-like type `0x86`.
Other entries are not used to establish identity. The header major is
authoritative even if a legacy version entry also appears. On the legacy path,
an explicit version entry must be the documented u16 and at most 2; captures
without that entry retain their existing interpretation.

All entry lengths remain bounded by the declared opaque extent, which must end
at the signature. Repeated IDs are refused. The verifier still checks the
certificate chain, signature and nonce before identity extraction. An unreadable
identity produces no measurement; the configured KBS cannot replace it with the
caller's outer measurement claim. Unknown chip architecture remains unreadable.
This is signed identity extraction, not RIM golden-value appraisal.

## Primary sources and fixture provenance

- NVIDIA, [NVIDIA Opaque Data Format](https://docs.nvidia.com/attestation/specs/latest/opaque-data-format.html),
  page dated 6 October 2026; read 22 October 2026. Defines layout, version
  compatibility, and driver/VBIOS IDs and value types.
- NVIDIA attestation-sdk at
  [`11b2bfeb42a1158aa08744603ecb239ccb3d2265`](https://github.com/NVIDIA/attestation-sdk/tree/11b2bfeb42a1158aa08744603ecb239ccb3d2265),
  shared `nv-attestation-sdk-cpp/src/spdm/spdm_opaque_data_parser.cpp` and GPU
  `nv-attestation-sdk-cpp/src/gpu/spdm/gpu_opaque_data_parser.cpp`. These clarify
  header precedence and retaining unknown value types. WCM preserves its own
  stricter duplicate-ID refusal.
- The optional structural test reads a separately supplied copy of
  `nv-attestation-sdk-cpp/unit-tests/testdata/sample_nvdaod_transcript.txt` at
  that revision. Set `WCM_NVDAOD_VENDOR_TRANSCRIPT` to its absolute local path.
  No raw report is included in this change. The upstream sample is copyright
  NVIDIA Corporation & Affiliates, under its Apache-2.0 LICENSE.
  Source blob: `fcdfad5d2704cdded9e7b7fe588312e90117cdba`.
  Source SHA-256:
  `346fff240b98f3be7ee50bf5d3ddfd1f7013df77dc5460c7dae3fd1c9634c13b`.
  Decoded 4,178-byte transcript SHA-256:
  `b0501d231c44422a61ddd83b082fd3315eeb93fdf402add78cf60dda3c9e4e53`.
  It contains 17 entries, including driver `620.12` and VBIOS
  `96.00.D9.00.0F`. The vendor sample has no accompanying device certificate
  chain here and is used only for structural parsing; its signature is not
  authenticated by this change. The shorter driver field is retained as a
  variable-length compatibility control.

The references define the encoding and explain the scope. They do not provide
independent live-device acceptance, device-root enrollment, a RIM comparison or
hardware custody evidence. Those remain owner review and later validation.
