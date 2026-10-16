# Redactions in this record

Edited on October 1, 2026, after the run, before release. The evaluated planner is in an
internal repository, so the record for the two evaluated targets (`pinned-52632cc`,
`pinned-3d5b48a`) keeps commit ids, counts and file hashes and replaces source-derived text
with generic labels:

| Recorded text | Label in this record |
|---|---|
| names of the three evaluated tests that fail under the controls | `evaluated test 1` to `evaluated test 3`, with a short description |
| the evaluated test file and selector in the pytest command | `<evaluated test selection>` |
| the evaluated planner module named in each control | `<evaluated planner module>` |
| the evaluated source line removed by the admission-check control | `<evaluated planner: admission check call>` |
| the evaluated planner's refusal message in the predecessor control | `<evaluated planner refusal: predecessor check>` |

The reference target is unchanged. Counts, pass and fail outcomes and every other field are as
recorded. `SHA256SUMS.json` lists the edited files' new hashes; the hashes as first written were:

| File | SHA-256 as first written | SHA-256 now |
|---|---|---|
| `rerun.json` | `6ab734f1a7d5b4c744484efbfbf024bd5cdfd4e3ef50ad48eab95174d7a40d98` | `e5c220c14eb039bee6019edfb2e463e52837b791d9e2b19c6c1e86f64c7b8c6d` |
| `pinned-52632cc-controller-admission-predecessor.json` | `72feb52278e3ebedae7d9cbef87d2b9f21bc466a5a16da98de6d03f73e5f6176` | `eb3202f78fddbcd4e21c7cc82ff17b77c5c99f2453385a6b44017f1c577b9c9a` |
| `pinned-3d5b48a-controller-admission-predecessor.json` | `72feb52278e3ebedae7d9cbef87d2b9f21bc466a5a16da98de6d03f73e5f6176` | `eb3202f78fddbcd4e21c7cc82ff17b77c5c99f2453385a6b44017f1c577b9c9a` |

`rerun.py` writes the unredacted names when it is run against the evaluated repository; apply
the same labels before publishing a new record.
