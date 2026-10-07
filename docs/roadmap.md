# Roadmap

What WCM can do now, what comes next, and what is further out, for anyone
planning around it.

The canonical roadmap is [`ROADMAP.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/ROADMAP.md).

- **Now** - pre-1.0 developer preview. Hardware checks have been tested on real
  chips for all three platforms: AMD SEV-SNP (Azure), Intel TDX (GCP) and NVIDIA
  H100 in confidential mode, each with a saved hardware report in the repository
  that verifies offline.
- **Next** - testing on bare-metal machines rather than cloud VMs
  (`/dev/*-guest` providers), and portable test cases that carry real hardware
  reports in each vendor's own format.
- **Later** - resolve or narrow the open questions in §8 (notably the
  key-extraction half of 8.8, which needs new chips), the SCITT/CoSAI standards
  path, and SDKs in more programming languages.

Public release is a deliberate decision by the Project Lead; it is not gated on open question 8.8.
