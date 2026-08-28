# Vendored SARIF schema provenance

`sarif-schema-2.1.0.json` is copied unmodified from the OASIS Standard incorporating
Approved Errata 01, dated 28 August 2023:

- [Official schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
- [SARIF 2.1.0 Plus Errata 01 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
- SHA-256: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`

This official errata version fixes the earlier schema's invalid regular expression;
the project does not patch or relax the upstream schema to make its tests pass.
Local validation requires no schema fetch at runtime.

Copyright © OASIS Open 2023. All Rights Reserved. The schema is third-party
standards material; the project's MIT OR Apache-2.0 grant does not relicense it.
[OASIS notices](OASIS-NOTICES.txt) and [upstream license terms](OASIS-LICENSE.md)
are retained alongside it and included when the schema is distributed. The
[OASIS IPR policy](https://www.oasis-open.org/policies-guidelines/ipr/), including
the treatment of Computer Language Definitions, governs this material. Patent,
trademark and distribution questions require manual/legal review; cargo-deny
does not assess them. No OASIS endorsement is implied.
