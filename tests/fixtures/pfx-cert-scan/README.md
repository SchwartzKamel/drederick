# pfx-cert-scan fixtures

GAP-014 — PFX/cert/keytab/ccache awareness scanner.

This directory is intentionally a placeholder. All test fixtures are
generated on-the-fly in `PfxCertScannerTests` via `RSA.Create()` +
`CertificateRequest.CreateSelfSigned()` (.NET-native, no `openssl`
shellout) so the suite stays hermetic and portable across CI runners.

A hand-rolled MIT Kerberos ccache v4 buffer is written in-test for the
golden-ticket heuristic — see `Ccache_Native_Parses_PrincipalAndGoldenTicket`.
