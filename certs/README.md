# Extra trusted CA certificates (optional)

Only needed if your network inspects HTTPS traffic (for example Cisco Secure Access, Umbrella or
Zscaler re-signing certificates), which causes errors such as `CERTIFICATE_VERIFY_FAILED` /
"TLS certificate verification failed" when the app calls OpenAI or Cisco AI Defense.

The start scripts (`start.cmd` / `start.ps1` on Windows, `bash start.sh` on macOS/Linux) fill this
folder automatically when it is empty. To do it by hand:

- Windows: `powershell -ExecutionPolicy Bypass -File .\scripts\export-network-root-ca.ps1`
- macOS / Linux: `bash scripts/export-network-root-ca.sh`

Or ask IT for your organisation's inspection root CA and save it here as a PEM file (`*.pem` or
`*.crt` beginning with `-----BEGIN CERTIFICATE-----`). Files in this folder are git-ignored and are
never part of the image. The app *adds* these certificates to the standard trust store; it never
disables certificate verification. Unreadable files are skipped with a warning in the logs.

Check with your IT/security team that the certificates are the correct, expected ones before
trusting them.
