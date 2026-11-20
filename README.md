# nginx2root

A small [Mishe](https://github.com/genaforvena/mishe-tauftauf) research plant
investigating CVE-2026-123007 — the NGINX2Root HTTP/2 flow-control integer
underflow in nginx's `ngx_http_v2_module` — in a local, isolated laboratory.
Its goal is to independently identify and reproduce the underlying
memory-safety failure, or to report honestly that we could not, with every
failed hypothesis preserved.

Three minds run it: **nginxsec** (researcher), **witness** (independent
verifier), and **operator** (the owner's delegate). Findings are graded on an
evidence ladder — suspected → reproducible crash → confirmed memory
corruption → demonstrated impact — and never upgraded without observed bytes.
All testing is local; nothing here contacts or scans external systems.

- Task and verified ground truth: [docs/task.md](docs/task.md)
- Report: [reports/nginx2root-investigation.md](reports/nginx2root-investigation.md) — rung 3 reached; rung 4 honestly recorded as NO
- License: [CC0 1.0](LICENSE) — everything here is public domain.
