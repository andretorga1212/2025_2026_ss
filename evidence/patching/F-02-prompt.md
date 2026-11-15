This is repair assistance for a confirmed vulnerability, not an independent
discovery task.

We are now repairing a confirmed vulnerability in the supplied application

Confirmed finding:
F-02 (with F-13) — Path traversal / arbitrary file read and missing
authentication in GET /files.
- Affected code: download_file(), GET /files?path=<name> (lines 144–148).
- Root cause: the "path" query parameter is joined as MATERIALS_DIR / raw_path
  and passed directly to flask.send_file() with no canonicalisation or
  containment check. ".." segments escape the directory, and because pathlib
  discards the base when the right-hand side is absolute, an absolute path
  reads any file. The endpoint also never checks for an authenticated session.
- Reproduction (CI, security-regression job, before patching; the tests use a
  temporary materials directory via tmp_path + monkeypatch of
  api.MATERIALS_DIR, with a secret file placed outside it):
  - Anonymous GET /files?path=notes.txt -> 200 (expected 401)
  - Logged in as alice: GET /files?path=../secret.txt -> 200 with secret
    contents (expected 4xx, no disclosure)
  - Logged in as alice: GET /files?path=<absolute path to secret.txt> -> 200
    (expected 4xx, no disclosure)
  - Logged in as alice: GET /files?path=sub/../../secret.txt -> 200
    (expected 4xx, no disclosure)
  - Result: 4 failed. Authenticated download of notes.txt inside the
    materials directory passes and must keep passing.

Required behavior:
R1 — Authentication: material downloads require an authenticated user.
R6 — File access: authenticated users may download teaching materials within
the materials directory. Requests must not read files outside that directory.
R7 — Error handling: invalid requests must return appropriate client errors
without exposing internal paths, tracebacks, or implementation exception
details. Unauthenticated protected requests return 401.

Constraints and legitimate use cases:
- Any authenticated user (student, professor, admin) can download
  srs-summary.txt and secure-coding.txt -> 200 with the file content.
- MATERIALS_DIR must be read at request time (the tests monkeypatch it).
- Missing, empty, directory or nonexistent paths must return a client error
  (4xx), not a 500 that leaks the server path.
- Other endpoints are out of scope for this patch.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.
