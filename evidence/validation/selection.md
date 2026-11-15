# Selected vulnerabilities for validation and repair

## V1 — F-01: Unauthenticated, unauthorized grade modification
- **Type:** Authorization (per-user / per-course permission).
- **Location:** `baseline_secure_coding_api.py`, `update_grade`, L128–142.
- **Root cause:** The handler never reads `flask.session`. It has no authentication,
  no role check and no check that `course_id` is in the professor's `courses`.
  Both the in-place update (L140) and the append of a new record (L138) are reachable.
- **Requirements violated:** R1 (authentication), R3 (professors only for assigned
  courses; students cannot update), R4 (role or login alone is not permission),
  R7 (401/403, denied update leaves data unchanged).
- **Why selected:** A login check alone does not fix it. The repair must enforce
  permission for a specific user and course on both the update and the create paths.
- **Detected by:** LLM conditions A, B and C. Not detected by Bandit or Semgrep.

## V2 — F-02 (+ F-13): Path traversal / arbitrary file read in `/files`
- **Type:** File access.
- **Location:** `download_file`, L144–148.
- **Root cause:** The `path` query parameter is joined as `MATERIALS_DIR / raw_path`
  and passed to `send_file` with no canonicalisation or containment check.
  `..` segments escape the directory, and an absolute path replaces the base entirely.
  The endpoint also has no authentication check (F-13).
- **Requirements violated:** R1 (downloads need an authenticated user),
  R6 (no reads outside the materials directory), R7 (client error, no internal details).
- **Why selected:** The fix requires a change to application logic (path resolution
  and containment), and its root cause differs from V1.
- **Detected by:** LLM conditions A, B and C. Not detected by Bandit or Semgrep.

Not selected: hard-coded key, debug mode, credentials and bind address. Changes
limited to these do not satisfy the assignment, and the SAST tools already report them.
