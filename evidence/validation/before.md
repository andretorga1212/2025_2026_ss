# Security tests before patching

- **CI run:** https://github.com/andretorga1212/2025_2026_ss/actions/runs/43720400416
- **Commit:** "Add security tests before patching"
- **Result:** `security-regression` job failed: 8 failed, 3 passed
  (Python 3.10.22, pytest 9.2.0). `build` was skipped, so no image was published.

All failures are violated security assertions: the vulnerable app returned `200`
where the requirements expect a denial. The permitted operations passed, which
shows the tests run correctly on the unpatched application.

## V1 — F-01: Grade update authorization (`tests_security/test_grade_authorization.py`)

| Test | Expected (requirement) | Observed | Result |
|---|---|---|---|
| `test_assigned_professor_can_update_grade` (supplied example) | 200, grade updated | 200 | PASSED |
| `test_admin_can_update_grade` | 200, grade updated (R3) | 200 | PASSED |
| `test_anonymous_cannot_update_grade` | 401, data unchanged (R1, R7) | `assert 200 == 401` | FAILED |
| `test_student_cannot_update_own_grade` | 403, data unchanged (R3, R4) | `assert 200 == 403` | FAILED |
| `test_professor_cannot_update_unassigned_course` | 403, SSD grade unchanged (R3, R4) | `assert 200 == 403` | FAILED |
| `test_professor_cannot_create_record_in_unassigned_course` | 403, no new SSD record (R3, R4) | `assert 200 == 403` | FAILED |

**Observed behaviour:** Any client, anonymous or logged in with any role, can
change an existing grade or create a new grade record in any course.

## V2 — F-02/F-13: File access (`tests_security/test_file_access.py`)

These tests use a temporary materials directory (`tmp_path` + `monkeypatch`),
with a secret file placed outside it.

| Test | Expected (requirement) | Observed | Result |
|---|---|---|---|
| `test_authenticated_user_can_download_material` | 200, file content (R6) | 200 | PASSED |
| `test_anonymous_download_is_rejected` | 401 (R1, R7) | `assert 200 == 401` | FAILED |
| `test_relative_traversal_is_blocked` (`../secret.txt`) | 4xx, secret not disclosed (R6) | `assert 400 <= 200` | FAILED |
| `test_absolute_path_is_blocked` (absolute path) | 4xx, secret not disclosed (R6) | `assert 400 <= 200` | FAILED |
| `test_nested_traversal_is_blocked` (`sub/../../secret.txt`) | 4xx, secret not disclosed (R6) | `assert 400 <= 200` | FAILED |

**Observed behaviour:** `/files` serves materials without login and returns
`200` for a relative, an absolute and a nested traversal path out of the
materials directory, so files outside it are readable.

## Conclusion
Both selected vulnerabilities are confirmed by executable tests. Patching can start.
