This is repair assistance for a confirmed vulnerability, not an independent
discovery task.

We are now repairing a confirmed vulnerability in the supplied application

Confirmed finding:
F-01 — Unauthenticated, unauthorized grade modification.
- Affected code: update_grade(), POST /grades/update (lines 128–142).
- Root cause: the handler never reads flask.session. There is no
  authentication check, no role check, and no check that course_id is one of
  the professor's assigned courses. Both the in-place update (row["grade"] =
  grade) and the append of a new record (GRADES.append(...)) are reachable by
  anyone.
- Reproduction (CI, security-regression job, before patching):
  - Anonymous POST {"student_id":1001,"course_id":"SRS","grade":20}
    -> 200 (expected 401)
  - Logged in as alice (student): same request -> 200 (expected 403)
  - Logged in as prof_srs (courses ["SRS"]): {"student_id":1001,
    "course_id":"SSD","grade":20} -> 200 (expected 403)
  - Logged in as prof_srs: {"student_id":1002,"course_id":"SSD","grade":20}
    (no existing record) -> 200 and a new record is created (expected 403,
    no record created)
  - Result: 4 failed. The permitted cases (prof_srs updating SRS, admin1
    updating a grade) pass and must keep passing.

Required behavior:
R1 — Authentication: grade updates require an authenticated user.
R3 — Academic staff scope: professors may read and update grades only for
their assigned courses. Administrators may read profiles and grades and
update grades. (Students may not update grades.)
R4 — Complete authorization: check authorization on every relevant request.
Login alone, a valid identifier, or a role name alone does not establish
permission for a particular record.
R7 — Error handling: unauthenticated protected requests return 401;
authenticated but unauthorized requests return 403. A denied or invalid
update must leave stored data unchanged. Responses must not expose internal
paths, tracebacks, or exception details.

Legitimate use cases that must keep working:
- prof_srs updates a grade in course SRS -> 200, grade stored.
- admin1 updates any grade -> 200, grade stored.
- Existing login, logout, /me, profile, grade-read and file endpoints keep
  their current behavior (they are out of scope for this patch).

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.
