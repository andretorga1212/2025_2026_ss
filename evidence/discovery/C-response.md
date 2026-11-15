# Static security review: `baseline_secure_coding_api.py`

This review is from reading the source only; nothing was executed, so every test below is a proposal. Protected endpoints never read the session, so R1–R4 are not enforced anywhere. Together with the path traversal in `/files`, an unauthenticated network client can read and modify all records and read arbitrary files.

## Findings table

| ID | Title | Location | Requirement | Severity | Confidence |
|---|---|---|---|---|---|
| F-01 | No authentication on protected endpoints | `get_profile` L115–120, `get_grades` L122–126, `update_grade` L128–142, `download_file` L144–148 | R1, R7 | Critical | High |
| F-02 | Any caller can read any student profile (no object-level or role check) | `get_profile` L115–120 | R2, R3, R4 | High | High |
| F-03 | Grade reads are not scoped to requester, and empty results return 200 | `get_grades` L122–126 | R2, R3, R4 | High | High |
| F-04 | Grade updates have no role or course-scope check | `update_grade` L128–142 | R3, R4, R7 | Critical | High |
| F-05 | Grade update body is not validated, so arbitrary records and values are stored | `update_grade` L130–140, `find_grade` L56–60 | R5, R7 | High | High |
| F-06 | Path traversal and absolute-path file read | `download_file` L146–148 | R6 | Critical | High |
| F-07 | Student identifier in path is not validated | `get_profile` L117, `get_grades` L124 | R5, R7 | Medium | High |
| F-08 | Catch-all error handler leaks exception details and turns client errors into 500 | `handle_error` L150–155 | R7 | Medium | High |
| F-09 | Hardcoded session signing key allows session forgery | L8, `login` L91–94 | R1–R4 (inferred) | High (latent) | High on the fact, medium on impact |
| F-10 | Debug mode enabled and bound to all interfaces | L159 | Inferred | High | Medium |
| F-11 | Plaintext passwords and no brute-force control | `User` L27–33, `USERS` L36–43, `login` L88 | Inferred | Medium | High on the fact; the requirement is assumed |
| F-12 | Session and cookie hardening gaps (CSRF, revocation, stale claims) | `login` L91–94, `logout` L98–101, config L8 | Inferred | Low | Medium |

F-01 to F-08 violate the stated requirements. F-09 to F-12 rest on security requirements I have inferred; the exercise policy does not state them.

## Supporting explanations

### F-01: No authentication on protected endpoints
- **Location:** L115–148, all four protected handlers.
- **Input and path:** Any HTTP request reaches the handler body directly. `flask.session` is read only in `me` (L105–112); there is no `before_request` hook or decorator.
- **Missing control:** There is no session check before handling. The root cause is that authentication exists as a login feature but is never used as a gate.
- **Preconditions and impact:** The attacker needs only network reachability. Every other finding below becomes exploitable anonymously.
- **Test:** With no cookie, call `GET /students/1001/profile`, `GET /grades/1001`, `POST /grades/update` and `GET /files?path=srs-summary.txt`. R1/R7 expect 401 for each; the code predicts 200.
- **Assumptions and confidence:** High. This assumes no reverse proxy enforces authentication in front of the app; none is shown.

### F-02: Unrestricted profile read
- **Location:** `get_profile`, L115–120.
- **Input and path:** The URL segment `student_id` goes through `int()` into `STUDENT_PROFILES.get()` and the full record (name, email, programme) is returned.
- **Missing control:** There is no comparison with the session's `student_id` and no role check. The identifier alone is treated as permission, which R4 forbids.
- **Preconditions and impact:** None today because of F-01. Even with authentication added, a student could read other profiles and a professor could read any profile, which R3 prohibits. IDs are sequential (1001, 1002), so enumeration is trivial.
- **Test:** As alice, `GET /students/1002/profile` should be 403. As prof_srs, `GET /students/1001/profile` should be 403. As admin1, 200. As alice on 1001, 200.
- **Assumptions and confidence:** High. One policy point is unstated: whether a student requesting a nonexistent ID should get 403 or 404. I assume 403, decided before the existence lookup, so the status does not reveal which IDs exist.

### F-03: Grade reads not scoped
- **Location:** `get_grades`, L122–126.
- **Input and path:** The URL `student_id` goes through `int()` into a filter on `GRADES` by student only, and all matching rows are returned.
- **Missing control:** There is no ownership check for students (R2) and no course filter for professors (R3). R4's rule to deny when no permitted records exist is also missing: an unknown or unpermitted ID returns `200 []`.
- **Preconditions and impact:** None today. After authentication is added, students could read each other's grades, and prof_srs requesting `/grades/1001` would receive the SSD grade (course not assigned).
- **Tests:**
  - As alice, `GET /grades/1002` should be 403.
  - As prof_srs, `GET /grades/1001` should return only the SRS row.
  - As a professor whose courses match none of the student's rows, the response should be 403, not `[]`.
  - As admin1, all rows are returned.
- **Assumptions and confidence:** High. The response for an admin requesting a nonexistent student (404 or empty) is not defined by the policy; I assume 404.

### F-04: Grade update without authorization
- **Location:** `update_grade`, L128–142.
- **Input and path:** The JSON body fields `student_id`, `course_id` and `grade` go to `find_grade`, then an in-place write (L140) or an append (L138).
- **Missing control:** There is no role check (students must not update) and no check that `course_id` is in the professor's assigned courses.
- **Preconditions and impact:** None today; anonymous users can change any grade. This is an integrity loss on the application's most sensitive data, and there is no audit trail.
- **Tests:**
  - Unauthenticated update: 401 expected.
  - As alice, update own SRS grade to 20: 403 expected.
  - As prof_srs, update an SSD grade: 403 expected.
  - As prof_srs on SRS and as admin1: 200 expected.
  - After each denial, read the grades back and confirm they are unchanged (R7).
- **Assumptions and confidence:** High.

### F-05: Grade update input not validated
- **Location:** L130–140; `find_grade` L56–60.
- **Input and path:** The whole JSON body is attacker-controlled. Values are stored and echoed with no type, range or existence check.
- **Demonstrated code facts:**
  - `grade` accepts any JSON value: `true`, `-5`, `1000`, strings, objects, `null`.
  - A nonexistent `student_id` or unknown `course_id` creates a new record (L138).
  - `find_grade` uses `==`, so `"1001"` does not match `1001`. Sending the ID as a string appends a parallel record instead of updating, and repeated distinct values grow `GRADES` without bound.
  - Missing fields, or a body that is a list, string or `null`, raise `KeyError`/`TypeError`. No write happens in those cases, but F-08 turns them into 500 instead of 400.
- **Inferred (version-dependent):** Python's JSON parser accepts `NaN` and `Infinity` by default. A range check written as `not (0 <= g <= 20)` rejects NaN, but one written as `g < 0 or g > 20` accepts it. Worth a test once validation exists.
- **Missing control:** Schema validation per R5: the body must be an object; `student_id` must be an integer (not a boolean) that exists; `course_id` must be SRS or SSD; `grade` must be an integer or float, not a boolean, finite, and between 0 and 20.
- **Preconditions and impact:** None today. Results are corrupted or nonsensical grade data, phantom students and courses, and memory growth.
- **Tests:** Send each of these and expect 400 with `GRADES` unchanged:
  - `{"student_id":1001,"course_id":"SRS","grade":true}`
  - grade `21`, `-1`, `"20"`, `null`, `NaN`
  - `student_id` `9999`, `"1001"`, `true`, `1001.0`
  - `course_id` `"XYZ"`
  - each field missing in turn
  - body `[]`, `"x"`, `null`
  - a non-JSON content type
  - Boundaries `0`, `20` and `13.5` should succeed.
- **Assumptions and confidence:** High. "Existing student identifier" could mean a key in `STUDENT_PROFILES` or a student in `USERS`; I assume `STUDENT_PROFILES`. Whether fractional grades are allowed is covered by "numeric", so I assume yes.

### F-06: Path traversal in material download
- **Location:** `download_file`, L146–148.
- **Input and path:** The query parameter `path` is joined as `MATERIALS_DIR / raw_path` and passed to `flask.send_file(target)`.
- **Missing control:** There is no containment check. Two independent bypasses exist:
  - `..` segments are not normalised or rejected.
  - With `pathlib`, joining an absolute path discards the base, so `path=/etc/passwd` resolves outside the directory with no `..` at all.
  - `send_file` performs no safe join.
- **Preconditions and impact:** None today. The attacker can read any file the process can read, including this source file (signing key at L8, passwords at L36–43), which feeds F-09 and F-10. An empty or missing `path` targets the directory itself, and a nonexistent name raises an OS error whose message contains the absolute server path (leaked through F-08).
- **Tests:** Each of these should be rejected (400 or 404) with no content from outside `materials/`:
  - `GET /files?path=../baseline_secure_coding_api.py`
  - `GET /files?path=/etc/hostname`
  - `GET /files?path=subdir/../../<file>`
  - an empty `path`
  - a symlink placed inside `materials/` that points outside
  - `path=srs-summary.txt` should still succeed for an authenticated user.
- **Assumptions and confidence:** High for `..` and absolute paths. Symlink escape depends on who can write to `materials/`, which is unknown. Backslash handling differs on Windows; I assume a POSIX host.

### F-07: Student identifier not validated
- **Location:** L117 and L124. The route uses the default string converter and then a bare `int()`.
- **Input and path:** The URL segment goes into `int(student_id)`.
- **Demonstrated code facts:**
  - Non-numeric input raises `ValueError`, which becomes a 500 with the exception text.
  - `-1` and `0` parse and are looked up, though R5 requires positive integers.
  - `int()` accepts aliases of one ID, such as `+1001`, `1_001`, surrounding whitespace and non-ASCII digits. A future authorization check that compares the raw string rather than the parsed integer would be bypassable.
- **Missing control:** A strict positive-integer check returning 400.
- **Impact:** Violates R5/R7 and causes information leakage. It becomes a real bypass risk only if the eventual authorization check is written against the unparsed value.
- **Test:** Request `/grades/abc`, `/grades/-1`, `/grades/0`, `/grades/+1001`, `/grades/1_001` and `/grades/%201001`. Expect 400 for all, or a documented canonical form.
- **Assumptions and confidence:** High on behaviour. Whether alias forms must be rejected or just canonicalised is a policy choice; I assume rejection.

### F-08: Error handler leaks details and returns the wrong status
- **Location:** `handle_error`, L150–155.
- **Input and path:** Any input that raises an exception has its `str(exc)` and class name returned to the client with status 500.
- **Missing control:** There is no separation between client errors and server faults, and no generic message. In Flask, a handler registered for `Exception` also receives HTTP exceptions, so routing 404s, 405s and bad-JSON 400/415 errors would all be returned as 500 with internal text.
- **Impact:** Discloses absolute filesystem paths (through F-06), key names and Python exception types. It breaks the R7 status contract, and clients cannot distinguish their own errors from server faults.
- **Test:** `GET /nope` should be 404; `GET /login` should be 405; `POST /grades/update` with `text/plain` should be 400 or 415; `GET /files?path=missing.txt` should be 404. None of the bodies should contain a path, a `type` field or exception text.
- **Assumptions and confidence:** High for the leakage on application exceptions. The HTTP-exception behaviour is from my knowledge of Flask's documented handler resolution and is untested here; treat the first three tests as confirm-or-reject.

### F-09: Hardcoded session signing key
- **Location:** L8; session claims set at L91–94.
- **Input and path:** Flask's default sessions are client-held cookies signed with `SECRET_KEY`. Anyone who knows the key can mint a cookie with any `user`, `role`, `student_id` and `courses`.
- **Missing control:** The key is a guessable constant in source, and it is retrievable through F-06. Role and scope are trusted from the cookie rather than looked up server-side.
- **Preconditions and impact:** There is no impact today, because no endpoint checks the session. Once F-01 to F-04 are fixed using session values, this becomes a complete authentication and authorization bypass, so it must be fixed in the same change.
- **Test:** After authorization is added, sign a cookie offline with the source key claiming `role=admin` and call `/me` and a protected endpoint. It should be rejected once the key is a random secret loaded from the environment.
- **Assumptions and confidence:** High on the mechanism, assuming the default cookie session interface (no server-side session extension is imported).

### F-10: Debug mode on all interfaces
- **Location:** L159, `app.run(debug=True, host="0.0.0.0")`.
- **Missing control:** The development server and interactive debugger are enabled and reachable from the network.
- **Impact:** The Werkzeug debugger console allows code execution, protected by a PIN. The PIN is derived from host values that are readable through a file-read flaw like F-06, so the combination is a plausible route to remote code execution.
- **Preconditions:** The app must be started through `__main__`. Running under a WSGI server would not hit this line.
- **Test:** In the deployed configuration, check whether `/console` responds and whether an unhandled error returns debugger markup. Both should be absent.
- **Assumptions and confidence:** Medium. The deployment method is unknown, and the catch-all handler in F-08 may suppress the traceback page while leaving the console endpoint available.

### F-11: Plaintext passwords and no brute-force control
- **Location:** L30, L36–43, L88.
- **Demonstrated facts:** Passwords are stored and compared in plaintext with `!=`. They are short and predictable, and there is no attempt limiting or lockout.
- **Impact:** Online guessing is possible, and F-06 discloses all credentials at once. A timing side channel from `!=` is theoretical and not practical here.
- **Test:** Send 100 wrong passwords for alice and observe that no throttling occurs. Inspect storage for hashes.
- **Assumptions and confidence:** The requirement is inferred, since R1–R7 do not mention credential storage. The demo credentials may be deliberate teaching fixtures.

### F-12: Session and cookie hardening gaps
- **Location:** L8 (no cookie configuration), L91–94, L98–101.
- **Demonstrated facts:**
  - No `SESSION_COOKIE_SECURE` or `SESSION_COOKIE_SAMESITE` is set, and no CSRF token exists on the POST endpoints.
  - `logout` only clears the client's cookie, so a previously captured cookie stays valid until it expires.
  - Role and courses are snapshotted at login, so later changes to a user's role would not take effect.
- **Impact:** Low. The JSON content-type requirement on `/grades/update` and modern browsers' SameSite defaults partly mitigate CSRF. `/login` and `/logout` remain forgeable cross-site.
- **Test:** Log in, save the cookie, log out and replay the cookie against `/me`. Then submit a cross-origin form POST to `/logout`.
- **Assumptions and confidence:** Medium. This assumes browser clients and no TLS-terminating proxy that sets cookie flags; neither is specified.

## Limits of this review

- It covers this one file only. I did not inspect Flask or Werkzeug versions, deployment configuration, or the filesystem.
- Rate limiting, logging and auditing, transport security, and concurrency on the shared in-memory lists were not assessed in depth.
- An area with no finding listed has not been shown to be safe.
