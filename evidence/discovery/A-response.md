# Static security review: `baseline_secure_coding_api.py`

This review is from reading the source only; nothing was executed, and the proposed tests are unrun. No authorisation policy is stated in the file, so every access-control finding rests on an assumed policy, which I name. The list is not exhaustive, and deployment configuration and dependency versions are out of view.

**Assumed policy** (inferred from the `role`, `student_id` and `courses` fields, not from any stated requirement):
- Students may read only their own profile and grades.
- Professors may read and write grades only for courses in their `courses` list.
- Admins are unrestricted.
- Course materials require at least a logged-in user.

## Findings table

| ID | Title | Location | Severity | Confidence |
|---|---|---|---|---|
| F-01 | Path traversal / arbitrary file read | `download_file`, L144–148 | Critical | High |
| F-02 | Unauthenticated grade modification | `update_grade`, L128–142 | Critical | High (fact); policy assumed |
| F-03 | Unauthenticated profile read (PII, enumerable IDs) | `get_profile`, L115–120 | High | High (fact); policy assumed |
| F-04 | Unauthenticated grade read | `get_grades`, L122–126 | High | High (fact); policy assumed |
| F-05 | Hardcoded, guessable `SECRET_KEY` allows session forgery | L8; session use L91–94, L105–113 | High (latent today) | High |
| F-06 | Debug mode on all interfaces; RCE chain with F-01 | L159 | Critical if run via `__main__` | Medium |
| F-07 | Plaintext hardcoded credentials, weak passwords, no login throttling | L36–43, `login` L82–96 | High | High |
| F-08 | Catch-all error handler leaks internals and turns all errors into 500 | `handle_error`, L150–155 | Medium | High |
| F-09 | No input validation on grade writes | `update_grade`, L130–142 | Medium | High |
| F-10 | Logout does not invalidate sessions; cookie and CSRF hardening absent | `logout` L98–101; config L7–8 | Low–Medium | Medium |

## Supporting explanations

### F-01: Path traversal / arbitrary file read
- **Input and flow:** The `path` query parameter (L146) is joined as `MATERIALS_DIR / raw_path` (L147) and passed to `flask.send_file` (L148).
- **Root cause:** There is no containment check. `pathlib` keeps `..` segments, and joining an absolute path discards `MATERIALS_DIR` entirely. `send_file` does no path sanitising. The endpoint also has no authentication.
- **Preconditions:** Network access only.
- **Impact:** Read of any file the process can read, including this source file (the secret key and all passwords) and system files. It enables F-05 and F-06.
- **Test:** Request `GET /files?path=../baseline_secure_coding_api.py` and `GET /files?path=/etc/passwd`. The claim is confirmed if file contents are returned, and rejected if both are refused while `?path=srs-summary.txt` still works.
- **Uncertainty:** The need for authentication on materials is an assumption; the traversal is a code fact. OS permissions or a container limit the reach.

### F-02: Unauthenticated grade modification
- **Input and flow:** JSON body fields `student_id`, `course_id` and `grade` (L130–134) go to `find_grade`, then to an in-place update or an append (L136–140).
- **Root cause:** The function never reads `flask.session`. There is no authentication, role check or course-ownership check. This is a demonstrated fact.
- **Preconditions:** None beyond network access.
- **Impact:** Any anonymous client can change or create any grade, a complete loss of grade integrity.
- **Test:** With no cookie, send `POST /grades/update` with `{"student_id":1001,"course_id":"SRS","grade":20}`, then `GET /grades/1001`. Repeat as `alice` (a student) and as `prof_srs` for course `SSD`. Under the assumed policy, all three should be denied.
- **Uncertainty:** Who may write grades is assumed. For example, whether admins can, or who owns `SSD`, is not stated.

### F-03: Unauthenticated profile read
- **Input and flow:** The `student_id` path segment goes to `int()` and then a lookup in `STUDENT_PROFILES` (L117–120).
- **Root cause:** There is no session check and no comparison with `session["student_id"]`.
- **Preconditions:** None; IDs are sequential (1001, 1002).
- **Impact:** Disclosure of name, email and programme for every student by enumeration.
- **Test:** Request `GET /students/1002/profile` with no cookie, then as `alice`. Both should be denied under the assumed policy.
- **Uncertainty:** Whether professors or admins may read profiles is unknown.

### F-04: Unauthenticated grade read
- **Input and flow:** The `student_id` path segment is used to filter `GRADES` (L124–126).
- **Root cause:** Same as F-03.
- **Impact:** Disclosure of all grades for any student.
- **Test:** Request `GET /grades/1002` anonymously and as `alice`.
- **Uncertainty:** Same policy assumption. A correct fix needs per-course scoping for professors, which the code has no mechanism for at present.

### F-05: Hardcoded `SECRET_KEY`
- **Input and flow:** The attacker supplies the session cookie. Flask's default sessions are client-side and signed only with `SECRET_KEY` (L8). `user`, `role`, `student_id` and `courses` are stored in the cookie (L91–94) and trusted on read (L105–113).
- **Root cause:** The secret is a guessable constant in source, and it is also retrievable through F-01.
- **Preconditions:** Knowledge of the key.
- **Impact:** Forging a session with any identity or role. This is latent today because no endpoint enforces roles. It becomes a full authorisation bypass once F-02 to F-04 are fixed using session data.
- **Test:** Sign a cookie offline with the known key containing `{"user":"admin1","role":"admin"}` and request `GET /me`. The claim is confirmed if the forged values are echoed.
- **Uncertainty:** This assumes the key is not overridden at deployment; nothing in the file does so.

### F-06: Debug mode on `0.0.0.0`
- **Flow:** `app.run(debug=True, host="0.0.0.0")` (L159) enables the Werkzeug debugger and reloader on all interfaces.
- **Root cause:** A development setting is exposed to the network.
- **Preconditions:** The app is started through `__main__`, not a WSGI server. The debugger console is PIN-protected, but the PIN is derived from host values that F-01 can typically read.
- **Impact:** Potential remote code execution as the service user.
- **Test:** Check whether `/console` responds from a non-local host. Do not attempt PIN derivation outside an isolated lab.
- **Uncertainty:** Medium confidence. Console reachability and PIN behaviour depend on the Werkzeug version, which is unknown. The catch-all handler (F-08) probably suppresses the interactive traceback page but not the console route.

### F-07: Credential storage and login protection
- **Facts:** Passwords are plaintext constants (L37–42) compared with `!=` (L88). They are short and predictable. `login` has no rate limit, lockout or delay.
- **Root cause:** No password hashing, no secret management and no throttling.
- **Preconditions:** None for online guessing. F-01 discloses every password directly.
- **Impact:** Account takeover, including `admin1`.
- **Test:** Send repeated failed `POST /login` requests and observe that no throttling occurs. Confirm the passwords appear in the file retrieved through F-01.
- **Uncertainty:** The non-constant-time comparison is real but unlikely to be exploitable over a network. The identical error for an unknown user and a wrong password is correct and is not a finding.

### F-08: Catch-all error handler
- **Flow:** `@app.errorhandler(Exception)` returns `str(exc)` and the class name with status 500 (L150–155).
- **Facts:** `HTTPException` subclasses `Exception`, so 404, 405 and 415 responses also become 500. `int("abc")` at L117 and L124, and a missing JSON key at L132–134, surface as raw exception text.
- **Impact:** Disclosure of filesystem paths and internals. With F-01, the differing messages reveal whether a file exists. The wrong status codes also hinder clients and monitoring.
- **Test:** Request `GET /grades/abc`, `GET /nonexistent` and `GET /files?path=nope`, then inspect the bodies and status codes.
- **Uncertainty:** Low.

### F-09: Grade write validation
- **Input and flow:** JSON values are stored without checks (L132–140).
- **Facts:**
  - `grade` may be any JSON type or value.
  - A string `"1001"` does not equal the integer `1001`, so it creates a parallel row that `GET /grades/1001` never shows.
  - Unknown students and courses are accepted.
  - Appends are unbounded.
  - A `null` body raises `TypeError`.
- **Impact:** Corrupt or shadow records and memory growth, which is a denial-of-service risk. Stored values are echoed as JSON, so I see no injection sink in this file.
- **Test:** Post `grade: -5`, `grade: "A"`, `student_id: "1001"` and `student_id: 9999`, and check that each is accepted.
- **Uncertainty:** The valid grade range (0–20?) is assumed and not stated.

### F-10: Session lifecycle and cookie hardening
- **Facts:** `logout` only clears the client cookie (L100). Because sessions are stateless, a copied cookie stays valid after logout, by default until Flask's signature age limit. `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_SAMESITE` are not set, and there is no TLS and no CSRF protection. The role is fixed in the cookie at login, so later role changes do not propagate.
- **Impact:** Replay of captured cookies, and login or logout CSRF. CSRF against `/grades/update` is partly limited because `get_json()` requires a JSON content type, and it is moot while F-02 stands.
- **Test:** Log in, save the cookie, log out, then replay the cookie on `GET /me`.
- **Uncertainty:** Medium. Browser defaults and any TLS-terminating proxy change the exposure.

## Reviewed without a finding
- No SQL, template, shell or deserialisation sinks are present.
- The login redirect target is a constant (L96), so there is no open redirect.
- The seeded file writes (L19–24) use fixed names.

Remediation order when you get to patches: F-01 and F-02 first, then F-05 and F-06, since they would undermine any access-control fix for F-02 to F-04.
