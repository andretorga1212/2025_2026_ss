# Static security review: `baseline_secure_coding_api.py`

This review is from reading the source only; nothing was executed. The most serious problems are that anyone on the network can change grades without logging in (F-01) and read arbitrary files from the server (F-02).

## Assumed policy (inferred, not in the code)

The source contains no authorization rules, so the severities below rest on these assumptions:

- **A1:** All endpoints except `/`, `/login` and possibly `/me` require an authenticated session.
- **A2:** Students may read only their own profile and grades.
- **A3:** Only professors, for their assigned courses, and possibly admins may update grades.
- **A4:** `/files` should serve only files inside `materials/`. Whether downloads require login is unknown.

## Findings table

| ID | Title | Location | Severity | Confidence |
|---|---|---|---|---|
| F-01 | Unauthenticated, unauthorized grade modification | `update_grade`, L128–142 | Critical | High |
| F-02 | Path traversal / arbitrary file read | `download_file`, L144–148 | Critical | High |
| F-03 | Werkzeug debug mode on all interfaces | `__main__`, L159 | High–Critical | Medium |
| F-04 | Missing authentication and object-level authorization on grade reads | `get_grades`, L122–126 | High | High (given A1/A2) |
| F-05 | Missing authentication and object-level authorization on profiles | `get_profile`, L115–120 | High | High (given A1/A2) |
| F-06 | Hardcoded, guessable session signing key | L8 | High (latent) | High |
| F-07 | Plaintext, hardcoded, weak credentials | `User`, `USERS`, L30, L36–43, L88 | Medium | High |
| F-08 | No input validation on grade data | `update_grade`, L130–140 | Medium | High |
| F-09 | Error handler discloses internals and masks HTTP status codes | `handle_error`, L150–155 | Medium | High |
| F-10 | No login throttling or lockout | `login`, L82–96 | Medium | High |
| F-11 | Weak session lifecycle: no revocation, stale role claims | `login`/`logout`, L91–101 | Low–Medium | Medium |
| F-12 | Cookie and transport hardening absent; no CSRF defence | App config, L7–8, L159 | Low–Medium | Medium |

## Supporting explanations

### F-01: Unauthenticated grade modification
- **Input and flow:** The JSON body fields `student_id`, `course_id` and `grade` (L130–134) go to `find_grade` and are then written to `GRADES` (L138 or L140).
- **Root cause:** The function never reads `flask.session`. There is no authentication, role check, or check against the professor's `courses`, even though login stores them (L94).
- **Preconditions and impact:** Network reachability only. Anyone can alter or create any grade for any student and course, which is a complete loss of grade integrity.
- **Test:** With no cookie, POST `{"student_id":1001,"course_id":"SRS","grade":20}` as JSON, then GET `/grades/1001`. The finding is confirmed if the response is 200 and the grade changed. Repeat as `alice` (student) and as `prof_srs` for course `SSD`.
- **Fact vs. assumption:** The absence of any check is a code fact. That it is a vulnerability depends on A3, which is a very safe assumption.

### F-02: Path traversal in `/files`
- **Input and flow:** The query parameter `path` (L146) is joined as `MATERIALS_DIR / raw_path` (L147) and passed to `flask.send_file` (L148).
- **Root cause:** There is no canonicalization or containment check. `..` segments are preserved, and in `pathlib` an absolute right-hand operand replaces the base entirely. `send_file` performs no safe join, unlike `send_from_directory`.
- **Preconditions and impact:** None beyond reachability, since the endpoint has no authentication. An attacker can read any file the process can read, including this source file (which exposes the secret key and passwords for F-06 and F-07) and system files. It also supplies inputs that weaken the debugger PIN in F-03.
- **Test:** Request `path=../<this file's name>` and an absolute path such as `/etc/hostname`. A 200 with file contents confirms it. A 4xx, or a 500 with no content, rejects it.
- **Uncertainty:** Impact is bounded by OS permissions and any container isolation. Confidence in the flaw is high.

### F-03: Debug mode bound to `0.0.0.0`
- **Flow:** `app.run(debug=True, host="0.0.0.0")` enables the Werkzeug debugger and reloader on every interface.
- **Root cause:** A development configuration is used in a multi-user deployment.
- **Impact:** The debugger includes an interactive Python console, so reaching it means remote code execution. It is PIN-protected, but the PIN is derived from host values that are readable through F-02.
- **Preconditions:** The app is launched via `__main__` rather than a WSGI server. That is a deployment fact not shown in the source.
- **Test:** Request `/console` from a non-local host and check whether the debugger page is served.
- **Uncertainty:** The catch-all handler (L150) likely prevents the traceback page from appearing for view exceptions, but it does not remove the console route. Behaviour varies by Werkzeug version, so confidence is medium.

### F-04 and F-05: Unprotected grade and profile reads (IDOR)
- **Input and flow:** The URL segment `student_id` is converted with `int()` and used directly to look up `GRADES` (L124–125) or `STUDENT_PROFILES` (L117).
- **Root cause:** There is no session check and no comparison with `session["student_id"]` or the role.
- **Impact:** Anyone can read any student's grades, name, email and programme. The identifiers are sequential (1001, 1002), so enumeration is trivial.
- **Test:** Without a cookie, GET `/grades/1002` and `/students/1002/profile`. Repeat logged in as `alice`. A 200 with Bob's data confirms the finding.
- **Assumption:** A1 and A2. If professors or admins are meant to have broad read access, the finding still holds for unauthenticated users and students.

### F-06: Hardcoded secret key
- **Fact:** `SECRET_KEY = "dev-secret-key"` (L8). Flask sessions are client-side cookies signed with this key.
- **Root cause:** The secret is in source, has low entropy, and is also retrievable through F-02.
- **Impact:** An attacker can forge a session with any `user`, `role`, `student_id` and `courses`. Today only `/me` reads the session, so the direct impact is small. Once authorization is added to fix F-01, F-04 and F-05, this becomes a full bypass unless it is fixed alongside them.
- **Test:** Sign a cookie offline with the known key claiming `role=admin` and GET `/me`. If the forged values are echoed back, the finding is confirmed.
- **Note:** Session cookies are signed but not encrypted, so clients can read their contents.

### F-07: Plaintext hardcoded credentials
- **Fact:** Passwords are stored as plaintext strings (L37–42) and compared with `!=` (L88).
- **Root cause:** There is no password hashing, the credentials are trivially guessable and live in source, and the comparison is not constant-time.
- **Impact:** Any disclosure of the source (F-02) or of memory yields every account, including the admin account. The timing side channel is minor and probably impractical.
- **Test:** A code inspection is sufficient. Alternatively, obtain the source through F-02 and log in as `admin1`.
- **Assumption:** The in-memory store is a stated teaching simplification, but the plaintext handling is still a flaw.

### F-08: No validation in grade update
- **Input and flow:** The types and values of all three JSON fields are stored as given.
- **Root cause:** There are no checks on schema, type, range or referential integrity.
- **Impact:**
  - Grades can be out of range or non-numeric (`-5`, `9999`, strings, nested objects).
  - Records can be created for nonexistent students or courses.
  - A string `"1001"` does not match the integer `1001` in `find_grade`, so it creates a shadow record that `/grades/1001` never shows.
  - Unbounded appends allow memory exhaustion.
  - Malformed bodies raise `KeyError` or `TypeError`, which feeds F-09.
- **Test:** POST each of those variants and inspect the stored state and responses.
- **Assumption:** The valid grade scale is unknown. It is presumably 0–20, inferred from the seed data.

### F-09: Verbose catch-all error handler
- **Flow:** Any exception is returned to the client as `str(exc)` plus the class name (L152–155).
- **Root cause:** Internal error detail is sent to clients. `errorhandler(Exception)` also captures `HTTPException`, so 404, 405 and 415 responses become 500.
- **Impact:** Information disclosure. For example, a `FileNotFoundError` from `/files` reveals absolute server paths, which helps F-02. Status codes are also wrong, which hinders clients and monitoring.
- **Test:** GET `/files?path=nonexistent`, `/grades/abc` and an unknown route, then inspect the body and status.
- **Confidence:** High. The exact messages depend on Python and Flask versions.

### F-10: No brute-force protection
- **Flow:** `/login` allows unlimited attempts (L82–89).
- **Root cause:** There is no rate limiting, lockout, delay or logging.
- **Impact:** Online password guessing, made worse by the weak passwords in F-07.
- **Test:** Send a few hundred failed logins and then a correct one. If there is no throttling and the last one succeeds, the finding is confirmed.
- **Uncertainty:** An upstream proxy could throttle requests. None is shown.

### F-11: Session lifecycle
- **Fact:** `logout` only clears the client cookie (L100). Role and courses are copied into the session at login (L92–94).
- **Root cause:** Sessions are stateless with no server-side revocation, and authorization attributes are cached in the client token.
- **Impact:** A captured cookie stays valid after logout. Role or course changes do not take effect until the user logs in again. This matters once the session is used for authorization.
- **Test:** Save the cookie, log out, and replay the cookie against `/me`.
- **Uncertainty:** Cookie lifetime depends on Flask defaults and version.

### F-12: Cookie, transport and CSRF
- **Fact:** There is no TLS, no `SESSION_COOKIE_SECURE` or explicit `SAMESITE` setting, and no CSRF tokens.
- **Impact:** Credentials and cookies travel in cleartext if the app is served directly. Login and logout CSRF are possible through the form-encoded `/login` and the bodyless `/logout`. `/grades/update` is incidentally shielded by its JSON content-type requirement, but that is not a designed control and is irrelevant while F-01 exists.
- **Test:** Inspect the `Set-Cookie` attributes. Submit a cross-origin auto-posting form to `/logout`.
- **Uncertainty:** TLS may terminate upstream, and browser SameSite defaults vary. Confidence is medium.

## Limits of this review

- **Not confirmed:** Nothing was run, so every finding is a claim to test.
- **Not reviewed:** Dependency versions, the deployment setup (proxy, TLS, WSGI server), logging and auditing, and the concurrency safety of the in-memory `GRADES` list.
- **Not exhaustive:** Having no finding in an area does not mean it is safe.
