# Patch review record

Original LLM suggestions, saved unedited before review:
- `F-01-prompt.md` / `F-01-response.md`: grade-update authorization
- `F-02-prompt.md` / `F-02-response.md`: path traversal and missing authentication in `/files`

Both repairs were requested in separate conversations, labelled as repair assistance.
In both conversations the model ran the tests in its own sandbox and reported extra
passing cases (16 for F-01, 22 for F-02). We did not rely on those claims: the evidence
is our own CI run. The extra cases were not added to the repository.

## F-01: `update_grade`

| Section 12 question | Answer |
|---|---|
| Root cause or just the example input? | Root cause: the handler now resolves the user from the server-side `USERS` record and checks role and course before any write. |
| Authentication check leaving object/course authorization missing? | No: `can_update_grade()` allows admins any course and professors only their assigned `courses`. |
| All relevant paths protected? | Both write paths (in-place update and append) are behind the check. Grade and profile **reads** (F-04, F-05) are not changed; out of scope for this repair. |
| Authorized users still able to act? | Yes: `prof_srs` on SRS and `admin1` get 200; the success response body is unchanged. |
| Denial responses and state changes correct? | 401 anonymous, 403 student / unassigned course, 400 malformed body; `GRADES` unchanged on every denial. |
| Unrelated change, broad handler or insecure fallback? | Adds input validation for the same endpoint (R5/R7: booleans, `NaN`, out-of-range, non-integer IDs get 400). Kept because it is required by R5 and turns 500s into 400s. No broad exception handler, no fallback. |

**Remaining gaps (accepted, documented):** unknown course IDs (admin) and nonexistent
students (admin, or professor in their own course) are still accepted, so R5 is only
partly met. The hard-coded `SECRET_KEY` (F-06) still allows a forged admin session.

## F-02 / F-13: `download_file`

| Section 12 question | Answer |
|---|---|
| Root cause or just the example input? | Root cause: the path is resolved and must stay inside the resolved `MATERIALS_DIR` (`is_relative_to` + `is_file`). No string filtering of `..`. |
| Authentication check leaving authorization missing? | R6 only requires authentication for materials; any logged-in user may download. Login check added (401). |
| All relevant paths protected? | `download_file` is the only place a request value reaches the filesystem. |
| Authorized users still able to act? | Yes: authenticated download of a file inside the directory returns 200 with its content. |
| Denial responses correct? | 401 anonymous, 400 empty path, generic 404 for outside / missing / directory / malformed paths, with no server path in the body. |
| Unrelated change, broad handler or insecure fallback? | Two narrow `except (OSError, ValueError)` / `except OSError` blocks that fail closed with 404. No broad handler, no fallback. |

**Remaining gaps (accepted, documented):** check-then-open race if untrusted users can
write to `materials/`; legitimate symlinks pointing outside now return 404; session
integrity still depends on the hard-coded key (F-06).

## Final implementation

Both diffs were applied **without manual changes**. The final code in
`baseline_secure_coding_api.py` is identical to the two LLM diffs combined.
Pre-patch security tests were not modified. No functional test in `tests/` needed a
change, because neither repair touches the profile or grade-read endpoints.
