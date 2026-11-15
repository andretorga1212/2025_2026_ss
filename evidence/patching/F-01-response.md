The patch below closes F-01: applied to a copy of your file, the supplied suite goes from 4 failed to 6 passed, and 16 extra regression cases I wrote also pass.

Patch
diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -60,6 +60,23 @@
     return None
 
 
+GRADE_WRITE_ROLES = {"professor", "admin"}
+
+
+def current_user():
+    """Resolve the session to the server-side user record (None if anonymous)."""
+    return USERS.get(flask.session.get("user") or "")
+
+
+def can_update_grade(user, course_id):
+    """Per-record decision: admins any course, professors assigned courses only."""
+    if user.role == "admin":
+        return True
+    if user.role == "professor":
+        return course_id in (user.courses or [])
+    return False
+
+
 # -----------------------------------------------------------------------------
 # REST API Endpoints
 # -----------------------------------------------------------------------------
@@ -127,11 +144,30 @@
 
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
+    user = current_user()
+    if user is None:
+        return {"error": "authentication required"}, 401
+    if user.role not in GRADE_WRITE_ROLES:
+        return {"error": "forbidden"}, 403
+
+    data = flask.request.get_json(silent=True)
+    if not isinstance(data, dict):
+        return {"error": "invalid request body"}, 400
+
+    student_id = data.get("student_id")
+    course_id = data.get("course_id")
+    grade = data.get("grade")
+    if (
+        type(student_id) is not int
+        or not isinstance(course_id, str)
+        or not course_id
+        or type(grade) not in (int, float)
+        or not 0 <= grade <= 20
+    ):
+        return {"error": "invalid grade update"}, 400
 
-    student_id = data["student_id"]
-    course_id = data["course_id"]
-    grade = data["grade"]
+    if not can_update_grade(user, course_id):
+        return {"error": "forbidden"}, 403
 
     row = find_grade(student_id, course_id)
     if row is None:
The control
Authentication (R1, 401): the session’s user must resolve to a record in USERS. An anonymous, logged-out or unknown user is rejected before the body is read.
Role check (R3, 403): only professor and admin may write; the check is deny-by-default, so any other or future role gets 403. Students are rejected before the body is parsed, so they always get 403, never 400.
Per-record scope (R4, 403): a professor’s course_id must be in their assigned courses. The check runs once, before find_grade, so it covers both the in-place update and the append.
Server-side authority: role and courses come from USERS, not from the role and courses values copied into the session cookie at login. A test that tampers with those cookie fields confirms they are ignored.
Invalid input (R7, 400): a non-JSON body, a missing field or a wrong type previously raised into the catch-all handler, which returned a 500 carrying the exception text. These now return a fixed 400 message and leave GRADES untouched.

The success response is unchanged: {"status": "ok", "student_id", "course_id", "grade"} with 200.

Affected paths
Writes to GRADES: update_grade() is the only writer. Its two branches (row["grade"] = grade and GRADES.append(...)) are both behind the new checks.
Reads needing the same control (not patched, out of scope): these need the same current_user() plus per-record pattern and should be filed as separate findings.
GET /grades/<student_id> has no authentication or ownership check, so anyone can read any student’s grades. R3 covers reads too.
GET /students/<student_id>/profile has the same problem and exposes name and email.
Assumptions and limitations
Grade range: I assumed a 0–20 scale and numeric grades (int or float). Adjust the bound if that is wrong; it is one line.
Session forgery: SECRET_KEY = "dev-secret-key" is hardcoded, so anyone who knows it can forge a cookie with user=admin1 and pass every check. This patch cannot fix that; the key must come from a secret store.
No enrollment check: a professor can create a grade in their own course for any integer student_id, including a nonexistent one. The app has no enrollment data to check against.
Role changes: these take effect immediately for writes, but /me still shows the values captured at login.
Global error handler: it still returns str(exc) and the class name, and turns 404 and 405 into 500. I removed the ways update_grade could reach it, but the handler itself still conflicts with R7.
Other issues seen, untouched: /files path traversal, debug=True on 0.0.0.0, plaintext passwords, no CSRF protection on the cookie-authenticated POST, and no audit log of grade changes.
Suggested regression tests

These are the extra cases I ran; all pass against the patched file.

An anonymous request with a malformed or non-JSON body returns 401, not 400 or 500.
A student cannot update another student’s grade, cannot create a record in a new course, and gets 403 even with an empty body.
After logout, a former professor’s update returns 401 and data is unchanged.
A student session with role and courses tampered to admin values still gets 403.
A session naming a user not in USERS gets 401.
As admin, each invalid body returns 400 with no type field and no data change: null, a list, missing fields, a string student_id, a list course_id, a string grade, 21, -1 and true.
A professor can create a new record in an assigned course (the positive case for the append branch).
The success response body matches the original contract exactly.
