import copy

import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def snapshot():
    return copy.deepcopy(api.GRADES)


# Supplied positive example (not assessed)
def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


# R3: administrators may update grades (legitimate operation)
def test_admin_can_update_grade(client):
    login(client, "admin1", "adminpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SRS", "grade": 12},
    )
    assert response.status_code == 200
    assert api.find_grade(1002, "SRS")["grade"] == 12


# R1/R7: unauthenticated update -> 401, data unchanged
def test_anonymous_cannot_update_grade(client):
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 401
    assert api.GRADES == before


# R3/R4: a student is authenticated but has no update permission -> 403
def test_student_cannot_update_own_grade(client):
    login(client, "alice", "alicepw")
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 403
    assert api.GRADES == before


# R3/R4: professor role alone is not enough; course must be assigned
def test_professor_cannot_update_unassigned_course(client):
    login(client, "prof_srs", "profpw")
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 20},
    )
    assert response.status_code == 403
    assert api.GRADES == before


# Variation: unassigned course with no existing record must not be created
# (catches a patch that only checks the update branch, not the append branch)
def test_professor_cannot_create_record_in_unassigned_course(client):
    login(client, "prof_srs", "profpw")
    before = snapshot()
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SSD", "grade": 20},
    )
    assert response.status_code == 403
    assert api.find_grade(1002, "SSD") is None
    assert api.GRADES == before
