# Model and settings used

Fill in every field exactly as the interface displayed it.

| Field | Value |
|---|---|
| Model name and version (as displayed) | Claude Fable 5.2 Medium effort |
| Interface | web chat |
| Date of condition A | 14/11/26 |
| Date of condition B | 14/11/26 |
| Date of condition C | 14/11/26 |
| Date of repair conversations | 15/11/26 |

## Settings (discovery conversations A, B, C)

| Setting | Value |
|---|---|
| Fresh conversation for each condition | yes |
| Same model and settings for A, B and C | yes |
| Memory / reference to past chats | off |
| Custom instructions, project or connected sources | none |
| Web search | off |
| Code execution or other tools | off |
| Extended thinking / reasoning mode | off |
| Files supplied | only `baseline_secure_coding_api.py` |
| Requests per condition | no follow-up hints |
| Responses complete? | yes |

## Settings (repair conversations)

| Setting | Value |
|---|---|
| Separate conversation per repair | yes |
| Code execution available | yes: the model ran the tests in its own sandbox |
| Files supplied | `baseline_secure_coding_api.py`, `tests_security/conftest.py`, and the test file for that finding |
