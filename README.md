# Access Control Compliance Review Tool

A lightweight Python tool to **audit user access** against a **policy role catalog**.  
It flags common issues like **unknown roles**, **role not allowed for a department**, **inactive user with active access**, **duplicate user-role entries**, and **stale accounts**.

> Ideal Design for IT Audit / Tech Risk / Compliance, IT Operations, and Security teams.  
---

## Requirements

- Python 3.9+  
- No third-party packages required (uses Python standard library).

---

## Input Files

### `data/access_list.csv`
Columns:

| Column       | Notes                                  |
|--------------|----------------------------------------|
| user_id      | Unique user identifier                 |
| user_name    | Human-friendly name                    |
| department   | Department/team name                   |
| role         | Role assigned to this user             |
| status       | `active` or `inactive`                 |
| last_login   | ISO date `YYYY-MM-DD`                  |

### `data/policy_roles.csv`
Columns:

| Column             | Notes                                                         |
|--------------------|---------------------------------------------------------------|
| role               | Canonical role name                                           |
| department_allowed | Comma-separated list of allowed departments **or** `*` (all) |
| description        | Free text                                                     |

---

## How to Run

From the repository root:

```bash
python src/review.py \
  --input data/access_list.csv \
  --policy data/policy_roles.csv \
  --out output/violations.csv \
  --stale-days 90

After running, check:
	•	Terminal summary (violations by severity/issue and top users)
	•	output/violations.csv (machine-readable evidence for auditors)
