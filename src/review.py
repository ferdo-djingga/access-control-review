"""
Access Control Compliance Review Tool
- Cross-check a user access list against the official policy role catalog.
- Flag common violations (unknown roles, role not allowed for department,
  inactive users with active access, duplicate entries, stale accounts).

Input (CSV):
- access_list.csv with columns:
    user_id,user_name,department,role,status,last_login
  - status: "active" or "inactive"
  - last_login: ISO date "YYYY-MM-DD"

- policy_roles.csv with columns:
    role,department_allowed,description
  - department_allowed: comma-separated list of allowed departments or "*"

Output:
- violations.csv with columns:
    user_id,user_name,department,role,issue,severity,details

CLI:
    python src/review.py \
        --input data/access_list.csv \
        --policy data/policy_roles.csv \
        --out output/violations.csv \
        --stale-days 90
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple, Iterable, Optional


# Data Models
@dataclass(frozen=True)
class AccessRow:
    user_id: str
    user_name: str
    department: str
    role: str
    status: str
    last_login: Optional[datetime]

@dataclass(frozen=True)
class PolicyRole:
    role: str
    allowed_departments: Set[str]
    description: str


@dataclass
class Violation:
    user_id: str
    user_name: str
    department: str
    role: str
    issue: str
    severity: str
    details: str


# CSV Helpers
def read_access_list(path: Path) -> List[AccessRow]:
    required = {"user_id", "user_name", "department", "role", "status", "last_login"}
    rows: List[AccessRow] = []

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")

        for i, r in enumerate(reader, start=2):
            last_login_raw = (r.get("last_login") or "").strip()
            last_login_dt: Optional[datetime] = None
            if last_login_raw:
                try:
                    last_login_dt = datetime.strptime(last_login_raw, "%Y-%m-%d")
                except ValueError:
                    raise ValueError(
                        f"{path}: line {i}: invalid date '{last_login_raw}' "
                        f"(expected YYYY-MM-DD)"
                    )

            rows.append(
                AccessRow(
                    user_id=(r["user_id"] or "").strip(),
                    user_name=(r["user_name"] or "").strip(),
                    department=(r["department"] or "").strip(),
                    role=(r["role"] or "").strip(),
                    status=(r["status"] or "").strip().lower(),
                    last_login=last_login_dt,
                )
            )

    return rows


def read_policy_roles(path: Path) -> Dict[str, PolicyRole]:
    required = {"role", "department_allowed", "description"}
    roles: Dict[str, PolicyRole] = {}

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")

        for i, r in enumerate(reader, start=2):
            role = (r["role"] or "").strip()
            if not role:
                raise ValueError(f"{path}: line {i}: empty role")

            dep_raw = (r.get("department_allowed") or "").strip()
            if not dep_raw:
                raise ValueError(f"{path}: line {i}: department_allowed is empty")

            allowed = {"*"} if dep_raw == "*" else {d.strip() for d in dep_raw.split(",") if d.strip()}
            roles[role] = PolicyRole(
                role=role,
                allowed_departments=allowed,
                description=(r.get("description") or "").strip(),
            )

    return roles


# Validation Logic
def find_duplicates(rows: Iterable[AccessRow]) -> Set[Tuple[str, str]]:
    """
    Return set of (user_id, role) pairs that appear more than once.
    """
    seen: Set[Tuple[str, str]] = set()
    dups: Set[Tuple[str, str]] = set()
    for r in rows:
        key = (r.user_id, r.role)
        if key in seen:
            dups.add(key)
        else:
            seen.add(key)
    return dups


def review_access(
    access_rows: List[AccessRow],
    policy_roles: Dict[str, PolicyRole],
    stale_days: int = 90,
) -> List[Violation]:
    violations: List[Violation] = []

    # Precompute duplicates
    duplicate_pairs = find_duplicates(access_rows)
    stale_cutoff = datetime.today() - timedelta(days=stale_days)

    for r in access_rows:
        # 1) Unknown role
        if r.role not in policy_roles:
            violations.append(
                Violation(
                    user_id=r.user_id,
                    user_name=r.user_name,
                    department=r.department,
                    role=r.role,
                    issue="UNKNOWN_ROLE",
                    severity="HIGH",
                    details="Role not found in policy catalog.",
                )
            )
            # If role is unknown, skip department check (no policy to compare)
            continue

        policy = policy_roles[r.role]

        # 2) Role not allowed for this department
        if "*" not in policy.allowed_departments and r.department not in policy.allowed_departments:
            violations.append(
                Violation(
                    user_id=r.user_id,
                    user_name=r.user_name,
                    department=r.department,
                    role=r.role,
                    issue="ROLE_NOT_ALLOWED_FOR_DEPARTMENT",
                    severity="HIGH",
                    details=(
                        f"Role '{r.role}' allowed only for departments: "
                        f"{', '.join(sorted(policy.allowed_departments))}"
                    ),
                )
            )

        # 3) Inactive user should not have any access
        if r.status not in {"active", "inactive"}:
            violations.append(
                Violation(
                    user_id=r.user_id,
                    user_name=r.user_name,
                    department=r.department,
                    role=r.role,
                    issue="INVALID_STATUS",
                    severity="MEDIUM",
                    details=f"Status must be 'active' or 'inactive' (got '{r.status}').",
                )
            )
        elif r.status == "inactive":
            violations.append(
                Violation(
                    user_id=r.user_id,
                    user_name=r.user_name,
                    department=r.department,
                    role=r.role,
                    issue="INACTIVE_USER_HAS_ACCESS",
                    severity="HIGH",
                    details="User is inactive but still assigned access.",
                )
            )

        # 4) Duplicate user-role entries
        if (r.user_id, r.role) in duplicate_pairs:
            violations.append(
                Violation(
                    user_id=r.user_id,
                    user_name=r.user_name,
                    department=r.department,
                    role=r.role,
                    issue="DUPLICATE_USER_ROLE_ENTRY",
                    severity="LOW",
                    details="Duplicate user-role assignment found.",
                )
            )

        # 5) Stale accounts (optional low severity)
        if r.last_login is not None and r.last_login < stale_cutoff and r.status == "active":
            days = (datetime.today() - r.last_login).days
            violations.append(
                Violation(
                    user_id=r.user_id,
                    user_name=r.user_name,
                    department=r.department,
                    role=r.role,
                    issue="STALE_ACCOUNT",
                    severity="LOW",
                    details=f"Last login {days} days ago; threshold is {stale_days} days.",
                )
            )

    return violations


def write_violations(path: Path, violations: List[Violation]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "user_id",
                "user_name",
                "department",
                "role",
                "issue",
                "severity",
                "details",
            ],
        )
        writer.writeheader()
        for v in violations:
            writer.writerow(
                {
                    "user_id": v.user_id,
                    "user_name": v.user_name,
                    "department": v.department,
                    "role": v.role,
                    "issue": v.issue,
                    "severity": v.severity,
                    "details": v.details,
                }
            )


def print_summary(violations: List[Violation]) -> None:
    print("\n=== Compliance Summary ===")
    print(f"Total violations: {len(violations)}")

    by_issue: Dict[str, int] = defaultdict(int)
    by_sev: Dict[str, int] = defaultdict(int)
    by_user: Dict[str, int] = defaultdict(int)

    for v in violations:
        by_issue[v.issue] += 1
        by_sev[v.severity] += 1
        by_user[f"{v.user_name} ({v.user_id})"] += 1

    if violations:
        print("\nBy severity:")
        for sev in sorted(by_sev.keys()):
            print(f"  {sev:<6} : {by_sev[sev]}")

        print("\nBy issue:")
        for issue in sorted(by_issue.keys()):
            print(f"  {issue:<32} : {by_issue[issue]}")

        # Top 5 users with most violations
        print("\nTop users with violations:")
        top = sorted(by_user.items(), key=lambda kv: kv[1], reverse=True)[:5]
        for user, count in top:
            print(f"  {user:<30} : {count}")
    print()


# CLI
def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Cross-check access_list.csv against policy_roles.csv and output violations."
    )
    p.add_argument("--input", required=True, help="Path to access_list.csv")
    p.add_argument("--policy", required=True, help="Path to policy_roles.csv")
    p.add_argument("--out", required=True, help="Path to output violations.csv")
    p.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="Days of inactivity to flag 'STALE_ACCOUNT' (default: 90)",
    )
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    access_path = Path(args.input)
    policy_path = Path(args.policy)
    out_path = Path(args.out)

    try:
        access_rows = read_access_list(access_path)
        policy_roles = read_policy_roles(policy_path)
        violations = review_access(access_rows, policy_roles, stale_days=args.stale_days)
        write_violations(out_path, violations)
        print_summary(violations)
        print(f"Wrote {len(violations)} violations to: {out_path}")
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))