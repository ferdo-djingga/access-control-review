# Benchmark & Methodology

This document records the benchmark of my **Access Control Compliance Review Tool**
It shows how much faster the automated process is compared to manual review, and serves as reproducible audit evidence.  

---

## Goal

Quantify time saved in **User Access Reviews (UAR)** by comparing:

- **Manual review** (baseline, human effort) vs.  
- **Automated review** using `review.py`  

---

## Test Setup

- Dataset: `data/access_list.csv` (7 users, with duplicates and stale accounts)  
- Policy catalog: `data/policy_roles.csv` (6 valid roles)  
- Machine: macOS (Apple Silicon) laptop  
- Python: `python3`  
- Stale threshold: 90 days  

---

## Steps

### 1. Baseline (Manual)

- Reviewing 8 rows manually (check role, department, status, last login) typically takes about **2 minutes**.  
- Extrapolated to 1,000 rows → **4 hours 10 minutes**.  

### Program output
=== Compliance Summary ===
Total violations: 10

By severity:
  HIGH   : 3
  LOW    : 7

By issue:
  DUPLICATE_USER_ROLE_ENTRY        : 2
  INACTIVE_USER_HAS_ACCESS         : 1
  ROLE_NOT_ALLOWED_FOR_DEPARTMENT  : 1
  STALE_ACCOUNT                    : 5
  UNKNOWN_ROLE                     : 1

Top users with violations:
  Frank F (U006)                 : 4
  Claire C (U003)                : 2
  Alice A (U001)                 : 1
  Bob B (U002)                   : 1
  Daniel D (U004)                : 1

Wrote 10 violations to: output/violations.csv

### System Time Reported
0.04s user 0.02s system 61% cpu 0.096 total

## Results

### Actual Run (Demo Dataset)
| Method            | Rows Reviewed | Time Taken   | Notes                                     |
|-------------------|--------------:|-------------:|-------------------------------------------|
| Manual (baseline) | 8             | 2 minutes    | Assumes ~15 sec per row manually          |
| Automated         | 8             | 0.096 seconds| Measured with `time` command              |

### Extrapolated (Realistic Scale: 1,000 rows)
| Method            | Rows Reviewed | Time Taken   | Notes                                     |
|-------------------|--------------:|-------------:|-------------------------------------------|
| Manual (baseline) | 1,000         | 250 minutes  | Based on 2 min per 8 rows                 |
| Automated         | 1,000         | 12 seconds   | Scaled: 0.096 × (1000 ÷ 8) = 12.0 seconds |

---

## Time Savings

- **Demo dataset (8 rows):**  
  Manual ~2 minutes → Automated 0.096 seconds  
  → ~**99.9% faster**  

- **Realistic dataset (1,000 rows):**  
  Manual ~250 minutes (~4h 10m) → Automated ~12 seconds  
  → **>99.9% faster**  

**Improvement:**  
- Cuts hours of manual compliance checking into seconds.  
- Provides near **real-time audit evidence** with effective scalability.