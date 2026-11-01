---
name: Bug Report
about: Create a report to help improve CCK agent reliability
title: "[BUG] "
labels: ["bug"]
assignees: []
---

## Describe the Bug
A clear and concise description of the failure mode, unexpected ALLOW/BLOCK verdict, or drift detection issue.

## Steps to Reproduce
1. Register Fact: `...`
2. Register Dependency: `...`
3. Dispatch Action Gate payload: `...`
4. See error or unexpected verdict

## Expected Behavior
Expected decision outcome (`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, `REVALIDATE`) and reasoning.

## CCK Decision Receipt
Paste the Decision Receipt ID or JSON export:
```json
{
  "receipt_id": "rcpt-..."
}
```

## Environment
- OS: [e.g. Linux Ubuntu 22.04, macOS, Windows]
- Runtime: [e.g. Node.js 22, Python 3.11]
- CCK Version: [e.g. 0.2.0-rc1]
