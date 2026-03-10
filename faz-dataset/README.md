# faz-dataset — Claude Code Skill

A [Claude Code skill](https://docs.anthropic.com/en/docs/claude-code/skills) that turns Claude into an expert at writing **FortiAnalyzer dataset queries** for use under **Reports > Datasets** (or Report Templates > Chart Dataset) in the FAZ GUI.

## What it does

When invoked, the skill loads:

- The FAZ SQL dialect reference (macros, syntax, query skeletons, hcache patterns)
- Only the column-reference file that matches the requested log type

Claude then writes a complete, working query and explains any non-obvious clauses.

## Supported log types

| Log type | Table alias |
|---|---|
| Traffic | `$log` → `*_tlog` |
| Event | `$log` → `*_elog` |
| Web Filter | `$log` → `*_wlog` |
| App Control | `$log` → `*_alog` |
| Antivirus | `$log` → `*_vlog` |
| IPS / Security | `$log` → `*_slog` |

## Usage

Install the skill, then in any Claude Code session just describe what you want:

```
/faz-dataset  show top 10 sources by bytes for FortiGate traffic logs
```

Or let it trigger automatically when you paste a FAZ dataset question.

## Key conventions enforced

- Always `FROM $log` — never a hardcoded table name
- Always `WHERE $filter` — mandatory time/device scope
- `${REPORT_SESSION}` for bandwidth/session queries
- `###(subquery)###` for hcache cached subqueries
- ClickHouse SQL functions: `toDateTime()`, `formatDateTime()`, `ipstr()`, `arrayJoin()`, `has()`, `bitAnd()`, `multiIf()`

## Installation

Copy this directory into your Claude Code skills folder:

```
~/.claude/skills/faz-dataset/
```

Claude Code will detect `SKILL.md` and register the skill automatically.
