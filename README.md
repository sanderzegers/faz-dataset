# faz-dataset — Claude Code Skill

A [Claude Code skill](https://docs.anthropic.com/en/docs/claude-code/skills) that turns Claude into an expert at writing **FortiAnalyzer dataset queries** for use under **Reports > Datasets** (or Report Templates > Chart Dataset) in the FAZ GUI.

## What it does

When invoked, the skill loads:

- The FAZ SQL dialect reference (macros, syntax, query skeletons, hcache patterns)
- Only the column-reference files for the log types the query needs

Claude then writes a complete, working query and explains any non-obvious clauses.

## Supported log types

| Log type | Log source | Column file |
|---|---|---|
| Traffic | `$log-traffic` | `cols-tlog.md` |
| Event | `$log-event` | `cols-elog.md` |
| Web Filter | `$log-webfilter` | `cols-wlog.md` |
| App Control | `$log-app-ctrl` | `cols-alog.md` |
| Antivirus | `$log-virus` | `cols-vlog.md` |
| IPS / Attack | `$log-attack` | `cols-slog.md` |
| DNS Filter | `$log-dns` | `cols-dlog.md` |
| DLP | `$log-dlp` | `cols-dlp.md` |
| Email Filter | `$log-emailfilter` | `cols-emailfilter.md` |
| File Filter | `$log-file-filter` | `cols-file-filter.md` |
| FortiClient Event / Traffic | `$log-fct-event` / `$log-fct-traffic` | `cols-fct-event.md` / `cols-tlog.md` |
| SSL, SSH, WAF, Network Scan, Security, GTP, Content, VoIP, Protocol, SIEM, Anomaly, ICAP, Virtual Patch | `$log-<type>` | `cols-<type>.md` |

It also covers the ADOM reference tables, the SOC tables (`$event`, `$incident`), and the `fv_*` materialized views.

The traffic, attack, webfilter and event column files have been checked against real FAZ schemas. The others are documented from reference material and may contain columns that don't exist. `SELECT * FROM $log-<type> WHERE $filter LIMIT 1` lists the real columns for a log type.

## Usage

Install the skill, then in any Claude Code session just describe what you want:

```
/faz-dataset  show top 10 sources by bytes for FortiGate traffic logs
```

Or let it trigger automatically when you ask a FAZ dataset question.

## Key conventions enforced

- `FROM $log-<type>` — never a hardcoded table name
- `WHERE $filter` — mandatory time/device scope
- `bitAnd(logflag,1)>0` for sessions, `bitAnd(logflag,bitOr(1,32))>0` for bandwidth
- `###(subquery)###` hcache with `/*SkipSTART*/ORDER BY.../*SkipEND*/`
- `ipstr()` for IPs, `nullifna()` for `user`/`app` fields
- `${...}` macro logic written inline. Most macros (e.g. `${USER}`, `${THREAT_*}`) don't expand in custom datasets; `${REPORT_SESSION}` does
- FAZ helpers in snake_case (`regexp_replace`, `ip_subnet`); ClickHouse functions such as `isIPAddressInRange()` where tested

## Installation

Copy the `faz-dataset/` directory into your Claude Code skills folder:

```
~/.claude/skills/faz-dataset/
```

Claude Code detects `SKILL.md` and registers the skill automatically.

## Documentation

This repo also includes a detailed guide to writing FortiAnalyzer dataset queries — not specific to the Claude skill, but useful for understanding how FAZ SQL works:

**[FortiAnalyzer Dataset Query Writing Guide](faz-dataset-query-guide.md)**

Topics covered: query structure, execution model, macros, hcache, performance, and practical patterns.
