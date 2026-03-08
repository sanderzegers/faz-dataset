# faz-dataset — Claude Code Skill

A [Claude Code skill](https://docs.anthropic.com/en/docs/claude-code/skills) that turns Claude into an expert at writing **Fortinet FortiAnalyzer dataset queries** for use in:

- **Reports → Datasets**
- **Report Templates → Chart Dataset**

The skill helps generate **correct, production-ready FAZ dataset queries** using the FortiAnalyzer SQL dialect.

This Claude Code Skill is designed for FortiAnalyzer 7.6 and later.

------

# What the Skill Does

When invoked, the skill loads:

- The **FortiAnalyzer SQL dialect reference**
   (macros, syntax, query skeletons, hcache patterns)
- The **column reference file for the requested log type only**
   (to keep context focused and reduce hallucinations)

Claude then:

1. Writes a **complete dataset query**
2. Ensures it follows **FAZ dataset conventions**
3. Explains any **non-obvious clauses or functions**

------

# Supported Log Types

| Log Type       | `$log` Alias Resolves To |
| -------------- | ------------------------ |
| Traffic        | `*_tlog`                 |
| Event          | `*_elog`                 |
| Web Filter     | `*_wlog`                 |
| App Control    | `*_alog`                 |
| Antivirus      | `*_vlog`                 |
| IPS / Security | `*_slog`                 |

------

# Usage

After installing the skill, you can simply describe the dataset you want.

Example:

```
/faz-dataset show top 10 sources by bytes for FortiGate traffic logs
```

Claude will generate a **complete FortiAnalyzer dataset query** ready to paste into:

```
Reports → Datasets
```

The skill may also **trigger automatically** when you ask a FortiAnalyzer dataset-related question.

------

# Query Conventions Enforced

The skill ensures queries follow FortiAnalyzer best practices:

- Always use:

```
FROM $log
```

Never hardcode log tables.

- Always include:

```
WHERE $filter
```

This ensures proper **time and device scoping**.

- Use `${REPORT_SESSION}` for **session / bandwidth queries**
- Use **hcache subqueries** when appropriate:

```
###(subquery)###
```

- Prefer **ClickHouse SQL functions**, including:

```
toDateTime()
formatDateTime()
ipstr()
arrayJoin()
has()
bitAnd()
multiIf()
```

------

# Installation

Copy the skill directory into your Claude Code skills folder:

```
~/.claude/skills/faz-dataset/
```

Claude Code will automatically detect:

```
SKILL.md
```

and register the skill.

------

# Documentation

This repository also includes a **detailed guide to writing FortiAnalyzer dataset queries**, covering:

- How FAZ dataset queries actually work
- Query structure and execution model
- Macros and hidden system behavior
- Performance considerations
- Practical query design patterns

See:

**Guide: Writing FortiAnalyzer Dataset Queries**

*[Guide: FortiAnalyzer Dataset Query Writing Guide](faz-dataset-query-guide.md)*

This guide is **not specific to the Claude skill** and can be useful when writing FAZ dataset queries manually.
