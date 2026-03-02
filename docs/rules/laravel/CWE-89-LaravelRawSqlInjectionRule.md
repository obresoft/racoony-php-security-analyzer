# CWE-89: Laravel Raw SQL Injection

## Summary

This rule detects **SQL Injection risks** when user-controlled input is used inside **raw SQL execution paths** in Laravel.

It targets dangerous raw SQL APIs such as `DB::statement()`, `DB::raw()`, `whereRaw()`, `fromRaw()`, `unprepared()`, `selectRaw()`, and related methods.

Mapped to:

**CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)**

---

## Rule implementation overview

This rule is implemented by the `LaravelRawSqlInjectionRule::class`.

The rule performs the following checks:

### 1. Raw SQL Sink Detection
Detects calls to a configured list of raw SQL methods (e.g. `statement`, `raw`, `whereRaw`, `fromRaw`, `unprepared`, `selectRaw`, `insertUsing`, `orWhere`, etc.).

### 2. Laravel Context Validation
Runs only when the call is in a Laravel SQL context:
- DB facade usage, or
- Eloquent model query builder chains

### 3. Request Source Tracking
Inspects method arguments and reports a vulnerability when:
- a `Request::*()` method call is used directly as an argument, or
- a variable argument resolves to a value originating from `Request::*()`

This rule intentionally flags cases where **bindings exist but only protect values**, while user input still affects raw SQL fragments.

---

## Why This Matters

Raw SQL APIs are frequently misused under the assumption that parameter binding always prevents SQL injection.

In practice:

- bindings protect **values**
- they do not make it safe to inject **SQL fragments, identifiers, or clauses**
- direct string concatenation into SQL is high-risk

Impact can include:

- query manipulation
- unauthorized data access
- data modification or destruction (e.g. `DROP TABLE`)
- full SQL injection depending on the sink and DB permissions

---

## What the Rule Does

The rule reports a vulnerability when:

- A raw SQL method is called, and
- Any argument is derived from Laravel `Request` input (directly or via variable assignment)
