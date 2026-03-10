# CWE-89: Spatie Query Builder SQL Injection

## Summary

This rule detects **SQL Injection risks** in `spatie/laravel-query-builder` when **user-controlled identifiers or raw SQL fragments** are used in sorting or filter callbacks.

It targets dangerous uses of:

- `allowedSorts()`
- `defaultSort()`
- `allowedFilters()`

Mapped to:

**CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Spatie Query Builder Method Detection
Detects calls to:
- `allowedSorts()`
- `defaultSort()`
- `allowedFilters()`

### 2. Package Context Validation
Ensures the call belongs to **spatie/laravel-query-builder**.

### 3. User Input Detection
Reports a vulnerability when sort or filter definitions use:
- Laravel request input
- generic user-controlled input
- variables resolving to request data

### 4. Callback and Custom Sort Inspection
Also inspects:
- `AllowedSort::custom(...)`
- `AllowedFilter::callback(...)`
- `AllowedFilter::scope(...)`

and reports when user-controlled data reaches SQL builder methods, especially raw SQL methods.

---

## Why This Matters

If user-controlled input is allowed to define sortable columns, raw filter logic, or SQL fragments, attackers may be able to:

- manipulate query structure
- inject unsafe column or order expressions
- abuse raw SQL callbacks
- access or alter unintended data

This is especially risky when callback filters use `whereRaw()` or dynamic column names.

---

## What the Rule Does

The rule reports a vulnerability when:

- Spatie Query Builder sorting or filtering APIs are used, and
- user-controlled data reaches SQL-sensitive arguments or callback logic