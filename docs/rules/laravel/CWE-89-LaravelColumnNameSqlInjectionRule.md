# CWE-89: Laravel Column Name SQL Injection

## Summary

This rule detects SQL Injection vulnerabilities caused by passing **user-controlled input into SQL identifier positions** in Laravel Query Builder and Eloquent methods.

It focuses on dynamic:

- Column names
- Table names
- Raw SQL fragments

Mapped to:

**CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)**

---

## Rule implementation overview

This rule is implemented by the `LaravelColumnNameSqlInjectionRule::class`.

The rule performs the following checks:

### 1. Sink Detection
Identifies risky Query Builder and Eloquent methods where identifiers are interpreted as raw SQL.

### 2. Laravel Context Validation
Ensures the call belongs to:
- DB facade usage
- Eloquent model query builder chains

### 3. Source Tracking
Tracks whether arguments originate from:
- Request::input()
- Request::query()
- Other Laravel request accessors
- Variables previously assigned from request data

---

## Why This Matters

Laravel parameter binding protects **values**, but it does **not sanitize SQL identifiers** such as column names or table names.

Example:
```php
    $sort = $request->query('sort');
    DB::table('users')->orderByRaw($sort)->get();
```

In such cases, attackers may manipulate query structure.

Potential impact:

- Arbitrary SQL execution
- Query manipulation
- Unauthorized data access

---

## What the Rule Does

The rule reports a vulnerability when:

- A risky Query Builder or Eloquent method is called
- A SQL identifier or raw fragment is dynamically constructed
- The value originates from user-controlled input

The rule does not report issues when:

- Strict whitelisting is applied
- Only bound values (not identifiers) are dynamic
- Static SQL expressions are used
- Safe mapping logic is enforced

---

This rule enhances Laravel-specific SQL injection detection in Racoony by focusing on dynamic identifier misuse patterns.