# CWE-639: Spatie Query Builder Authorization Bypass

## Summary

This rule detects cases where **user-controlled input** is passed into Spatie Query Builder `allowedIncludes()` or `allowedFields()`.

If these values are not fixed server-side, an attacker may request unauthorized relations or fields.

Mapped to:

**CWE-639 — Authorization Bypass Through User-Controlled Key**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Spatie Query Builder Method Detection
Detects calls to:
- `allowedIncludes()`
- `allowedFields()`

### 2. Package Context Validation
Ensures the call belongs to **spatie/laravel-query-builder**.

### 3. User Input Detection
Reports a vulnerability when the argument comes from:
- Laravel request input
- generic user-controlled input sources such as `$_GET`
- variables or nested values resolving to user input

Literal arrays are treated as safe allow-lists.

---

## Why This Matters

If clients can control includes or sparse fieldsets directly, they may be able to request:

- hidden relations
- unauthorized related resources
- sensitive fields not intended for exposure

This can lead to authorization bypass and data exposure.

---

## What the Rule Does

The rule reports a vulnerability when:

- `allowedIncludes()` or `allowedFields()` is called on Spatie Query Builder, and
- the argument is user-controlled
