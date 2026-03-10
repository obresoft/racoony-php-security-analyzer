# CWE-532: Missing #[SensitiveParameter] Attribute on Sensitive Parameters

## Summary

This rule detects function or method parameters with **sensitive-looking names** that are missing the PHP `#[\SensitiveParameter]` attribute.

It helps reduce accidental exposure of secrets in stack traces, logs, and error output.

Mapped to:

**CWE-532 — Insertion of Sensitive Information into Log File**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Parameter Detection
Analyzes function, method, and closure parameters.

### 2. Sensitive Name Heuristic
Checks whether the parameter name looks sensitive, for example:
- `password`
- `secret`
- `token`
- `apiKey`
- `creditCard`
- `ssn`

### 3. Attribute Presence Check
Reports a vulnerability when a sensitive parameter does not have the `#[\SensitiveParameter]` attribute.

---

## Why This Matters

Without `#[\SensitiveParameter]`, sensitive values may appear in:

- stack traces
- error logs
- debug output

This increases the risk of leaking credentials, tokens, or other secret data.

---

## What the Rule Does

The rule reports a vulnerability when:

- a parameter name matches a sensitive-name heuristic, and
- the parameter is missing `#[\SensitiveParameter]`