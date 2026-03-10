# CWE-94: Code Injection

## Summary

This rule detects **code injection risks** when user-controlled input is used in dynamic code execution constructs such as `eval()` or dynamic file inclusion.

It also warns about `eval()` usage even when direct user input is not proven, because `eval()` is inherently dangerous.

Mapped to:

**CWE-94 — Improper Control of Generation of Code (Code Injection)**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Dangerous Code Execution Detection
Detects use of:
- `eval()`
- dynamic include/require expressions

### 2. User Input Tracking
Reports a vulnerability when the executed code or included path is derived from user-controlled input, including:
- direct superglobal access
- array/property access
- variables resolved from user input
- concatenated expressions containing user input

### 3. Eval Recommendation
If `eval()` is used and direct user input is not proven, the rule still reports a recommendation because `eval()` itself is a dangerous pattern.

---

## Why This Matters

Dynamic code execution can allow attackers to:

- execute arbitrary PHP code
- include unintended local or remote files
- bypass application logic
- fully compromise the application or server

Even partial control over evaluated code or included paths can become critical.

---

## What the Rule Does

The rule reports a vulnerability when:

- `eval()` or dynamic include/require is used, and
- the executed expression is derived from user-controlled input

The rule reports a recommendation when:

- `eval()` is used, even without confirmed user input flow
