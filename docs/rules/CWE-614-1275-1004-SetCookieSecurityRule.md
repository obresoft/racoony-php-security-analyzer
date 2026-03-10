# CWE-614 / CWE-1275 / CWE-1004: Insecure `setcookie()` Security Flags

## Summary

This rule detects insecure usage of PHP `setcookie()` when cookie security flags are missing or unsafe.

It checks whether cookies are configured with:

- `secure`
- `httponly`
- `samesite`

Mapped to:

- **CWE-614** — Sensitive Cookie in HTTPS Session Without `Secure` Attribute
- **CWE-1275** — Sensitive Cookie with Improper SameSite Attribute
- **CWE-1004** — Sensitive Cookie Without `HttpOnly` Flag

---

## Rule implementation overview

The rule performs the following checks:

### 1. `setcookie()` Detection
Runs on calls to PHP `setcookie()`.

### 2. Options Array Resolution
Inspects the cookie options passed directly or through a variable-resolved array.

### 3. Security Flag Validation
Reports a vulnerability when:
- `secure` is missing
- `httponly` is missing
- `samesite` is missing or not set to `Strict` / `Lax`

---

## Why This Matters

Missing cookie security flags can increase the risk of:

- cookie theft via XSS
- cookies being sent over insecure transport
- cross-site request abuse
- weaker session and token protection

These flags are a basic hardening requirement for sensitive cookies.

---

## What the Rule Does

The rule reports a vulnerability when:

- `setcookie()` is called without a secure options array, or
- the cookie options are missing `secure`, `httponly`, or safe `samesite`