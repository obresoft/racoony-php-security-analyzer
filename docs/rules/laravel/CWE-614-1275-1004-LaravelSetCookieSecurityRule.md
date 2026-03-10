# CWE-614 / CWE-1275 / CWE-1004: Laravel Session Cookie Security Flags

## Summary

This rule detects insecure Laravel session cookie configuration in `config/session.php`.

It checks whether session cookies are protected with:

- `secure`
- `http_only`
- `same_site`

Mapped to:

- **CWE-614** — Sensitive Cookie in HTTPS Session Without `Secure` Attribute
- **CWE-1275** — Sensitive Cookie with Improper SameSite Attribute
- **CWE-1004** — Sensitive Cookie Without `HttpOnly` Flag

---

## Rule implementation overview

The rule performs the following checks:

### 1. Session Config Detection
Runs only for Laravel `config/session.php` files.

### 2. Cookie Security Flag Validation
Checks whether the session config contains:
- `http_only`
- `secure`
- `same_site`

### 3. Secure Value Validation
Reports a vulnerability when:
- `http_only` is missing or not `true`
- `secure` is missing or not `true`
- `same_site` is missing or not set to `strict` or `lax`

---

## Why This Matters

Missing cookie security flags can weaken session protection and increase the risk of:

- cookie theft through XSS
- cookies being sent over insecure HTTP
- cross-site request abuse

These flags are part of the baseline hardening for Laravel session cookies.

---

## What the Rule Does

The rule reports a vulnerability when:

- `http_only` is missing or disabled
- `secure` is missing or disabled
- `same_site` is missing or uses an insecure value
