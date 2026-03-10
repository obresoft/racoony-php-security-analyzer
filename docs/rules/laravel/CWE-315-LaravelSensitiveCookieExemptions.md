# CWE-315: Laravel Sensitive Cookie Encryption Exemptions

## Summary

This rule detects cases where **sensitive cookies are excluded from Laravel cookie encryption**.

It flags risky cookie names such as session, CSRF, remember-me, and token-related cookies when they are added to encryption exemption lists.

Mapped to:

**CWE-315 — Cleartext Storage of Sensitive Information in a Cookie**

---

## Rule implementation overview

The rule performs the following checks:

### 1. EncryptCookies Configuration Detection
Checks Laravel cookie encryption exclusions in:
- `App\Http\Middleware\EncryptCookies` for Laravel `< 11`
- `bootstrap/app.php` middleware `encryptCookies([...])` for Laravel `>= 11`

### 2. Sensitive Cookie Name Matching
Reports when excluded cookies match sensitive names such as:
- session cookies
- CSRF / XSRF cookies
- remember-me cookies
- access / refresh / API / JWT token cookies

---

## Why This Matters

If sensitive cookies are excluded from encryption, their contents may be exposed or tampered with by the client.

This can increase the risk of:

- session tampering
- token leakage
- authentication bypass support
- exposure of security-sensitive state