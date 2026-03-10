# CWE-315: Laravel Missing EncryptCookies Middleware in Web Group

## Summary

This rule detects Laravel applications where the `EncryptCookies` middleware is missing from the `web` middleware group.

Without this middleware, sensitive cookie data may be stored in cleartext.

Mapped to:

**CWE-315 — Cleartext Storage of Sensitive Information in a Cookie**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Laravel Kernel Detection
Runs for Laravel `< 11` when analyzing `App\Http\Kernel`.

### 2. Web Middleware Group Inspection
Reads the `middlewareGroups` property and looks for `EncryptCookies` in the `web` group.

### 3. Middleware Resolution
Supports:
- direct middleware class references
- imported aliases
- custom middleware classes extending `EncryptCookies`

---

## Why This Matters

If cookie encryption middleware is missing, sensitive values stored in cookies may be readable or tampered with by the client.

This can increase the risk of:

- exposure of sensitive cookie contents
- tampering with security-related state
- weakened session and authentication protection
