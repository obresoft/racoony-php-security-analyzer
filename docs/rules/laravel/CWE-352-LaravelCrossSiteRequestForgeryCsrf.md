# CWE-352: Laravel Missing VerifyCsrfToken Middleware in Web Group

## Summary

This rule detects Laravel applications where the `VerifyCsrfToken` middleware is **missing from the `web` middleware group** (Laravel `< 11` kernel-based middleware configuration).

If CSRF protection is not applied to web routes, state-changing requests may be vulnerable to **Cross-Site Request Forgery (CSRF)**.

Mapped to:

**CWE-352 — Cross-Site Request Forgery (CSRF)**

---

## Rule implementation overview

This rule is implemented by the `LaravelCrossSiteRequestForgeryCsrf::class`.

## Why This Matters

CSRF attacks allow an attacker to trick an authenticated user’s browser into sending unwanted requests to your application.

If CSRF protection is not enforced for web routes, attackers may be able to:

- perform state-changing actions on behalf of the user
- exploit authenticated sessions without user intent
- modify sensitive data via crafted links/forms

---

## What the Rule Does

The rule reports a vulnerability when:

- `App\Http\Kernel` defines `middlewareGroups`
- the `web` group does not include `VerifyCsrfToken` (directly or via alias/inheritance)

It does not report issues when:

- `VerifyCsrfToken` is present in the `web` group
- the application is Laravel `>= 11` (this rule does not evaluate the new middleware configuration style)