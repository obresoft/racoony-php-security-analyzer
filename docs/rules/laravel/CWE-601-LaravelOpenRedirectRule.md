# CWE-601: Laravel Open Redirect

## Summary

This rule detects **potential open redirect vulnerabilities** in Laravel applications when a redirect destination is derived from **user-controlled input**.

It flags cases where request data (query/body/cookies/headers/superglobals) is used to build redirect URLs via Laravel redirect APIs.

Mapped to:

**CWE-601 — URL Redirection to Untrusted Site (Open Redirect)**

---

## Rule implementation overview

This rule is implemented by the `LaravelOpenRedirectRule::class`.

The rule performs the following checks:

### 1. Redirect Sink Detection
Detects calls to redirect methods considered dangerous (e.g. `redirect()->to(...)`, `redirect()->away(...)`, `Redirect::to(...)`, `Redirect::away(...)`, and similar).

### 2. Request / User Input Tracking
Reports when any redirect argument resolves to user-controlled input, including:
- Laravel `Request` accessors (e.g. `input()`, `get()`, `post()`, `query()`, `cookie()`, `header()`, `json()`)
- PHP superglobals (e.g. `$_GET`, `$_POST`)
- Other user input sources recognized by the generic input analyzer

---

## Why This Matters

Open redirects can be abused to:

- redirect users to phishing pages while using a trusted domain
- bypass allowlists in client-side navigation logic
- aid credential theft and social engineering campaigns
- chain with other issues (e.g. OAuth redirect_uri abuse)

Even if no data is directly leaked, open redirects often have real-world impact in authentication and payment flows.

---

## What the Rule Does

The rule reports a vulnerability when:

- A dangerous redirect method is called, and
- The redirect destination is derived from user-controlled input