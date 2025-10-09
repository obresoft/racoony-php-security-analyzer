# Changelog

All notable changes to **Racoony PHP Security Analyzer** will be documented in this file.

---

## [0.0.0] - 2025-10-09
### Added
- Initial **preview release** of Racoony 🎉
- Core CLI scanner with `.racoony-config.php` configuration support
- Minimum PHP requirement: `8.3`

#### Generic rules
- **CWE-532** — Missing `#[\SensitiveParameter]` attribute on sensitive parameters
- **CWE-94** — Code injection via `eval` or unsafe dynamic code execution
- **CWE-77** — Command injection (`exec`, `system`, `shell_exec`, etc.)
- **CWE-215** — Information exposure via debug functions (`var_dump`, `dd`, `print_r`, etc.)
- **CWE-315 / CWE-614 / CWE-1275 / CWE-1004** — Sensitive cookie misconfigurations (`HttpOnly`, `Secure`, `SameSite`)

#### Laravel-specific rules
- **CWE-915** — Mass assignment risks (`$fillable` / unguarded models)
- **CWE-352** — Missing CSRF middleware (`VerifyCsrfToken`)
- **CWE-94** — Insecure callable execution from request data (`call_user_func`, etc.)
- **CWE-601** — Open redirect detection
- **CWE-89** — SQL injection (raw queries and unsafe query-builder usage)
    - `LaravelColumnNameSqlInjectionRule`
    - `LaravelRawSqlInjectionRule`

#### Spatie Query Builder rules
- **CWE-639** — Authorization bypass via `allowedFields` / `allowedIncludes`
- **CWE-89** — SQL injection via `allowedSorts` / `defaultSort`

---
