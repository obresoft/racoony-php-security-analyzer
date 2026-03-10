# CWE-77: Command Injection

## Summary

This rule detects **command injection risks** when user-controlled input is passed into PHP shell execution functions.

It targets dangerous functions such as:

- `exec()`
- `system()`
- `shell_exec()`
- `passthru()`
- `popen()`
- `proc_open()`
- `pcntl_exec()`

Mapped to:

**CWE-77 — Improper Neutralization of Special Elements used in a Command (Command Injection)**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Shell Function Detection
Detects calls to dangerous shell execution functions.

### 2. User Input Detection
Reports a vulnerability when command arguments come from user-controlled input, including:
- superglobals such as `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SESSION`
- variables derived from those sources
- array/property access based on user input
- interpolated strings containing user input
- concatenated or ternary-built commands using user input

### 3. Raw Stream Input Detection
Also reports when raw input from:
- `php://input`
- `php://stdin`

is later used in shell execution.

### 4. Basic Safe Function Handling
Does not report when the command value is wrapped with recognized sanitizing functions such as `escapeshellcmd()`.

---

## Why This Matters

If user input is used in shell commands, attackers may be able to:

- execute arbitrary OS commands
- read or modify files
- pivot to remote code execution
- fully compromise the server depending on process privileges

Command injection is typically high impact and often critical in production systems.

---

## What the Rule Does

The rule reports a vulnerability when:

- A dangerous shell execution function is called, and
- The command argument is derived from user-controlled input