# CWE-215: Debug Function Exposure

## Summary

This rule detects **debug functions, debug methods, and debug-style output** that may expose internal application data.

It targets patterns such as `var_dump()`, `print_r()`, `phpinfo()`, `debug_backtrace()`, `dump()`, `dd()`, debug logger methods, and echoing debug output.

Mapped to:

**CWE-215 — Information Exposure Through Debug Information**

---

## Rule implementation overview

The rule performs the following checks:

### 1. Debug Function Detection
Detects calls to known debug-related functions such as:
- `var_dump()`
- `print_r()`
- `var_export()`
- `phpinfo()`
- `debug_backtrace()`
- `dump()`
- `dd()`
- `error_log()`
- Xdebug debug functions

### 2. Debug Method Detection
Detects debug-style method calls such as:
- `->dump()`
- `->debug()`

### 3. Debug Echo Detection
Detects `echo` statements that directly output debug functions like `print_r()` or `var_export()`.

### 4. Sensitive Debug Argument Detection
Raises an additional finding when `var_dump()` or `print_r()` is used on sensitive variables such as session or database configuration data.

---

## Why This Matters

Debug output left in production code can expose:

- server configuration
- session data
- internal variables
- database configuration
- stack traces and execution flow

This may help attackers understand the system and extract sensitive information.

---

## What the Rule Does

The rule reports a vulnerability when:

- A known debug function is used
- A debug-style method is called
- Debug output is echoed
- Sensitive variables are dumped with debug functions
