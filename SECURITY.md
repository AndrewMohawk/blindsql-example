# Security notice

This repository is deliberately vulnerable. It is a small, synthetic training
target for learning time-based blind SQL injection.

- Run it only on a machine and network you control.
- The included Compose file binds to `127.0.0.1` by default.
- Do not connect this application to production data or credentials.
- Do not reuse its authentication design in a real application.
- If you expose it beyond localhost, add an isolated reverse proxy, resource
  limits, monitoring, and appropriate network access controls.

The vulnerable query is intentionally separated from the real parameterized
authentication query. This makes the timing oracle useful without allowing a
simple SQL comment to authenticate.
