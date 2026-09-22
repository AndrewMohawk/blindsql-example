# BlindSQL Example

A deliberately vulnerable, synthetic web application for practicing
time-based blind SQL injection. The challenge is to recover the randomly
generated administrator password from response timing, then log in normally
to reveal the flag.

> **Warning**
> This is an intentionally vulnerable training target. Run it only in an
> isolated environment that you control. Never connect it to production data
> or credentials.

## Quick start

Requirements: Docker with the Compose plugin, Bash, and OpenSSL.

```sh
./bin/setup
docker compose up --build -d
curl -fsS http://127.0.0.1:8080/healthz
```

Open <http://127.0.0.1:8080/>. Stop the lab with:

```sh
docker compose down
```

`bin/setup` creates a mode-600 `.env` containing a random administrator
password, flag, and Flask session secret. The file is ignored by Git. Run
`./bin/setup --rotate` to replace all three and then recreate the container.

## Challenge behavior

The submitted username is used by two independent queries:

1. An intentionally interpolated lookup executes injected predicates and the
   bounded `sleep_ms(n)` function. Its result is discarded completely.
2. A separate parameterized query is the only authentication decision.

Consequently, `admin' --` with a wrong password always fails. A useful probe
shape is:

```text
admin' AND (CASE WHEN <predicate> THEN sleep_ms(100) ELSE 0 END)=1 --
```

`sleep_ms()` returns integer `0`, clamps sleeps to 250 ms, and rejects invalid
or negative values. A false predicate and a true predicate therefore return
the same 401 response; only the true predicate adds a bounded delay.

Example controls:

```sh
curl -sS -o /dev/null -w 'control %{http_code} %{time_total}\n' \
  --data-urlencode "username=admin' AND (CASE WHEN 1=0 THEN sleep_ms(100) ELSE 0 END)=1 -- " \
  --data-urlencode 'password=wrong' \
  http://127.0.0.1:8080/

curl -sS -o /dev/null -w 'delayed %{http_code} %{time_total}\n' \
  --data-urlencode "username=admin' AND (CASE WHEN 1=1 THEN sleep_ms(100) ELSE 0 END)=1 -- " \
  --data-urlencode 'password=wrong' \
  http://127.0.0.1:8080/
```

Both should return 401, while the delayed request should take approximately
100 ms longer when measured repeatedly.

## Tests

The test stage is separate from the runtime image:

```sh
docker build --target test -t blindsql-example:test .
docker run --rm blindsql-example:test
```

Tests prove that:

- control and delayed probes have byte-identical failure responses;
- the delayed probe adds approximately 100 ms;
- comment injection cannot authenticate;
- SQL errors match ordinary invalid-credential failures; and
- the real administrator credential still authenticates.

## Isolation and observability

The default Compose service:

- binds only to `127.0.0.1:8080`;
- runs as unprivileged UID/GID 10001;
- has a read-only root filesystem and no host mounts;
- drops all Linux capabilities and enables `no-new-privileges`;
- limits CPU, memory, processes, and concurrent in-flight work; and
- creates a separate in-memory SQLite connection for each request.

Two Gunicorn workers with four threads each permit concurrent timing tests
without a global query lock. Structured logs contain request/query monotonic
timestamps, worker and thread IDs, received HTTP protocol, and final status.
They never contain usernames, passwords, cookies, flags, or session tokens.

The included server speaks HTTP/1.1. Put a suitably configured reverse proxy
in front if your experiment requires client-facing TLS or HTTP/2, and remember
that a reverse proxy terminates and reconstructs the connection—it is not an
end-to-end shared TLS gate.
