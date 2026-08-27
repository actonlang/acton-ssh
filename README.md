# ssh — SSH client and server for Acton

A callback-driven SSH client and server library for [Acton](https://www.acton-lang.org),
built on [libssh](https://www.libssh.org) and integrated with Acton's libuv
event loop. All I/O is non-blocking and exposed through the actor model: you
create actors and receive results via action callbacks.

It implements both sides of the protocol — an Acton client can talk to an
Acton server, to OpenSSH `sshd`, or be driven by the OpenSSH `ssh` client.

## Features

- **Client**: password and public-key authentication, host-key verification
  (known_hosts and/or an `on_hostkey` callback), connect/auth timeouts,
  keepalive.
- **Channels**: `exec`, `shell` (with optional PTY), and `subsystem` requests;
  stdout/stderr streaming; EOF, exit status, and close with a defined callback
  ordering. `RunCommand` is a convenience wrapper that buffers output.
- **Server**: password and public-key auth callbacks, `exec`/`subsystem`
  dispatch, per-channel data streaming, ephemeral-port binding, in-memory or
  file-based host keys, and admission limits (max sessions / channels).
- **Compression**: `zlib@openssh.com` and `zlib` are compiled in and offered
  during key exchange, so a peer that asks for compression gets it. libssh
  proposes `none` first, so it is never used unless the peer prefers it.
- **Hardened**: bounded teardown (a stalled peer can't wedge a close),
  per-channel write-buffer limits, an accept loop that survives
  per-connection failures, and no use-after-free under load (validated with
  `acton test stress`, an OpenSSH interop suite, and a leak-checked soak).

## Requirements

This package builds an unmodified upstream libssh release with the Zig wrapper
in [`deps/libssh`](deps/libssh). libuv supplies readiness notifications and the
binding advances libssh through its public nonblocking `ssh_event` API. The
dependency is declared in [`Build.act`](Build.act).

libssh's compression methods use zlib from the
[acton-zlib](https://github.com/actonlang/acton-zlib) package: the wrapper
compiles against the headers of the exact zlib source acton-zlib pins, and the
zlib objects reach the final executable link through the package dependency —
the same headers-here/objects-there split used for mbedtls. The zlib version is
pinned in one place (acton-zlib), and an executable that also uses the Acton
`zlib` package links a single copy.

libssh and its crypto backend (mbedtls) run on the C library heap with their
own ownership; only libuv and Acton objects live on the GC heap. See the
header comment in [`src/ssh.ext.c`](src/ssh.ext.c) for the full memory model.

## Building

```sh
acton build
```

## Quick start

### Client

```python
import net
import ssh

actor main(env):
    var client: ?ssh.Client = None

    def on_hostkey(c: ssh.Client, state: str, info: ssh.HostKeyInfo):
        # Verify info.fingerprint against a known value in production.
        c.accept_hostkey()

    def on_connect(c: ssh.Client, err: ?str):
        if err is not None:
            print("connect failed:", err)
            env.exit(1)
            return
        ssh.RunCommand(c, "uname -a", on_exit, timeout=30.0)

    def on_close(c: ssh.Client, reason: str):
        pass

    def on_exit(ch: ssh.Channel, code: int, sig: ?str, out: bytes, err: bytes, error: ?str):
        if error is None:
            print(out.decode(), end="")
        if client is not None:
            client.close()
        env.exit(code)

    client = ssh.Client(
        net.TCPConnectCap(net.TCPCap(net.NetCap(env.cap))),
        "example.com", "alice",
        on_connect, on_close, on_hostkey,
        password="secret", port=u16(22))
```

### Server

```python
import net
import ssh

actor main(env):
    def on_listen(s: ssh.Server, err: ?str):
        if err is None:
            print("listening")

    def on_auth(sess: ssh.ServerSession, req: ssh.AuthRequest):
        # req.method is "password" or "publickey". For publickey, libssh has
        # already verified the signature; just decide if req.pubkey is allowed.
        if req.method == "password" and req.password == "secret":
            sess.accept_auth()
        else:
            sess.reject_auth("denied")

    def on_channel_open(sess: ssh.ServerSession):
        sess.accept_channel(ssh.ServerChannel(sess, on_data, on_stderr, on_chan_close))

    def on_exec(sess: ssh.ServerSession, ch: ssh.ServerChannel, cmd: str):
        ch.accept_request()
        ch.write(("you ran: " + cmd + "\n").encode())
        ch.send_exit_status(0)
        ch.close()

    def on_data(ch, data): pass
    def on_stderr(ch, data): pass
    def on_chan_close(ch, reason): pass
    def on_server_close(s, reason): pass
    def on_session(sess): pass

    ssh.Server(
        net.TCPListenCap(net.TCPCap(net.NetCap(env.cap))),
        "0.0.0.0", u16(2222),
        on_listen, on_server_close, on_session,
        on_auth, on_channel_open, on_exec)
```

Runnable versions of both are in [`src/example_client.act`](src/example_client.act)
and [`src/example_server.act`](src/example_server.act):

```sh
./out/bin/example_server 2222 demo demo &
./out/bin/example_client 127.0.0.1 demo "hello" 2222 demo
```

## API overview

- **`Client(cap, host, username, on_connect, on_close, on_hostkey?, ...)`** —
  `accept_hostkey()`, `reject_hostkey(reason)`, `close()`. Auth via `password`
  and/or `private_key_file` (+ `private_key_passphrase`). Tunables:
  `port`, `known_hosts`, `connect_timeout`, `auth_timeout`,
  `keepalive_interval`, `keepalive_enabled`, `close_timeout`,
  `max_write_buffer`.
- **`Channel(client, on_open, on_stdout, on_stderr, on_exit, on_close)`** —
  `request_exec(cmd)`, `request_shell(...)`, `request_subsystem(name)`,
  `write(data)`, `send_eof()`, `close()`. `?bytes` callbacks deliver `None`
  for EOF. Teardown order: `on_exit`, then stream EOFs, then `on_close`.
- **`RunCommand(client, cmd, on_exit, timeout?)`** — buffers stdout/stderr and
  reports once: `on_exit(channel, code, signal?, stdout, stderr, error?)`.
- **`Server(cap, host, port, on_listen, on_close, on_session, on_auth,
  on_channel_open, on_exec?, on_subsystem?, on_session_close?, ...)`** —
  `close()`, `bound_port()` (use `port=0` for an ephemeral port). Tunables
  include `host_key_path`/`host_key_type`/`host_key_bits`, the timeouts above,
  and `max_sessions` / `max_channels_per_session` / `max_write_buffer`.
- **`ServerSession`** — `accept_auth()`, `reject_auth(reason)`,
  `accept_channel(ServerChannel)`, `reject_channel(reason)`, `close()`.
- **`ServerChannel(session, on_data, on_stderr, on_close)`** —
  `accept_request()`, `reject_request(reason)`, `write(data)`,
  `write_stderr(data)`, `send_eof()`, `send_exit_status(status)`, `close()`.
- **`AuthRequest`** — `method` ("password"/"publickey"), `user`, `password?`,
  `pubkey?` (an authorized_keys `"<type> <base64>"` line).
- **`HostKeyInfo`** — `key_type`, `fingerprint`. Host-key states:
  `HOSTKEY_OK`, `HOSTKEY_UNKNOWN`, `HOSTKEY_NOT_FOUND`, `HOSTKEY_CHANGED`,
  `HOSTKEY_OTHER`, `HOSTKEY_ERROR`.

## Testing

```sh
acton test                       # loopback client<->server suite
acton test stress                # concurrent churn (race/lifetime fuzzing)
./interop/run_interop.sh         # interop with the OpenSSH ssh client and sshd
```

`src/bench_echo.act` measures echo throughput; `src/soak.act` runs many
connect→exec→close cycles for leak checking.

## Debugging

Set `ACTON_SSH_DEBUG=1` for gated lifecycle tracing (optionally
`ACTON_SSH_DEBUG_FILE=/path` to write per-pid logs), and
`ACTON_SSH_LIBSSH_LOG=<level>` to surface libssh's own logging.
