# SCP concurrency tests on one machine

These steps test `ScpPut`/`ScpGet` against many devices from a single
machine with no other SSH endpoints. They need no sudo: the Docker fleet
needs the `docker` group, and the rest runs as your own user.

`fleet.sh` (next to this file) starts one container per device. Every
container has its own IP, sshd, filesystem and limits, and can have its
network shaped with netem. `./fleet.sh` without arguments prints its usage;
[USAGE.md](USAGE.md) walks through it step by step.

## 1. Build

```sh
acton build
```

After an edit to `src/lib.ext.c`, `acton build` can report success and keep
the old object. If a fix seems to have no effect, delete the zig cache
manifests under `~/.cache/acton/zig-local-cache/h/` that reference
`out/types/ssh/lib.c` and build again.

## 2. A key without a passphrase

`bench_scp` and `example_scp_multi` log in with a key when the password is
`-`. They read the private key named by `$SCP_KEY` (default
`~/.ssh/id_ed25519`) and cannot ask for a passphrase.

```sh
ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/scp_test
export SCP_KEY=~/.ssh/scp_test
```

The Docker fleet needs nothing more. For the tests against the machine's own
sshd (section 7), also allow the key for logins from the machine itself:

```sh
echo "from=\"127.0.0.1\" $(cat ~/.ssh/scp_test.pub)" >> ~/.ssh/authorized_keys
ssh -i ~/.ssh/scp_test -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new 127.0.0.1 true && echo key works
```

## 3. A test file

Use random bytes, so a lost, repeated or reordered piece changes the file:

```sh
head -c 64M /dev/urandom > test_file.img
```

Every device that keeps a copy holds the whole file: 100 devices with
`--tmpfs /tmp` hold 6.4 GiB of RAM. Use a smaller file for many devices, or
`/dev/null` (section 5).

## 4. The fleet run

```sh
tools/scp-fleet/fleet.sh build          # bakes $SCP_KEY.pub in; needs apt access once

tools/scp-fleet/fleet.sh add fast 100 --tmpfs /tmp
tools/scp-fleet/fleet.sh add slow 10  --tmpfs /tmp -e NETEM="delay 100ms" -e UPLOAD_RATE=10mbit
tools/scp-fleet/fleet.sh add tiny 5   --tmpfs /tmp:size=32m --cpus 0.2
tools/scp-fleet/fleet.sh add oom 5    --tmpfs /tmp --memory 48m --memory-swap 48m

tools/scp-fleet/fleet.sh hosts /tmp/ > fleet.txt
/usr/bin/time -v ./out/bin/example_scp_multi --verify --timeout 300 fleet.txt test_file.img
```

The broken devices fail in known ways, so the expected result is exact:

| Devices | Expected |
|---|---|
| `fast`, `slow` | OK, and verified |
| `tiny` | upload fails: `No space left on device` |
| `oom` | upload fails: `remote scp killed by signal KILL` or `Session closed` |

The summary must read `110 of 120 devices OK` and the exit status must be 1.
Anything else is a bug: another failure, a hang, or a
`WARNING: no on_close 10 s after Client.close()` line.

Each device runs its own sshd, so the run needs no `--parallel`.

## 5. Variations

- **More devices.** Repeat with 10, 50, 100, 250 and 500 `fast` devices.
  Every handshake costs CPU on the client and on a device, and here they
  share one machine. If connect or auth timeouts appear only at high
  counts, rerun with `--parallel 50`: if they go away, the shared CPU
  caused them. One Docker network holds about 1000 containers (the Linux
  bridge port limit).
- **Uploads only.** `fleet.sh hosts /dev/null > null.txt` and run without
  `--verify`. Nothing is stored, so file size and device count are limited
  only by time.
- **Lossy links.** `fleet.sh add lossy 5 --tmpfs /tmp -e NETEM="delay 100ms loss 1%"`.
  The loss hits what the device sends, so `--verify` downloads drop to a few
  Mbit/s; raise `--timeout` to match. The expected count of OK devices grows
  by 5.
- **Password login.** `fleet.sh hosts /tmp/ scp-fleet` writes the root
  password `scp-fleet` instead of `-`.
- **Repeated runs.** Races show up only now and then, so run each setup
  several times. Restart the devices between runs; a restart empties their
  tmpfs `/tmp`:

  ```sh
  for i in $(seq 1 10); do
      docker restart $(docker ps -q --filter label=scp-fleet) >/dev/null
      tools/scp-fleet/fleet.sh hosts /tmp/ > fleet.txt     # IPs can change on restart
      ./out/bin/example_scp_multi --verify --timeout 300 fleet.txt test_file.img > run-$i.log 2>&1
      grep -q '110 of 120 devices OK' run-$i.log || echo "run $i: unexpected result, see run-$i.log"
  done
  ```

- **Thread counts.** Add `--rts-wthreads 1`, `2` or `4` to the client to
  change how actors interleave.

## 6. Faults during a run

Take NAME from `tools/scp-fleet/fleet.sh list`. Every fault must end that
device's transfer with an error and leave the others alone.

| Fault | Command | Expected |
|---|---|---|
| device freezes | `docker pause NAME` (later `docker unpause NAME`) | fails at `--timeout` |
| remote scp dies | `docker exec NAME pkill -KILL -x scp` | fails at once |
| link dies without a reset | `docker exec NAME tc qdisc replace dev eth0 root netem loss 100%` | fails at `--timeout` |
| device reboots | `docker restart NAME` | fails |

Use a large file or a `slow` device, so the transfer is still running when
the fault hits.

## 7. Without Docker: the machine's own sshd

These need the `authorized_keys` line from section 2.

```sh
# 50 sessions upload the same 100 MiB buffer to /dev/null at once
./out/bin/bench_scp fanout 127.0.0.1 $USER - /dev/null 100 50

# example_scp_multi, uploads only
for i in $(seq 1 50); do echo "127.0.0.1 $USER - 22 /dev/null"; done > local50.txt
./out/bin/example_scp_multi --parallel 8 local50.txt test_file.img

# example_scp_multi with --verify, files in RAM
for i in $(seq -w 1 50); do mkdir -p /dev/shm/scpload/d$i; echo "127.0.0.1 $USER - 22 /dev/shm/scpload/d$i/"; done > verify50.txt
./out/bin/example_scp_multi --verify --parallel 8 verify50.txt test_file.img
rm -rf /dev/shm/scpload
```

- `bench_scp fanout` prints throughput, the fastest and slowest session, and
  peak RSS inside and outside the GC heap.
- `example_scp_multi` opens all its connections at once. The default sshd
  drops some at random once more than 10 are still logging in
  (`MaxStartups 10:30:100`), so keep `--parallel 8`.
- `scp -f` sends only regular files, so `--verify` cannot read `/dev/null`
  back.
- With OpenSSH 9.8 or newer (`ssh -V`), skip wrong-password tests here:
  `PerSourcePenalties` can then refuse 127.0.0.1 for a while.

## 8. Measurements and debugging

- **Client memory and CPU.** `/usr/bin/time -v` prints the maximum resident
  set size and the CPU time.
- **GC statistics.** libgc reads `GC_PRINT_STATS` at startup;
  `GC_LOG_FILE` sends the output to a file instead of stderr:

  ```sh
  GC_PRINT_STATS=1 GC_LOG_FILE=$PWD/gc.log ./out/bin/example_scp_multi ...
  ```

  For a test, run one at a time, because every process appends to the same
  file:

  ```sh
  rm -f gc.log
  GC_PRINT_STATS=1 GC_LOG_FILE=$PWD/gc.log \
      acton test --tag openssh --module test_scp --name ScpRoundTripTester --no-cache --iter 1
  ```

- **Tracing a failure.** `ACTON_SSH_DEBUG=1 ACTON_SSH_DEBUG_FILE=$PWD/ssh-debug.log`
  logs the client's lifecycle, one file per process. `ACTON_SSH_LIBSSH_LOG=<level>`
  turns on libssh's own logging.
- **Separate CPUs.** Pin the client away from the devices, e.g.
  `taskset -c 0-3 ./out/bin/example_scp_multi --rts-wthreads 4 ...`, and give
  each device `--cpus`.

## 9. What one machine cannot show

- The client and every device share the CPU, so throughput reflects the
  encryption cost on both ends, not a network. Compare runs with each other.
- `UPLOAD_RATE` drops the packets above the rate, so uploads run somewhat
  slower than the rate. `NETEM` delays everything a container sends,
  including ACKs, so a delay lengthens the round trip both ways.
- All containers share one host key.

## 10. Clean up

```sh
tools/scp-fleet/fleet.sh down       # only containers labelled scp-fleet, and the scp-fleet network
docker rmi scp-fleet
rm -f fleet.txt null.txt local50.txt verify50.txt run-*.log gc.log
```
