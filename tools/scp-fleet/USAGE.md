# fleet.sh step by step

`fleet.sh` starts SSH servers in Docker containers, one per device, so that
`example_scp_multi` and `bench_scp` can run against many devices from one
machine. Every container has its own IP, sshd, filesystem and limits.

You need:

- Docker, and membership in the `docker` group. sudo is not needed.
- Access to the Debian package mirrors once, to build the image.
- `acton build` in the repository root, for the client programs.

Run every command below from the repository root. The IPs in the examples
will differ on your machine. For the full test plan, see
[README.md](README.md).

## 1. Generate a key

```sh
ssh-keygen -t ed25519 -N '' -C scp-test -f ~/.ssh/scp_test
```

This creates the private key `~/.ssh/scp_test` (mode 600) and the public
key `~/.ssh/scp_test.pub`. If a file with that name exists, `ssh-keygen`
asks before it overwrites it; pick another name instead.

The key must not have a passphrase (`-N ''`): `example_scp_multi` and
`bench_scp` read the file and cannot ask for one. Check the key:

```sh
head -1 ~/.ssh/scp_test            # -----BEGIN OPENSSH PRIVATE KEY-----
ssh-keygen -y -f ~/.ssh/scp_test   # prints the public key; a passphrase prompt means the key has one
```

Tell the client programs and `fleet.sh` where the key is. Leave `~`
unquoted: in quotes it stays a literal `~`, and the file is not found.

```sh
export SCP_KEY=~/.ssh/scp_test
```

## 2. Build the image

```sh
tools/scp-fleet/fleet.sh build
```

The image accepts `$SCP_KEY.pub` for root logins. To use another public
key, pass it: `tools/scp-fleet/fleet.sh build ~/.ssh/other.pub`.

The key is baked into the image. After a new key, build again and recreate
the containers (steps 3 and 9), because running containers keep the old
key.

Without access to the package mirrors, build the image on another machine
with the same public key and copy it over:

```sh
docker save scp-fleet | ssh TEST_SERVER docker load
```

## 3. Start devices

`add PREFIX COUNT [DOCKER_RUN_OPTION...]` starts COUNT containers named
`scp-PREFIX-001`, `scp-PREFIX-002`, ... and prints the name and IP of each.
Give each kind of device its own prefix:

```
$ tools/scp-fleet/fleet.sh add fast 3 --tmpfs /tmp
scp-fast-001 172.23.0.2
scp-fast-002 172.23.0.3
scp-fast-003 172.23.0.4

$ tools/scp-fleet/fleet.sh add slow 1 --tmpfs /tmp -e NETEM="delay 100ms" -e UPLOAD_RATE=10mbit
scp-slow-001 172.23.0.5

$ tools/scp-fleet/fleet.sh add tiny 1 --tmpfs /tmp:size=32m --cpus 0.2
scp-tiny-001 172.23.0.6
```

Adding to a prefix that exists continues its numbering:

```
$ tools/scp-fleet/fleet.sh add fast 2 --tmpfs /tmp
scp-fast-004 172.23.0.7
scp-fast-005 172.23.0.8
```

The options go to `docker run`. These make devices differ:

| Option | Device |
|---|---|
| `--tmpfs /tmp` | `/tmp` in RAM: uploads do not touch the disk, and a restart empties it |
| `--tmpfs /tmp:size=32m` | a small `/tmp`, as on OpenWrt: a bigger upload fails with `No space left on device` |
| `--cpus 0.2` | a slow CPU |
| `--memory 48m --memory-swap 48m --tmpfs /tmp` | little RAM: a big upload into `/tmp` gets the remote side OOM-killed |
| `-e NETEM="delay 100ms"` | netem options for what the device sends; a delay lengthens the round trip both ways |
| `-e NETEM="delay 100ms loss 1%"` | a lossy link: downloads from the device slow to a few Mbit/s |
| `-e UPLOAD_RATE=10mbit` | uploads to the device run at somewhat less than this rate |

`list` shows the running devices:

```
$ tools/scp-fleet/fleet.sh list
scp-fast-001 172.23.0.2
scp-fast-002 172.23.0.3
...
```

## 4. Check a device (optional)

Log in with the key, and look at a device's network settings:

```sh
ssh -i "$SCP_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null root@172.23.0.2 hostname     # scp-fast-001
docker exec scp-slow-001 tc qdisc show dev eth0                  # qdisc netem ... delay 100ms
```

## 5. Write the hosts file

`hosts REMOTE_PATH` prints one line per running device, in the format of
`example_scp_multi`, with the container name in a comment above it:

```
$ tools/scp-fleet/fleet.sh hosts /tmp/ > fleet.txt
$ cat fleet.txt
# scp-fast-001
172.23.0.2 root - 22 /tmp/
# scp-fast-002
172.23.0.3 root - 22 /tmp/
...
```

- The password `-` means: log in with the key in `$SCP_KEY`.
- `hosts /tmp/ scp-fleet` writes the root password `scp-fleet` instead, to
  test password logins.
- `hosts /dev/null` sends every upload to `/dev/null`. Nothing is stored,
  but `--verify` cannot read `/dev/null` back.

## 6. Run the client

```sh
acton build
head -c 64M /dev/urandom > test_file.img
./out/bin/example_scp_multi --verify --timeout 300 fleet.txt test_file.img
```

With the devices from step 3, the summary shows every `fast` and `slow`
device OK and `scp-tiny-001` failed with `No space left on device`. The
exit status is 1, because one device failed.

Two options check each copy after its upload. Use either, both or neither:

| Options | Check |
|---|---|
| none | the upload succeeded and the remote `scp` exited with status 0 |
| `--remote-md5` | runs `md5sum` on the device and compares the digest with the MD5 of `test_file.img`; nothing is downloaded |
| `--verify` | downloads the copy and compares it byte by byte |
| `--remote-md5 --verify` | the MD5 check first, then the download, only if the MD5 matches |

`--remote-md5` is much cheaper than `--verify` for large files and many
devices, because only a 32-character digest comes back. It needs `md5sum`
on the device; the fleet's devices and BusyBox have it. Don't combine
either check with `hosts /dev/null`: `md5sum /dev/null` gives the MD5 of
nothing, and `scp -f` cannot send `/dev/null`.

### Example: `--remote-md5`

Three good devices, one with a small `/tmp`, and one without `md5sum`, as on
a device that lacks it:

```sh
tools/scp-fleet/fleet.sh add fast 4 --tmpfs /tmp:size=300m
tools/scp-fleet/fleet.sh add tiny 1 --tmpfs /tmp:size=32m
docker exec scp-fast-004 mv /usr/bin/md5sum /usr/bin/md5sum.off
tools/scp-fleet/fleet.sh hosts /tmp/ > fleet.txt

head -c 64M /dev/urandom > test_file.img
md5sum test_file.img                  # the digest the devices must report
./out/bin/example_scp_multi --remote-md5 --timeout 300 fleet.txt test_file.img
```

The output, abridged (times, IPs and digests differ):

```
logging in with the key in /home/you/.ssh/scp_test where the password is -
sending test_file.img (67108864 bytes) to 5 devices, 5 at a time, checking each copy's MD5 on the device
MD5 of test_file.img: 0b5f6e2c1c5e3d1a8f3b9a4e7d2c6b10
[root@172.23.0.2] connected in 0.210 s, uploading to /tmp/
[root@172.23.0.2] uploaded 67108864 bytes in 1.402 s (45.6 MiB/s)
[root@172.23.0.2] checking the MD5 of /tmp/test_file.img
[root@172.23.0.2] MD5 matches in 0.160 s
[root@172.23.0.2] OK after 1.790 s
...
[root@172.23.0.6] FAILED after 0.912 s: upload failed: ...No space left on device
[root@172.23.0.5] FAILED after 1.850 s: MD5 check failed: remote md5sum exited with 127: bash: line 1: md5sum: command not found

summary:
  ok    root@172.23.0.2  1.790 s      /tmp/
  ok    root@172.23.0.3  1.801 s      /tmp/
  ok    root@172.23.0.4  1.795 s      /tmp/
  FAIL  root@172.23.0.5  MD5 check failed: remote md5sum exited with 127: bash: line 1: md5sum: command not found
  FAIL  root@172.23.0.6  upload failed: ...No space left on device
3 of 5 devices OK in 1.853 s (103.6 MiB/s in total). The transfers took 8.148 s added up.
```

The exit status is 1. Put `md5sum` back with
`docker exec scp-fast-004 mv /usr/bin/md5sum.off /usr/bin/md5sum`.

A damaged copy fails with
`MD5 check failed: the copy has MD5 <digest on the device>, LOCAL_FILE <digest of test_file.img>`.

To check the MD5 and then download the copy as well, add `--verify`; the
download runs only on the devices whose MD5 matched:

```sh
./out/bin/example_scp_multi --remote-md5 --verify --timeout 300 fleet.txt test_file.img
```

Every device runs its own sshd, so all devices can connect at once.
`--parallel` is needed only to limit the load.

### 100 sessions at once

There are three ways, depending on what the test is about.

**A steady load of 100 sessions over many devices.** `--parallel 100` runs
at most 100 transfers (connect, upload, verify, close) at once, and starts
the next device whenever one finishes:

```sh
tools/scp-fleet/fleet.sh add fast 500 --tmpfs /tmp:size=300m
tools/scp-fleet/fleet.sh hosts /tmp/ > fleet.txt
./out/bin/example_scp_multi --parallel 100 --verify --timeout 300 fleet.txt test_file.img
```

The first line of output confirms the limit:
`sending ./test_file.img (... bytes) to 500 devices, 100 at a time, verifying each copy`.
Finished devices keep their copy: with a 64 MiB file, the 500 copies hold
31 GiB of RAM at the end.

**A burst: 100 devices, all at once.** Without `--parallel`, every session
connects and uploads at the same moment:

```sh
tools/scp-fleet/fleet.sh add fast 100 --tmpfs /tmp:size=300m
tools/scp-fleet/fleet.sh hosts /tmp/ > fleet100.txt
./out/bin/example_scp_multi --verify --timeout 300 fleet100.txt test_file.img
```

**The client's peak memory with 100 uploads at the same instant.**
`bench_scp fanout` opens 100 sessions to one device, 8 connecting at a
time, waits until all are connected, and then starts every upload together.
It prints throughput, the fastest and slowest session, and the peak RSS
inside and outside the GC heap:

```sh
./out/bin/bench_scp fanout 172.23.0.2 root - /dev/null 64 100
```

The device's sshd accepts 200 connections that are still logging in, so
all 100 sessions can go to one device.

`--tmpfs /tmp:size=300m` caps each device's `/tmp`: Docker sets no limit by
default, so a wrong file size could otherwise fill the machine's RAM.

## 7. Break devices during a run

Take the names from `list`. Every fault must end that device's transfer with
an error and leave the other devices alone.

| Fault | Command | Undo |
|---|---|---|
| the device freezes | `docker pause scp-fast-002` | `docker unpause scp-fast-002` |
| the remote scp dies | `docker exec scp-fast-003 pkill -KILL -x scp` | none needed |
| the link dies without a reset | `docker exec scp-slow-001 tc qdisc replace dev eth0 root netem loss 100%` | `docker exec scp-slow-001 tc qdisc replace dev eth0 root netem delay 100ms` |
| the device reboots | `docker restart scp-fast-001` | none needed |

A frozen device and a dead link leave the TCP connection open, so the
transfer fails only at `--timeout`. Use a large file or a `slow` device, so
that the transfer is still running when the fault hits.

## 8. Between runs

Devices keep their files until a restart empties their tmpfs `/tmp`. A
restart can change IPs, so write the hosts file again:

```sh
docker restart $(docker ps -q --filter label=scp-fleet) >/dev/null
tools/scp-fleet/fleet.sh hosts /tmp/ > fleet.txt
```

## 9. Clean up

```sh
tools/scp-fleet/fleet.sh down    # removes the scp-fleet containers and network, nothing else
docker rmi scp-fleet             # optional: the image too
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `build` prints `cannot read public key ...` | `SCP_KEY` is unset or wrong, or the `.pub` file is missing. Set `SCP_KEY` or pass the public key's path. |
| `permission denied while trying to connect to the Docker daemon` | You are not in the `docker` group yet. Log in again after being added. |
| `add` prints `invalid IP` instead of an IP | The container exited at once. `docker logs NAME` shows why; a mistyped `NETEM` prints `tc`'s usage text. Fix the option, then `down` and `add` again. |
| `Permission denied (publickey)` or an auth failure | The image holds another key than `$SCP_KEY`. Build again, then recreate the containers. |
| `connect failed: OSError: host is unreachable` | The device's IP changed, after a restart for example. Write the hosts file again. |
| `connect failed: OSError: connection refused` right after `add` | sshd was still starting. Wait a second. |
