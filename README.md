# Drop reasons dump (drdump)

Small utility to dump drop reasons from BTF files (by default using the running
kernel ones), which can also resolve reasons (raw value to enum variant) and
generate bpftrace and stap scripts to dump drop reasons from the `skb:kfree_skb`
tracepoint.

## Installing

`drdump` is configured to be build as a static binary when building for x86_64.

```
$ git clone https://github.com/retis-org/drdump.git
$ cd drdump
$ cargo build --release
```

A pre-build binaries are available on the
[release page](https://github.com/retis-org/drdump/releases/).

## Usage

See the below examples and the `drdump --help` output.

## Examples

Dumping all known drop reasons,

```
$ drdump
     0 = RX_QUEUED
     1 = RX_CONTINUE
     2 = SKB_DROP_REASON_NOT_SPECIFIED
     3 = SKB_DROP_REASON_NO_SOCKET
     4 = SKB_DROP_REASON_PKT_TOO_SMALL
...
```

Resolving a specific raw drop reason,

```
$ drdump -r 65538
RX_DROP_U_REPLAY
$ drdump -r 65900`
Unknown reason 65900 (sub-system: SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE)
```

Generating a bpftrace script to dump drop reasons,

```
$ drdump -f bpftrace > drop.bt
$ chmod +x drop.bt
$ ./drop.bt
...
```

Generating a stap script to dump drop reasons,

```
$ drdump -f stap > drop.stp
$ stap-prep
$ stap --all-modules drop.stp
...
```
