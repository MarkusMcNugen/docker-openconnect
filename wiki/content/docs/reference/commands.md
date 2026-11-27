---
title: Commands
weight: 4
---

Two programs in the image manage the running server. Run them with `docker exec`.

## ocpasswd

Edits the password file. ocserv reads the file at every login, so a change applies to the next login.

```bash
docker exec -it openconnect ocpasswd -c /config/ocpasswd [options] USERNAME
```

| Option | Effect |
|---|---|
| none | Adds the user or changes the password. Asks twice on a terminal; without one, reads one line from standard input. |
| `-g GROUPS`, `--groupname=GROUPS` | Sets the user's groups, comma-separated. |
| `-l`, `--lock` | Locks the user; logins are refused. |
| `-u`, `--unlock` | Unlocks the user. |
| `-d`, `--delete` | Removes the user. |
| `-c FILE`, `--passwd=FILE` | The password file. Always `/config/ocpasswd`, or `PASSWD_FILE`. |

## occtl

Queries and controls the running server through its control socket.

```bash
docker exec openconnect occtl [--json] COMMAND
```

`--json` prints JSON instead of text, for scripts. `occtl` with no command opens an interactive prompt.

| Command | Effect |
|---|---|
| `show status` | Server status and statistics. The container's health check runs this; it exits non-zero when ocserv does not answer. |
| `show users` | The connected sessions, one per line. |
| `show user NAME` | Details of each session of one user: addresses, DNS, routes, traffic and the client. |
| `show id ID` | The same for one session, by the ID `show users` prints. |
| `show sessions all`, `show sessions valid` | Session cookies, all or only those a client can still reconnect with. |
| `show session SID` | One session cookie. |
| `show ip bans` | Banned client addresses. |
| `show ip ban points` | Every client address with points toward a ban. |
| `show iroutes` | Routes that users' per-user settings make them offer. |
| `show events` | Connections and disconnections as they happen, until interrupted. |
| `disconnect user NAME`, `disconnect id ID` | Ends sessions; the client may reconnect with its cookie. |
| `terminate user NAME`, `terminate id ID` | Ends sessions and invalidates their cookies, so the client must log in again. |
| `terminate session SID` | Invalidates one cookie of a disconnected session. |
| `unban ip ADDRESS` | Lifts a ban. |
| `reload` | Reloads the configuration and certificates. |
| `stop now` | Stops the server, which stops the container. |

## Output

From the smoke test, with two sessions of the user `smoke` connected.

`occtl show users`:

```text
      id     user    vhost             ip         vpn-ip device   since    dtls-cipher    status
      94    smoke  default      10.89.0.4 192.168.255.241  vpns1    15s      (no-dtls) connected
      88    smoke  default      10.89.0.3 192.168.255.80  vpns0    34s      (no-dtls) connected
```

`ip` is the client's own address and `vpn-ip` its address in the tunnel. `dtls-cipher` shows the UDP channel's cipher, or `(no-dtls)` while the session runs over TCP only.

`occtl show user smoke` prints a block per session:

```text
	ID: 94
	Username: smoke   Groupname: (none)
	State: connected
	vhost: default
	Device: vpns1   MTU: 1434
	Remote IP: 10.89.0.4   Location: unknown
	Local Device IP: 10.89.0.2
	IPv4: 192.168.255.241   P-t-P IPv4: 192.168.255.1
	IPv6: fd3e:7a0c:5b19:bc5c:c44b:cdf0:a15e:160d   P-t-P IPv6: fd3e:7a0c:5b19::
	User-Agent: Open AnyConnect VPN Agent v9.12
	RX: 48 (48 bytes)   TX: 520 (520 bytes)
	Average bandwidth RX: 3 bytes/s  TX: 34 bytes/s
	DPD: 90   KeepAlive: 32400
	Hostname: a7a8c0f628eb
	Last connected at: 2026-11-25 21:25 (   15s)
	Session started at: 2026-11-25 21:25 (   15s)
	Session: eGPmN+
	TLS ciphersuite: (TLS1.3)-(ECDHE-SECP256R1)-(ECDSA-SECP256R1-SHA256)-(AES-256-GC

	DNS: 9.9.9.9
		1.1.1.1
	Routes: defaultroute
	Restricted to routes: False
```

`occtl --json show users` prints the same fields as a JSON array, one object per session, with numbers and lists as JSON values:

```json
[
  {
    "ID":  94,
    "Username":  "smoke",
    "State":  "connected",
    "Device":  "vpns1",
    "Remote IP":  "10.89.0.4",
    "IPv4":  "192.168.255.241",
    "IPv6":  "fd3e:7a0c:5b19:bc5c:c44b:cdf0:a15e:160d",
    "RX":  "48",
    "TX":  "520",
    "raw_connected_at":  1795641920,
    "TLS ciphersuite":  "(TLS1.3)-(ECDHE-SECP256R1)-(ECDSA-SECP256R1-SHA256)-(AES-256-GC",
    "DNS":	["9.9.9.9", "1.1.1.1"],
    "Restricted to routes":  "False"
  }
]
```

The object above is cut to the commonly used fields; each object also carries `Groupname`, `vhost`, `MTU`, `Local Device IP`, `P-t-P IPv4`, `P-t-P IPv6`, `User-Agent`, the `_RX`/`_TX` text forms, the averages, `DPD`, `KeepAlive`, `Hostname`, both timestamps in text and `raw_` form, `Full session`, `Session`, `NBNS`, `Split-DNS-Domains`, `Routes`, `No-routes`, `iRoutes` and `Restricted to ports`.

`occtl show status`:

```text
General info:
	Status: online
	Server PID: 2
	Sec-mod PID: 83
	Sec-mod instance count: 1
	Up since: 2026-11-25 21:24 (   42s)
	Active sessions: 2
	Total sessions: 0
	Total authentication failures: 0
	IPs in ban list: 0
```

followed by the same counters for the current statistics period.
