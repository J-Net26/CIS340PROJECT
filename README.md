# DSCP — Device System Communication Protocol

CIS 340 final project. DSCP is a custom application-layer protocol that lets one
user (the **requester**) ask another user (the **owner**) for their device's
system information over the network. Nothing is sent until the owner has seen
exactly what would be shared and has approved it. It replaces sending
screenshots or emails.

| Member | Area | Files |
|---|---|---|
| Julius | Protocol / message format | `shared/protocol.py` |
| Albert | Code / testing | `server/`, `client/`, `requirements.txt` |
| Seth | Security (TLS, HMAC, logging) | `shared/security.py`, `generate_cert.py`, `config.example.ini`, `.gitignore` |

## 1. File tree

```
CIS340 project/
├── README.md              this file
├── requirements.txt       the one third-party package (psutil)
├── config.example.ini     example settings; copy to config.ini
├── generate_cert.py       one-time script: creates the TLS certificate
├── .gitignore             keeps secrets, logs and compiled files out
├── shared/
│   ├── __init__.py
│   ├── protocol.py        message format: constants, builders, parser, reader
│   └── security.py        config, pre-shared key, TLS contexts, HMAC, logging
├── server/                runs on the OWNER's device
│   ├── __init__.py
│   ├── server.py          listener, session state machine, error replies
│   ├── consent.py         consent screen and keyboard input with a timeout
│   └── sysinfo.py         collects the NS and S tier fields
└── client/                runs on the REQUESTER's device
    ├── __init__.py
    └── client.py          requests, HMAC check, built-in tests
```

Created at run time and **not** part of the deliverable: `config.ini`,
`certs/`, `logs/`.

## 2. Setup on a fresh machine

You need Python 3.8 or newer. Run every command from the project folder.

### Windows (PowerShell)

```powershell
python -m pip install -r requirements.txt
Copy-Item config.example.ini config.ini
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the printed key into `config.ini` after `psk =`, then create the
certificate:

```powershell
python -m pip install cryptography
python generate_cert.py
```

(`cryptography` is only needed by `generate_cert.py`, and only when the
`openssl` command is not installed. If Git for Windows is installed, the script
finds its `openssl` automatically and you can skip that `pip install`.)

### macOS / Linux

```bash
python3 -m pip install -r requirements.txt
cp config.example.ini config.ini
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Paste the printed key into `config.ini` after `psk =`, then:

```bash
python3 generate_cert.py
```

`openssl` is already installed on macOS and Linux, so nothing else is needed.
The manual equivalent of the script is:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 -subj "/CN=DSCP-Server" -keyout certs/server.key -out certs/server.crt
```

### Two different devices

1. Do the setup above on the **owner's** device (the server).
2. On the **requester's** device, install psutil and copy over two things:
   `config.ini` (same `psk`) and `certs/server.crt`. **Never copy
   `certs/server.key`.**
3. In the requester's `config.ini`, set `server_host` to the owner's IP address.
4. Allow incoming TCP port 5050 through the owner's firewall. (Windows asks the
   first time the server starts.)

Instead of writing the key in `config.ini`, you can set the environment variable
`DSCP_PSK` on both devices; it takes priority over the file.

## 3. Running

Terminal 1, the owner:

```
python server/server.py
```

Terminal 2, the requester:

```
python client/client.py
```

The client asks for your name and then a tier. On the server the owner sees:

```
============================================================
DSCP REQUEST
  Requester : Bob
  Asked for : BOTH
  Would send: tier BOTH, exactly these values:
    [NS] cpu_percent = 7.0
    [NS] memory_percent = 60.6
    [NS] disk_percent = 82.1
    [NS] temperatures = unavailable
    [S] hostname = ...
    [S] ip_address = ...
    [S] mac_address = ...
============================================================
[y] approve  [n] deny  [r] reduce tier  [x] exclude fields >
```

- `y` sends exactly what is listed.
- `n` sends `DENY|403|...`.
- `r` keeps only the NS or only the S tier (available while both are selected).
- `x` removes named fields, e.g. `mac_address, hostname`.

After `r` or `x` the screen is shown again with the new selection, so the owner
always approves the final content. Stop the server with Ctrl+C.

Options: `python server/server.py --help`, `python client/client.py --help`.

## 4. Tests

Start the server in one terminal, then run a client test in another. For the
timeout tests, start the server with a short timeout so you do not wait a full
minute: `python server/server.py --timeout 10`.

| Test | Command | What to do on the server | Expected on the client |
|---|---|---|---|
| **1** Successful session | `python client/client.py --test 1` | type `y` | `DATA 200`, HMAC verified, then `BYE` |
| **2** Malformed requests | `python client/client.py --test 2` | nothing | four `ERR 400` and one `ERR 422`, then `BYE` (the session survives every error) |
| **3** Several requests, one session | `python client/client.py --test 3` | answer three prompts (try `y`, `n`, then `r`/`x`) | three replies on one connection, then `BYE` |
| **4a** Inactivity timeout | `python client/client.py --test 4a` | nothing | `ERR 408` after the timeout |
| **4b** Empty message | `python client/client.py --test 4b` | nothing | `ERR 400: Empty message` |
| **4c** Oversized message | `python client/client.py --test 4c` | nothing | `ERR 400: Header line too long` |
| **4d** Consent timeout | `python client/client.py --test 4d` | do **not** answer | `ERR 408` after the timeout |
| 5 Bad HMAC (extra) | `python client/client.py --test 5` | type `y` | `ERR 401`, data discarded; server shows "client reported ERR 401" |
| 6 Drop without BYE (extra) | `python client/client.py --test 6` | nothing | server shows and logs `ERR 446` |

Other error codes:

- **421 / 448**: start the server with `--simulate-error 421` (or `448`), then
  run test 1.
- **447 (busy)**: run test 4d, and while the consent prompt is waiting run
  test 1 in a third terminal; the second client receives `ERR 447`.
- **447 (no socket)**: run any client test with the server stopped, or start a
  second server while one is running.

## 5. Protocol specification

### Transport

TCP port 5050. TLS (version 1.2 or newer) wraps the whole session: the
handshake happens immediately after the TCP connection, before any DSCP message.

### Messages

Line-based UTF-8 text. Header fields are separated by `|` and every header line
ends with `\n`. Only `DATA` has a body.

| Message | Direction | Meaning |
|---|---|---|
| `HELLO\|requester_name\|tier` | client → server | request; name is 1–32 printable characters, tier is `NS`, `S` or `BOTH` |
| `DATA\|200\|tier\|body_length\|hmac_hex` + body | server → client | approved; exactly `body_length` bytes of JSON follow the header |
| `DENY\|403\|reason` | server → client | the owner refused |
| `ERR\|status\|description` | either | an error (table below) |
| `BYE` | either | end of session; the server answers `BYE` and closes |

Example exchange:

```
C: HELLO|Bob|NS
S: DATA|200|NS|98|3f1c...(64 hex characters)
S: {"cpu_percent": 11.3, "disk_percent": 82.1, "memory_percent": 60.4, "temperatures": "unavailable"}
C: BYE
S: BYE
```

Limits: header line at most 1024 bytes, body at most 1 MiB.

### Tiers

| Tier | Fields |
|---|---|
| `NS` (non-sensitive) | `cpu_percent`, `memory_percent`, `disk_percent`, `temperatures` |
| `S` (sensitive) | `hostname`, `ip_address`, `mac_address` |
| `BOTH` | all of the above |

`temperatures` is the text `"unavailable"` on systems where psutil cannot read
sensors (Windows, macOS, most virtual machines).

### State machine

1. **Connect**: TCP connection, then TLS handshake.
2. **Request**: the requester sends `HELLO`.
3. **Consent**: the server collects the data and shows it to the owner.
4. **Reply**: `DATA` (approved), `DENY` (denied) or `ERR` (invalid request).
5. **Repeat or finish**: another `HELLO`, or `BYE` → server replies `BYE` and closes.
6. **Timeout**: after 60 seconds of inactivity the server sends `ERR 408` and
   ends the session.

### Status codes

| Code | Meaning | Sent as | Session afterwards |
|---|---|---|---|
| 200 | OK | `DATA` | continues |
| 400 | Malformed request | `ERR` | continues |
| 401 | Bad HMAC | `ERR` (client → server) | continues |
| 403 | Consent denied | `DENY` | continues |
| 408 | Timeout (idle requester or silent owner) | `ERR` | closed |
| 421 | Permission error reading system info | `ERR` | continues |
| 422 | Unknown tier | `ERR` | continues |
| 446 | Connection dropped without BYE/DENY | `ERR` (best effort) + log | closed |
| 447 | Socket unavailable | `ERR` when the server is busy; shown and logged locally when no connection exists | closed |
| 448 | Collection failure | `ERR` | continues |

## 6. Security design

- **TLS** encrypts everything, so nobody on the network can read the requests
  or the data. The certificate is self-signed. The client trusts only its own
  copy of `server.crt` (certificate pinning), so an impostor without
  `server.key` fails the handshake. Host-name checking is off because the
  server is reached by whatever IP address it has that day.
- **HMAC-SHA256** over the exact bytes of every `DATA` body, keyed with the
  pre-shared key. The client recomputes it and compares with
  `hmac.compare_digest` (constant time). On a mismatch the data is discarded
  and `ERR|401` is sent. The key is read from `config.ini` or `DSCP_PSK`; it is
  never in the source code, and the placeholder `CHANGE_ME` or a key shorter
  than 16 characters is refused.
- **Consent before transmission**: the data is collected and displayed locally
  first; the socket is only written after the owner types `y`.
- **Input validation**: names must be printable (no control or escape
  characters reach the owner's terminal or the log), sizes are capped, and
  free-text fields have `|` and newlines removed.
- **Logging**: `logs/server.log` and `logs/client.log` record connect, request,
  consent decision, errors and disconnect. They contain session numbers, tiers,
  field **names** and status codes only. They never contain field values, host
  names, IP or MAC addresses (including the requester's IP), or the key.

## 7. Ambiguities in the spec and the choices made

1. **Certificates cannot be made with the standard library.** `generate_cert.py`
   uses the `openssl` command, or the `cryptography` package if openssl is
   missing. This is a setup tool only; the protocol code uses just the standard
   library and psutil.
2. **Which timeout applies while waiting for consent?** The same value
   (60 s) is used for an idle requester and for an owner who does not answer;
   both produce `ERR 408` and end the session. An unanswered prompt is never
   treated as approval. Each consent question restarts the timer.
3. **"Must be sent and received" versus 446 and 447.** A dropped connection
   has nobody left to receive `ERR 446`: the server still attempts to send it
   and always logs it; the client logs 446 itself if the server vanishes. 447
   is sent on the wire when the server is busy with another session, and is
   shown and logged locally when no connection can be made at all.
4. **"Without BYE/DENY".** `DENY` keeps the session open so the requester can
   ask again, but a requester who simply closes right after a `DENY` is not
   reported as 446.
5. **Does ERR end the session?** No, except 408, 446 and 447. After 400, 421,
   422 or 448 the requester may send another `HELLO`.
6. **Tier field in DATA** is the tier actually sent, which can be lower than
   the tier requested. Excluded fields are simply absent from the JSON; the
   requester is not told which were withheld.
7. **What the HMAC covers.** The body only, as specified. The header is still
   protected in transit by TLS.
8. **Who sends 401?** Only the client verifies an HMAC, so the client sends
   `ERR|401` to the server, and both sides log it.
9. **One session at a time.** Consent uses one terminal, so a second requester
   gets `ERR 447` instead of queueing silently.
10. **Oversized messages.** A header over 1024 bytes gets `ERR 400` and the rest
    of that line is discarded so the session continues; past 64 KiB with no
    newline the session is closed.
11. **Requester name in logs.** Not in the sensitive tier, so it is logged on
    the server; the requester's IP address is not.
12. **Requester identity.** The name in `HELLO` is self-declared. Anyone who has
    the pre-shared key and certificate can claim any name; the owner's consent
    is the control.

## 8. Troubleshooting

| Message | Fix |
|---|---|
| `Configuration error: No pre-shared key set` | create `config.ini` and set `psk`, or set `DSCP_PSK` |
| `Cannot load the TLS certificate/key` | run `python generate_cert.py` |
| `TLS setup failed` on the client | copy the server's current `certs/server.crt` to the client |
| `ERR 447 ... cannot connect` | start the server; check `server_host`, the port and the firewall |
| `ERR 447 ... cannot listen` | another program (or another server) is using port 5050 |
| `ERR 401: HMAC check FAILED` | the `psk` differs between the two devices |

## 9. Before submitting

Delete `config.ini`, `certs/`, `logs/` and any `__pycache__` folders so the
deliverable contains no secrets, logs or compiled files.
