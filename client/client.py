# =============================================================================
# File:           client/client.py
# Purpose:        The DSCP client. It runs on the REQUESTER's device, connects
#                 to the owner's server over TLS, sends HELLO requests, and
#                 shows the DATA / DENY / ERR replies. Every DATA body is
#                 checked with HMAC-SHA256 before it is displayed.
#                 It also contains the built-in test scenarios (--test).
#
#                 Run from the project root:
#                   python client/client.py              (interactive)
#                   python client/client.py --test 1     (see --help for all)
# Primary member: Albert (code / testing)
# =============================================================================

# argparse reads the command-line options (--test, --name, --host, --port).
import argparse
# json turns the DATA body text back into a dictionary.
import json
# os and sys are used for the import-path fix just below.
import os
import sys
# socket provides TCP; ssl (used through shared/security.py) provides TLS.
import socket

# This file lives in <project>/client/. Add the project root to Python's
# search path so "import shared..." works when running this script directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The message format (Julius' module).
from shared import protocol
# TLS, HMAC, config and logging helpers (Seth's module).
from shared import security

# Status codes after which the server closes the session, so the client must
# not try to send anything else.
SESSION_ENDING_CODES = (408, 446, 447)


def connect(config, logger):
    """
    State 1: open the TCP connection and do the TLS handshake.
    Returns (conn, reader), or None if the server cannot be reached.
    """
    try:
        # Open a TCP connection to the owner's device (10 s to connect).
        raw = socket.create_connection((config["server_host"], config["port"]), timeout=10)
    except OSError:
        # Error 447 on our side: there is no socket to talk through, so the
        # error is shown and logged locally (the IP address is NOT logged).
        logger.error("ERROR status=447 Socket unavailable: cannot connect")
        print("ERR 447: Socket unavailable - cannot connect to %s port %d. Is the server running?"
              % (config["server_host"], config["port"]))
        return None
    try:
        # Build the client TLS settings: trust only our copy of the server's
        # certificate (certificate pinning).
        context = security.make_client_context(config["cert_file"])
        # Perform the TLS handshake. After this, everything is encrypted.
        conn = context.wrap_socket(raw, server_hostname=config["server_host"])
    except OSError as error:
        # FileNotFoundError (no certificate file) and ssl.SSLError (handshake
        # or verification failure) are both kinds of OSError.
        logger.error("TLS_FAILED type=%s", type(error).__name__)
        print("TLS setup failed (%s). The client needs a copy of the SERVER's certs/server.crt."
              % type(error).__name__)
        # Close the plain TCP socket we opened above.
        raw.close()
        return None
    # How long we are willing to wait for each reply (the owner needs time
    # to read the consent screen).
    conn.settimeout(config["reply_timeout"])
    # Log the successful connection with the TLS version, no addresses.
    logger.info("CONNECT tls=%s", conn.version())
    print("Connected with %s." % conn.version())
    # The reader turns the byte stream into header lines and bodies.
    return conn, protocol.MessageReader(conn)


def send(conn, message, logger):
    """Send bytes to the server. Returns False instead of crashing on failure."""
    try:
        # sendall() keeps sending until every byte has been handed to TCP.
        conn.sendall(message)
        return True
    except OSError:
        # The server closed the connection before we could send.
        logger.warning("SEND_FAILED")
        return False


def read_reply(conn, reader, psk, logger):
    """
    Read ONE reply from the server, show it, and return (kind, status).
    kind is "DATA", "DENY", "ERR", "BYE", or "CLOSED" if the session is dead.
    """
    # ---- read and parse the header line --------------------------------------
    try:
        # Wait for the next header line from the server.
        line = reader.read_line()
        # Check it against the message format.
        message = protocol.parse_header(line)
    except socket.timeout:
        # The server never answered within reply_timeout seconds.
        logger.error("ERROR status=408 no reply from server")
        print("ERR 408: Timeout - the server did not reply.")
        return ("CLOSED", 408)
    except protocol.ConnectionDropped:
        # The server closed without sending BYE, DENY or ERR: error 446.
        logger.error("ERROR status=446 connection dropped by server")
        print("ERR 446: Connection dropped without BYE/DENY.")
        return ("CLOSED", 446)
    except protocol.ProtocolError as error:
        # The SERVER sent something malformed. Tell it, then give up on this
        # session because we can no longer trust the stream.
        logger.error("ERROR status=%d malformed reply from server", error.status)
        print("Server sent a malformed reply: " + error.description)
        send(conn, protocol.build_err(400, "Malformed reply"), logger)
        return ("CLOSED", 400)

    # ---- BYE ------------------------------------------------------------------
    if message["type"] == "BYE":
        logger.info("BYE received")
        print("<- BYE (session closed by server)")
        return ("BYE", None)

    # ---- DENY|403|reason ------------------------------------------------------
    if message["type"] == "DENY":
        logger.info("DENY status=403")
        print("<- DENY 403: " + message["reason"])
        return ("DENY", 403)

    # ---- ERR|status|description -----------------------------------------------
    if message["type"] == "ERR":
        logger.error("ERR received status=%d", message["status"])
        print("<- ERR %d: %s" % (message["status"], message["description"]))
        return ("ERR", message["status"])

    # ---- HELLO is client-to-server only ---------------------------------------
    if message["type"] != "DATA":
        logger.error("ERROR status=400 unexpected message type from server")
        print("Server sent an unexpected message type.")
        send(conn, protocol.build_err(400, "Unexpected message type"), logger)
        return ("CLOSED", 400)

    # ---- DATA|200|tier|body_length|hmac_hex + body ----------------------------
    try:
        # Read exactly body_length bytes: the JSON body.
        body = reader.read_exact(message["length"])
    except (socket.timeout, protocol.ConnectionDropped):
        # The connection died in the middle of the body.
        logger.error("ERROR status=446 connection dropped during DATA body")
        print("ERR 446: Connection dropped while receiving the data.")
        return ("CLOSED", 446)

    # Integrity check: recompute the HMAC of the received bytes with our copy
    # of the pre-shared key and compare it with the value in the header.
    if not security.verify_hmac(psk, body, message["hmac"]):
        # Mismatch: the body was altered, or the two sides have different
        # keys. The data is NOT shown, and the server is told with ERR 401.
        logger.error("ERROR status=401 HMAC verification failed")
        print("ERR 401: HMAC check FAILED - the data was discarded (wrong key or tampering).")
        send(conn, protocol.build_err(401, "Bad HMAC"), logger)
        return ("ERR", 401)

    try:
        # The HMAC is good, so decode the bytes and parse the JSON text.
        fields = json.loads(body.decode(protocol.ENCODING))
    except ValueError:
        # UnicodeDecodeError and JSONDecodeError are both kinds of ValueError.
        logger.error("ERROR status=400 DATA body is not valid JSON")
        print("The DATA body was not valid JSON.")
        send(conn, protocol.build_err(400, "Body is not valid JSON"), logger)
        return ("ERR", 400)

    # Log what kind of data arrived: tier, size and count only, never values.
    logger.info("DATA status=200 tier=%s bytes=%d hmac=ok", message["tier"], len(body))
    print("<- DATA 200 (tier %s, %d bytes, HMAC verified)" % (message["tier"], len(body)))
    # Show each field on its own line.
    for field, value in fields.items():
        print("     %-15s %s" % (field, value))
    return ("DATA", 200)


def session_over(kind, status):
    """Return True if the reply means the session can no longer be used."""
    # CLOSED and BYE always end the session; so do the ERR codes after which
    # the server hangs up.
    return kind in ("CLOSED", "BYE") or (kind == "ERR" and status in SESSION_ENDING_CODES)


def request(conn, reader, psk, logger, name, tier):
    """State 2-4: send one HELLO and show the reply. Returns (kind, status)."""
    # Log the request (the requester name is this user's own choice).
    logger.info("REQUEST tier=%s", tier)
    print("-> HELLO|%s|%s   (waiting for the owner's decision...)" % (name, tier))
    # Build the HELLO line with the protocol module and send it.
    if not send(conn, protocol.build_hello(name, tier), logger):
        return ("CLOSED", None)
    # Wait for DATA, DENY or ERR.
    return read_reply(conn, reader, psk, logger)


def send_raw(conn, reader, psk, logger, raw_bytes, label):
    """Send hand-made bytes (used by the tests to send invalid messages)."""
    print("-> " + label)
    # Send the bytes exactly as given, bypassing the builders on purpose.
    if not send(conn, raw_bytes, logger):
        return ("CLOSED", None)
    # Show whatever the server answers.
    return read_reply(conn, reader, psk, logger)


def say_bye(conn, reader, psk, logger):
    """State 5: send BYE and wait for the server's BYE."""
    print("-> BYE")
    # Only wait for the answer if our BYE was actually sent.
    if send(conn, protocol.build_bye(), logger):
        read_reply(conn, reader, psk, logger)


def interactive(conn, reader, psk, logger, name):
    """Let the user make as many requests as they like, then say BYE."""
    while True:
        # Ask which tier to request, or q to finish.
        tier = input("\nTier to request [NS / S / BOTH], or q to quit > ").strip().upper()
        if tier == "Q":
            # Leave the loop; BYE is sent below.
            break
        if tier not in protocol.TIERS:
            # Catch typing mistakes locally instead of bothering the owner.
            print("Please type NS, S, BOTH or q.")
            continue
        # Send the request and show the reply.
        kind, status = request(conn, reader, psk, logger, name, tier)
        if session_over(kind, status):
            # The server ended the session, so there is nobody to say BYE to.
            return
    # Normal exit: end the session politely.
    say_bye(conn, reader, psk, logger)


def run_test(test, conn, reader, psk, logger, name):
    """Run one of the built-in test scenarios on an open connection."""
    # ---- Test 1: one successful session ---------------------------------------
    if test == "1":
        print("TEST 1 - successful session. Approve (y) on the server.")
        kind, status = request(conn, reader, psk, logger, name, "BOTH")
        if not session_over(kind, status):
            say_bye(conn, reader, psk, logger)

    # ---- Test 2: malformed requests each get an error -------------------------
    elif test == "2":
        print("TEST 2 - malformed requests. Each one should get an ERR reply.")
        # Each entry is (bytes to send, description shown on screen).
        bad_messages = [
            (b"HELO|Bob|NS\n", "HELO|Bob|NS          (misspelled message type, expect 400)"),
            (b"HELLO|Bob\n", "HELLO|Bob            (missing tier field, expect 400)"),
            (b"HELLO|Bob|NS|extra\n", "HELLO|Bob|NS|extra   (too many fields, expect 400)"),
            (b"HELLO|" + b"B" * 40 + b"|NS\n", "HELLO|<40-char name>|NS (name over 32 chars, expect 400)"),
            (b"HELLO|Bob|XYZ\n", "HELLO|Bob|XYZ        (unknown tier, expect 422)"),
        ]
        for raw_bytes, label in bad_messages:
            kind, status = send_raw(conn, reader, psk, logger, raw_bytes, label)
            if session_over(kind, status):
                return
        # The session survived every error, so it can still end normally.
        say_bye(conn, reader, psk, logger)

    # ---- Test 3: several requests in one session ------------------------------
    elif test == "3":
        print("TEST 3 - three requests in one session. Answer each on the server.")
        for tier in ("NS", "S", "BOTH"):
            kind, status = request(conn, reader, psk, logger, name, tier)
            if session_over(kind, status):
                return
        say_bye(conn, reader, psk, logger)

    # ---- Test 4a: inactivity timeout ------------------------------------------
    elif test == "4a":
        print("TEST 4a - inactivity. Sending nothing; the server should send ERR 408.")
        read_reply(conn, reader, psk, logger)

    # ---- Test 4b: empty message -----------------------------------------------
    elif test == "4b":
        print("TEST 4b - empty message. The server should reply ERR 400.")
        kind, status = send_raw(conn, reader, psk, logger, b"\n", "(an empty line)")
        if not session_over(kind, status):
            say_bye(conn, reader, psk, logger)

    # ---- Test 4c: oversized message -------------------------------------------
    elif test == "4c":
        print("TEST 4c - oversized message. The server should reply ERR 400.")
        # A 5000-byte name makes the header far longer than the 1024 limit.
        oversized = b"HELLO|" + b"A" * 5000 + b"|NS\n"
        kind, status = send_raw(conn, reader, psk, logger, oversized, "HELLO|<5000 x 'A'>|NS")
        if not session_over(kind, status):
            say_bye(conn, reader, psk, logger)

    # ---- Test 4d: consent timeout ---------------------------------------------
    elif test == "4d":
        print("TEST 4d - consent timeout. Do NOT answer on the server; expect ERR 408.")
        request(conn, reader, psk, logger, name, "NS")

    # ---- Test 5: bad HMAC (extra) ---------------------------------------------
    elif test == "5":
        print("TEST 5 - bad HMAC. Approve (y) on the server; the client checks with a WRONG key.")
        # Verify with a deliberately wrong key so the check must fail.
        kind, status = request(conn, reader, b"deliberately-wrong-key", logger, name, "NS")
        if not session_over(kind, status):
            say_bye(conn, reader, psk, logger)

    # ---- Test 6: drop the connection without BYE (extra) ----------------------
    elif test == "6":
        print("TEST 6 - dropping the connection without BYE. The server should log error 446.")
        # Nothing to do here: main() closes the socket without sending BYE.


def main():
    """Read options, connect, and run either a test or the interactive mode."""
    # ---- command-line options ------------------------------------------------
    parser = argparse.ArgumentParser(description="DSCP client (requester)")
    parser.add_argument("--test", choices=("1", "2", "3", "4a", "4b", "4c", "4d", "5", "6"),
                        help="1 success | 2 malformed | 3 several requests | 4a idle timeout | "
                             "4b empty message | 4c oversized message | 4d consent timeout | "
                             "5 bad HMAC | 6 drop without BYE")
    parser.add_argument("--name", help="requester name (max 32 characters)")
    parser.add_argument("--host", help="server address (default: from config)")
    parser.add_argument("--port", type=int, help="server port (default: from config, 5050)")
    # Read the options the user actually typed.
    args = parser.parse_args()

    # ---- configuration, logging, key ----------------------------------------
    # Read config.ini (or defaults).
    config = security.load_config()
    # Command-line options replace the configured host and port.
    if args.host:
        config["server_host"] = args.host
    if args.port:
        config["port"] = args.port
    # Open logs/client.log for appending.
    logger = security.setup_logger("client", config["log_dir"])
    try:
        # Load the pre-shared HMAC key from the environment or config file.
        psk = security.load_psk(config)
    except security.ConfigError as error:
        # Missing or weak key: explain and stop.
        print("Configuration error: " + str(error))
        sys.exit(1)

    # ---- requester name ------------------------------------------------------
    # Use --name if given; tests default to "Bob"; otherwise ask.
    name = args.name or ("Bob" if args.test else input("Your name (max 32 characters) > ").strip())
    # Check the name locally so an obvious mistake never reaches the owner.
    if not protocol.validate_name(name):
        print("The name must be 1-32 printable characters and must not contain '|'.")
        sys.exit(1)

    # ---- connect -------------------------------------------------------------
    connection = connect(config, logger)
    # None means the server could not be reached (error 447 already shown).
    if connection is None:
        sys.exit(1)
    # Unpack the TLS socket and its message reader.
    conn, reader = connection

    try:
        if args.test:
            # Run the chosen scenario.
            run_test(args.test, conn, reader, psk, logger, name)
        else:
            # Normal use: let the user type requests.
            interactive(conn, reader, psk, logger, name)
    except KeyboardInterrupt:
        # Ctrl+C: still try to end the session politely.
        print()
        send(conn, protocol.build_bye(), logger)
    finally:
        # Always close the socket and record that we disconnected.
        conn.close()
        logger.info("DISCONNECT")


# Run main() only when this file is executed directly, not when imported.
if __name__ == "__main__":
    main()
