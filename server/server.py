# =============================================================================
# File:           server/server.py
# Purpose:        The DSCP server. It runs on the OWNER's device, listens on
#                 TCP port 5050, wraps every connection in TLS, and for each
#                 HELLO request it collects the system info, asks the owner
#                 for consent in this terminal, and replies with DATA, DENY
#                 or ERR. Every error in the spec is SENT to the client as a
#                 message; the server never just crashes or closes.
#
#                 Run from the project root:   python server/server.py
# Primary member: Albert (code / testing)
# =============================================================================

# argparse reads the command-line options (--timeout, --simulate-error).
import argparse
# json turns the collected dictionary into the text body of a DATA message.
import json
# os and sys are used for the import-path fix just below.
import os
import sys
# socket provides TCP; ssl (used through shared/security.py) provides TLS.
import socket
# threading lets the server answer "busy" while a session is in progress.
import threading

# This file lives in <project>/server/. Python only searches the folder of
# the script being run, so add the project root to the search path. After
# this line "import shared..." and "import server..." both work.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The message format (Julius' module).
from shared import protocol
# TLS, HMAC, config and logging helpers (Seth's module).
from shared import security
# The owner's consent screen.
from server import consent
# The system-information collector.
from server import sysinfo

# The consent prompt uses ONE terminal, so only one session can be active at
# a time. Whoever holds this lock owns the terminal.
session_lock = threading.Lock()


def send(conn, message, logger, session_id):
    """Send bytes to the client. Returns False instead of crashing on failure."""
    try:
        # sendall() keeps sending until every byte has been handed to TCP.
        conn.sendall(message)
        # The whole message was sent.
        return True
    except OSError:
        # The client has gone away. Log it (no addresses) and carry on.
        logger.warning("SEND_FAILED session=%d", session_id)
        return False


def send_err(conn, status, description, logger, session_id):
    """Log an error and send it to the client as ERR|status|description."""
    # Record the error code in the log file (never any data values).
    logger.error("ERROR session=%d status=%d %s", session_id, status, description)
    # Also show it in the owner's terminal.
    print("[session %d] sent ERR %d: %s" % (session_id, status, description))
    # Build the ERR line with the protocol module and send it.
    send(conn, protocol.build_err(status, description), logger, session_id)


def handle_hello(conn, message, psk, timeout, simulate, logger, session_id):
    """
    Handle one HELLO request (state-machine steps 3 and 4).
    Returns what happened as a word:
      "data"  - DATA was sent           (session continues)
      "deny"  - DENY was sent           (session continues)
      "error" - ERR 421/448 was sent    (session continues)
      "end"   - the session must be closed (consent timeout or client gone)
    """
    # Pull the two validated fields out of the parsed message.
    name = message["name"]
    tier = message["tier"]
    # Log the request. The requester name was validated as printable text.
    logger.info("REQUEST session=%d requester=%s tier=%s", session_id, name, tier)

    # ---- collect the data first, so the owner sees the real values ----------
    try:
        # Read the fields for the requested tier from the operating system.
        data = sysinfo.collect(tier, simulate)
    except PermissionError:
        # The operating system refused access: error 421.
        send_err(conn, 421, "Permission error reading system info", logger, session_id)
        # The session stays open; the requester may try again.
        return "error"
    except Exception as error:
        # Any other failure while collecting: error 448. Only the exception
        # TYPE goes to the log, in case its text contains system details.
        logger.error("COLLECT_FAILED session=%d type=%s", session_id, type(error).__name__)
        send_err(conn, 448, "Collection failure", logger, session_id)
        # The session stays open.
        return "error"

    # ---- ask the owner (nothing has been transmitted yet) -------------------
    decision, approved = consent.ask_consent(name, tier, data, timeout)

    # ---- the owner did not answer in time: ERR 408 and end the session ------
    if decision == "timeout":
        logger.info("CONSENT session=%d decision=timeout", session_id)
        send_err(conn, 408, "Timeout waiting for the owner's consent", logger, session_id)
        # "end" tells the caller to close the session.
        return "end"

    # ---- the owner said no: DENY|403|reason ---------------------------------
    if decision == "deny":
        logger.info("CONSENT session=%d decision=deny", session_id)
        print("[session %d] denied. Sending DENY 403." % session_id)
        send(conn, protocol.build_deny("Owner denied the request"), logger, session_id)
        # The session stays open; the requester may ask again or say BYE.
        return "deny"

    # ---- the owner approved: build and send DATA ----------------------------
    # The tier label describes what is ACTUALLY sent after any trimming.
    sent_tier = sysinfo.tier_of(approved)
    # Convert the dictionary to JSON text, then to UTF-8 bytes. sort_keys
    # makes the output order predictable.
    body = json.dumps(approved, sort_keys=True).encode(protocol.ENCODING)
    # Compute the HMAC-SHA256 of the exact bytes we are about to send.
    mac = security.compute_hmac(psk, body)
    # Log the decision with field NAMES only, never their values.
    logger.info("CONSENT session=%d decision=approve tier_sent=%s fields=%s",
                session_id, sent_tier, ",".join(sorted(approved)))
    print("[session %d] approved. Sending DATA (%d bytes, tier %s)." % (session_id, len(body), sent_tier))
    # Send the DATA header followed by the body. send() returns False if the
    # client is gone, in which case the session must end.
    if send(conn, protocol.build_data(sent_tier, body, mac), logger, session_id):
        return "data"
    return "end"


def run_session(conn, psk, timeout, simulate, logger, session_id):
    """Serve one client until BYE, a timeout, or a dropped connection."""
    # The reader turns the byte stream into header lines.
    reader = protocol.MessageReader(conn)
    # From now on, any recv() that waits longer than 'timeout' seconds raises
    # socket.timeout. This implements the 60-second inactivity rule.
    conn.settimeout(timeout)
    # Remembers whether our most recent reply was DENY. The spec says a close
    # after DENY is acceptable, so it is not reported as error 446.
    last_reply_was_deny = False

    # Each pass through this loop handles one message from the client.
    while True:
        # ---- read the next header line --------------------------------------
        try:
            line = reader.read_line()
        except socket.timeout:
            # State 6: no activity for 'timeout' seconds. Tell the client
            # with ERR 408 and end the session.
            send_err(conn, 408, "Timeout: no activity for %d seconds" % timeout, logger, session_id)
            return
        except protocol.ConnectionDropped:
            # The client vanished without sending BYE.
            if last_reply_was_deny:
                # Leaving right after a DENY is allowed by the spec.
                logger.info("CLOSED_AFTER_DENY session=%d", session_id)
            else:
                # Error 446. We still TRY to send it (the client may only
                # have closed its sending direction), but it usually cannot
                # be delivered, so the log entry is the reliable record.
                send_err(conn, 446, "Connection dropped without BYE/DENY", logger, session_id)
            return
        except protocol.ProtocolError as error:
            # The line was too long or not valid text (Test 4: oversized).
            send_err(conn, error.status, error.description, logger, session_id)
            # A fatal error means we lost track of the stream: end the session.
            if error.fatal:
                return
            # Otherwise wait for the next message.
            continue

        # ---- check the line against the message format ----------------------
        try:
            message = protocol.parse_header(line)
        except protocol.ProtocolError as error:
            # Malformed request (400) or unknown tier (422). Send the error
            # and keep the session open (Test 2).
            send_err(conn, error.status, error.description, logger, session_id)
            continue

        # ---- BYE: reply BYE and close (state 5) ------------------------------
        if message["type"] == "BYE":
            logger.info("BYE session=%d", session_id)
            # The spec says the server answers BYE with BYE.
            send(conn, protocol.build_bye(), logger, session_id)
            return

        # ---- ERR from the client (for example 401 after a bad HMAC) ---------
        if message["type"] == "ERR":
            # Just record that the client reported a problem; no reply needed.
            logger.error("CLIENT_ERR session=%d status=%d", session_id, message["status"])
            print("[session %d] client reported ERR %d" % (session_id, message["status"]))
            continue

        # ---- DATA or DENY are server-to-client only -------------------------
        if message["type"] != "HELLO":
            # A well-formed message that a client is not allowed to send.
            send_err(conn, 400, "Unexpected message type from a requester", logger, session_id)
            continue

        # ---- HELLO: collect, ask for consent, reply -------------------------
        outcome = handle_hello(conn, message, psk, timeout, simulate, logger, session_id)
        # "end" means a consent timeout or a failed send: end the session.
        if outcome == "end":
            return
        # Remember whether this reply was a DENY (see the 446 rule above).
        last_reply_was_deny = (outcome == "deny")


def handle_connection(raw, tls_context, psk, timeout, simulate, logger, session_id):
    """Runs in its own thread for every incoming TCP connection."""
    # 'conn' will become the TLS socket; None means "handshake not done yet".
    conn = None
    try:
        # Do not let a silent client stall the TLS handshake forever.
        raw.settimeout(10)
        try:
            # State 1: perform the TLS handshake. From here on everything
            # sent or received through 'conn' is encrypted.
            conn = tls_context.wrap_socket(raw, server_side=True)
        except OSError as error:
            # ssl.SSLError is a kind of OSError. The peer did not speak TLS
            # or rejected our certificate. Log the error type only.
            logger.warning("TLS_HANDSHAKE_FAILED session=%d type=%s", session_id, type(error).__name__)
            return

        # Try to take the terminal. blocking=False returns immediately with
        # False if another session already holds it.
        if not session_lock.acquire(blocking=False):
            # Error 447: we cannot serve this socket right now.
            send_err(conn, 447, "Socket unavailable: server is busy with another session", logger, session_id)
            try:
                # Give the client up to 2 seconds to read the error and close.
                # Closing while its HELLO is still unread could reset the
                # connection and destroy our ERR message on the way.
                conn.settimeout(2)
                conn.recv(4096)
            except OSError:
                # Timeout or closed connection: either is fine here.
                pass
            return

        try:
            # We own the terminal: log the connection (no IP address) and
            # serve the client.
            logger.info("CONNECT session=%d tls=%s", session_id, conn.version())
            print("\n[session %d] requester connected (%s)" % (session_id, conn.version()))
            run_session(conn, psk, timeout, simulate, logger, session_id)
        finally:
            # Always give the terminal back, even if something went wrong.
            session_lock.release()
            logger.info("DISCONNECT session=%d", session_id)
            print("[session %d] session ended. Waiting for the next requester..." % session_id)
    except Exception as error:
        # Last line of defence: an unexpected bug in one session must never
        # take down the whole server. Log the type and move on.
        logger.error("INTERNAL_ERROR session=%d type=%s", session_id, type(error).__name__)
    finally:
        # Close whichever socket we ended up with (TLS if the handshake
        # succeeded, otherwise the plain TCP socket).
        try:
            (conn or raw).close()
        except OSError:
            # Closing an already-dead socket can fail; nothing to do.
            pass


def main():
    """Start the server and accept connections until Ctrl+C."""
    # ---- command-line options ------------------------------------------------
    parser = argparse.ArgumentParser(description="DSCP server (owner's device)")
    # Lets a demo use a short timeout instead of waiting the full 60 seconds.
    parser.add_argument("--timeout", type=float, help="inactivity timeout in seconds (default: from config, 60)")
    # Forces error 421 or 448 so those codes can be demonstrated on demand.
    parser.add_argument("--simulate-error", type=int, choices=(421, 448),
                        help="pretend system-info collection fails with this code")
    # Read the options the user actually typed.
    args = parser.parse_args()

    # ---- configuration, logging, key ----------------------------------------
    # Read config.ini (or defaults).
    config = security.load_config()
    # Open logs/server.log for appending.
    logger = security.setup_logger("server", config["log_dir"])
    # The command-line timeout, if given, replaces the configured one.
    timeout = args.timeout if args.timeout is not None else config["timeout"]
    try:
        # Load the pre-shared HMAC key from the environment or config file.
        psk = security.load_psk(config)
        # Load the certificate and private key and build the TLS settings.
        tls_context = security.make_server_context(config["cert_file"], config["key_file"])
    except security.ConfigError as error:
        # Missing or weak key: explain and stop.
        print("Configuration error: " + str(error))
        logger.error("STARTUP_FAILED reason=config")
        sys.exit(1)
    except OSError:
        # FileNotFoundError and ssl.SSLError are both kinds of OSError.
        print("Cannot load the TLS certificate/key. Run:  python generate_cert.py")
        logger.error("STARTUP_FAILED reason=certificate")
        sys.exit(1)

    # ---- open the listening socket -------------------------------------------
    try:
        # create_server() makes a TCP socket, binds it to the address and
        # port, and starts listening, all in one call.
        listener = socket.create_server((config["bind_host"], config["port"]))
    except OSError:
        # Error 447 on our side: the port is already in use or not permitted.
        # There is no client to send it to yet, so it is logged and shown.
        logger.error("ERROR status=447 Socket unavailable: cannot listen on port %d", config["port"])
        print("ERR 447: Socket unavailable - cannot listen on port %d (already in use?)" % config["port"])
        sys.exit(1)

    # accept() will give up after 1 second so the loop below can notice
    # Ctrl+C promptly on every operating system.
    listener.settimeout(1.0)
    # Start the background thread that feeds typed lines to the consent prompt.
    consent.start_keyboard_thread()
    logger.info("SERVER_START port=%d timeout=%d", config["port"], timeout)
    print("DSCP server listening on port %d (TLS). Press Ctrl+C to stop." % config["port"])

    # Sessions are numbered 1, 2, 3... The number identifies a session in the
    # log without recording the client's IP address.
    session_id = 0
    try:
        while True:
            try:
                # Wait (up to 1 second) for a client to connect. 'raw' is the
                # new plain TCP socket; the address is deliberately unused.
                raw, _address = listener.accept()
            except socket.timeout:
                # Nobody connected during this second: wait again.
                continue
            # Give the new connection the next session number.
            session_id += 1
            # Serve it in its own thread so this loop can keep accepting
            # (and can tell a second client that the server is busy).
            threading.Thread(
                target=handle_connection,
                args=(raw, tls_context, psk, timeout, args.simulate_error, logger, session_id),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        # The owner pressed Ctrl+C: shut down cleanly.
        print("\nServer stopped.")
        logger.info("SERVER_STOP")
    finally:
        # Release the port.
        listener.close()


# Run main() only when this file is executed directly, not when imported.
if __name__ == "__main__":
    main()
