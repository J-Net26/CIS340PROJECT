# =============================================================================
# File:           shared/protocol.py
# Purpose:        The single source of truth for the DSCP (Device System
#                 Communication Protocol) message format. It contains:
#                   - the protocol constants (port, tiers, size limits, codes)
#                   - "build" functions that turn values into bytes to send
#                   - a "parse" function that turns a received header line
#                     back into values, rejecting anything malformed
#                   - MessageReader, which reads header lines and DATA bodies
#                     from a socket
#                 Both server/server.py and client/client.py import this file,
#                 so the two sides can never disagree about the format.
# Primary member: Julius (protocol / message format)
# =============================================================================

# "socket" is imported only so we can recognise the socket.timeout exception.
import socket

# -----------------------------------------------------------------------------
# Protocol constants
# -----------------------------------------------------------------------------

# The TCP port DSCP uses when the config file does not say otherwise.
DEFAULT_PORT = 5050

# The three legal tier names. NS = non-sensitive, S = sensitive, BOTH = both.
TIERS = ("NS", "S", "BOTH")

# The longest requester name allowed in a HELLO message (from the spec).
MAX_NAME_LEN = 32

# The longest header line we accept, in bytes, NOT counting the final "\n".
# The longest legal header is a DATA header (about 100 bytes), so 1024 is
# generous while still stopping someone from sending an endless line.
MAX_HEADER_BYTES = 1024

# If a line is too long we throw the rest of it away so the session can carry
# on. This is the most we are willing to throw away before giving up entirely.
MAX_DISCARD_BYTES = 65536

# The largest DATA body we accept, in bytes (1 MiB). Real bodies are < 1 KiB.
MAX_BODY_BYTES = 1048576

# Every header line and every JSON body is encoded as UTF-8 text.
ENCODING = "utf-8"

# Status codes used by the protocol, with a short human-readable meaning.
# 200 and 403 travel inside DATA and DENY; the others travel inside ERR.
STATUS_TEXT = {
    200: "OK",
    400: "Malformed request",
    401: "Bad HMAC (integrity check failed)",
    403: "Consent denied",
    408: "Timeout",
    421: "Permission error reading system info",
    422: "Unknown tier",
    446: "Connection dropped without BYE/DENY",
    447: "Socket unavailable",
    448: "Collection failure",
}


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class ProtocolError(Exception):
    """Raised when a received message breaks the DSCP rules."""

    def __init__(self, status, description, fatal=False):
        # Let the normal Exception class store the description as its message.
        super().__init__(description)
        # The numeric status code that should be reported (for example 400).
        self.status = status
        # A short explanation that is safe to send to the other side.
        self.description = description
        # True means the byte stream can no longer be trusted, so the session
        # must be closed after the error is reported.
        self.fatal = fatal


class ConnectionDropped(Exception):
    """Raised when the other side disappears in the middle of a session."""


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

def _clean(text):
    """Make free text safe to place inside one header field."""
    # Convert whatever we were given (number, exception, ...) to a string.
    text = str(text)
    # "|" separates fields and "\n" ends the header, so neither may appear
    # inside a field. "\r" is removed too so Windows line endings cannot leak.
    for bad in ("|", "\n", "\r"):
        # Swap each forbidden character for a harmless space.
        text = text.replace(bad, " ")
    # Hand the cleaned text back to the caller.
    return text


def validate_name(name):
    """Return True if 'name' is a legal requester name for HELLO."""
    # Rule 1: after removing surrounding spaces there must be something left.
    if len(name.strip()) == 0:
        return False
    # Rule 2: the spec limits the name to 32 characters.
    if len(name) > MAX_NAME_LEN:
        return False
    # Rule 3: only printable characters. This blocks control characters and
    # terminal escape codes, because the name is shown on the owner's screen
    # and written to the log file.
    if not name.isprintable():
        return False
    # Rule 4: the field separator can never be part of a field.
    if "|" in name:
        return False
    # Every rule passed, so the name is legal.
    return True


# -----------------------------------------------------------------------------
# Builders: values -> bytes ready for socket.sendall()
# -----------------------------------------------------------------------------

def build_hello(name, tier):
    """Build 'HELLO|requester_name|tier\\n' (sent by the client)."""
    # Join the three fields with "|", end the line with "\n", encode to bytes.
    return ("HELLO|" + name + "|" + tier + "\n").encode(ENCODING)


def build_data(tier, body, hmac_hex):
    """Build 'DATA|200|tier|body_length|hmac_hex\\n' followed by the body."""
    # len(body) counts BYTES (body is a bytes object), which is exactly what
    # the receiver needs in order to know how much to read after the header.
    header = "DATA|200|" + tier + "|" + str(len(body)) + "|" + hmac_hex + "\n"
    # The message on the wire is the encoded header immediately followed by
    # the raw body bytes. There is no newline after the body.
    return header.encode(ENCODING) + body


def build_deny(reason):
    """Build 'DENY|403|reason\\n' (sent by the server when consent is denied)."""
    # _clean() guarantees the reason cannot break the header format.
    return ("DENY|403|" + _clean(reason) + "\n").encode(ENCODING)


def build_err(status, description):
    """Build 'ERR|status|description\\n' (may be sent by either side)."""
    # str(status) turns the integer code (for example 400) into text.
    return ("ERR|" + str(status) + "|" + _clean(description) + "\n").encode(ENCODING)


def build_bye():
    """Build 'BYE\\n' (ends the session politely)."""
    # BYE has no fields at all, so the message is a constant.
    return b"BYE\n"


# -----------------------------------------------------------------------------
# Parser: one received header line -> dictionary of values
# -----------------------------------------------------------------------------

def parse_header(line):
    """
    Check one header line (already decoded, without its newline) and return a
    dictionary describing it. The dictionary always has a "type" key.
    Raises ProtocolError(400 or 422) if the line breaks the format.
    """
    # An empty line is not a message at all (Test 4: empty message).
    if line == "":
        raise ProtocolError(400, "Empty message")

    # Cut the line into fields at every "|" character.
    parts = line.split("|")
    # The first field is always the message type (HELLO, DATA, ...).
    command = parts[0]

    # ---- HELLO|requester_name|tier ------------------------------------------
    if command == "HELLO":
        # HELLO must have exactly three fields: HELLO, the name and the tier.
        if len(parts) != 3:
            raise ProtocolError(400, "HELLO needs exactly 2 fields: name and tier")
        # Give the two remaining fields readable names.
        name = parts[1]
        tier = parts[2]
        # The name must follow the rules in validate_name() above.
        if not validate_name(name):
            raise ProtocolError(400, "Requester name must be 1-32 printable characters")
        # A tier that is not NS, S or BOTH has its own error code, 422.
        if tier not in TIERS:
            raise ProtocolError(422, "Unknown tier (use NS, S or BOTH)")
        # Everything checked out: return the parsed request.
        return {"type": "HELLO", "name": name, "tier": tier}

    # ---- DATA|200|tier|body_length|hmac_hex ---------------------------------
    if command == "DATA":
        # DATA must have exactly five fields.
        if len(parts) != 5:
            raise ProtocolError(400, "DATA needs exactly 4 fields")
        # The status field of DATA is always the literal text 200.
        if parts[1] != "200":
            raise ProtocolError(400, "DATA status must be 200")
        # The tier field tells the requester what was actually granted.
        if parts[2] not in TIERS:
            raise ProtocolError(422, "Unknown tier in DATA")
        # body_length must be made of ASCII digits only (no sign, no spaces).
        if not (parts[3].isascii() and parts[3].isdigit()):
            raise ProtocolError(400, "DATA body_length must be a number")
        # Now it is safe to convert the length text to an integer.
        length = int(parts[3])
        # Refuse absurd lengths so a bad peer cannot make us allocate memory.
        if length > MAX_BODY_BYTES:
            raise ProtocolError(400, "DATA body is too large")
        # HMAC-SHA256 is 32 bytes, which is always 64 hexadecimal characters.
        hmac_hex = parts[4].lower()
        # Check the length and that every character is a hex digit.
        if len(hmac_hex) != 64 or any(c not in "0123456789abcdef" for c in hmac_hex):
            raise ProtocolError(400, "DATA hmac must be 64 hex characters")
        # Return the parsed header; the caller reads the body separately.
        return {"type": "DATA", "tier": parts[2], "length": length, "hmac": hmac_hex}

    # ---- DENY|403|reason ----------------------------------------------------
    if command == "DENY":
        # DENY must have exactly three fields and its status is always 403.
        if len(parts) != 3 or parts[1] != "403":
            raise ProtocolError(400, "DENY must be DENY|403|reason")
        # Return the reason the owner (or server) gave.
        return {"type": "DENY", "status": 403, "reason": parts[2]}

    # ---- ERR|status|description ---------------------------------------------
    if command == "ERR":
        # ERR must have exactly three fields.
        if len(parts) != 3:
            raise ProtocolError(400, "ERR must be ERR|status|description")
        # The status must be a three-digit number such as 400 or 408.
        if not (parts[1].isascii() and parts[1].isdigit() and len(parts[1]) == 3):
            raise ProtocolError(400, "ERR status must be a 3-digit number")
        # Return the code as an integer plus the description text.
        return {"type": "ERR", "status": int(parts[1]), "description": parts[2]}

    # ---- BYE ----------------------------------------------------------------
    if command == "BYE":
        # BYE has no fields, so anything after it is malformed.
        if len(parts) != 1:
            raise ProtocolError(400, "BYE takes no fields")
        # Return a dictionary with only the type.
        return {"type": "BYE"}

    # ---- anything else ------------------------------------------------------
    # The first field was not one of the five message types we know.
    raise ProtocolError(400, "Unknown message type")


# -----------------------------------------------------------------------------
# MessageReader: turns a stream of bytes into header lines and bodies
# -----------------------------------------------------------------------------

class MessageReader:
    """
    TCP (and TLS on top of it) delivers a continuous STREAM of bytes, not
    separate messages. One recv() call may return half a line or two lines.
    This class keeps the leftover bytes in a buffer so callers can simply ask
    for "the next header line" or "exactly N bytes of body".
    """

    def __init__(self, sock):
        # The connected (TLS-wrapped) socket we read from.
        self.sock = sock
        # Bytes that have arrived but have not been handed to the caller yet.
        self.buffer = b""

    def _recv(self):
        """Read the next chunk of bytes from the socket."""
        try:
            # Ask the operating system for up to 4096 bytes. This blocks until
            # data arrives, the peer closes, or the socket timeout expires.
            chunk = self.sock.recv(4096)
        except socket.timeout:
            # A timeout is not a dropped connection. Pass it up unchanged so
            # the caller can answer with ERR 408.
            raise
        except OSError as error:
            # Any other socket/TLS failure (reset, broken pipe, bad TLS record)
            # means the peer is gone. Only the error TYPE is kept, never
            # addresses, so it is safe to log.
            raise ConnectionDropped(type(error).__name__)
        # recv() returning zero bytes is how TCP reports "the peer closed".
        if chunk == b"":
            raise ConnectionDropped("peer closed the connection")
        # Give the received bytes to the caller.
        return chunk

    def _discard_rest_of_line(self):
        """Throw away an over-long line up to and including its newline."""
        # Count how much we are throwing away, starting with the buffer.
        discarded = len(self.buffer)
        # Empty the buffer: none of it is usable.
        self.buffer = b""
        # Keep reading until we find the newline that ends the bad line.
        while True:
            # Stop if the peer keeps sending without ever ending the line.
            if discarded > MAX_DISCARD_BYTES:
                # fatal=True tells the caller to close the session.
                raise ProtocolError(400, "Header line far too long", fatal=True)
            # Read the next piece of the over-long line.
            chunk = self._recv()
            # Add its size to the running total.
            discarded += len(chunk)
            # Did this chunk contain the end of the line?
            if b"\n" in chunk:
                # Keep only what came AFTER the newline: that is the start of
                # the next message, which may be perfectly valid.
                self.buffer = chunk.split(b"\n", 1)[1]
                # The stream is back in step, so stop discarding.
                return

    def read_line(self):
        """Return the next header line as text, without its newline."""
        # Keep reading until the buffer contains a complete line.
        while b"\n" not in self.buffer:
            # No newline yet. If we already hold more than the limit, this
            # cannot be a legal header (Test 4: oversized message).
            if len(self.buffer) > MAX_HEADER_BYTES:
                # Get rid of the rest of the bad line...
                self._discard_rest_of_line()
                # ...and report it. Not fatal: the next line can be read.
                raise ProtocolError(400, "Header line too long")
            # Read more bytes and add them to the end of the buffer.
            self.buffer += self._recv()
        # Split at the FIRST newline: "line" is before it, the rest is kept
        # in the buffer for the next call.
        line, _, self.buffer = self.buffer.partition(b"\n")
        # A whole line that arrived in one chunk can still be too long.
        if len(line) > MAX_HEADER_BYTES:
            raise ProtocolError(400, "Header line too long")
        try:
            # Turn the bytes into text. Invalid UTF-8 raises an exception.
            text = line.decode(ENCODING)
        except UnicodeDecodeError:
            # Bytes that are not text cannot be a DSCP header.
            raise ProtocolError(400, "Header is not valid UTF-8 text")
        # Be tolerant of Windows-style "\r\n" endings by dropping a final "\r".
        return text.rstrip("\r")

    def read_exact(self, count):
        """Return exactly 'count' bytes (used for the DATA body)."""
        # Keep reading until the buffer holds at least 'count' bytes.
        while len(self.buffer) < count:
            # Add the next chunk to the buffer.
            self.buffer += self._recv()
        # The first 'count' bytes are the body we were asked for.
        body = self.buffer[:count]
        # Whatever follows belongs to the next message, so keep it.
        self.buffer = self.buffer[count:]
        # Hand the body back.
        return body
