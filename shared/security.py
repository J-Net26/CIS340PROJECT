# =============================================================================
# File:           shared/security.py
# Purpose:        Everything security-related that the server and the client
#                 share:
#                   - reading the config file and the pre-shared key (PSK)
#                   - building the TLS contexts that encrypt the whole session
#                   - computing and checking the HMAC-SHA256 of a DATA body
#                   - creating the log file writer
# Primary member: Seth (security: TLS, HMAC, logging)
# =============================================================================

# configparser reads ".ini" style configuration files.
import configparser
# hashlib provides the SHA-256 hash function used inside the HMAC.
import hashlib
# hmac implements HMAC and a timing-safe comparison function.
import hmac
# logging writes timestamped event lines to the log file.
import logging
# os gives access to environment variables and file-path helpers.
import os
# ssl is Python's TLS library (it wraps OpenSSL).
import ssl

# The project root is the folder ABOVE this file's folder ("shared/..").
# __file__ is this file's path; abspath makes it absolute; dirname strips one
# level each time it is called.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The value shipped in config.example.ini. It is refused as a real key so
# nobody runs the system with a key that is published in the repository.
PLACEHOLDER_PSK = "CHANGE_ME"

# The shortest key we accept, in characters. Short keys are easy to guess.
MIN_PSK_LENGTH = 16


class ConfigError(Exception):
    """Raised when the configuration is missing something we need."""


def _resolve(path):
    """Turn a path from the config file into an absolute path."""
    # A path that is already absolute (C:\... or /home/...) is used as it is.
    if os.path.isabs(path):
        return path
    # A relative path is taken to be relative to the project root, so the
    # programs behave the same no matter which folder they are started from.
    return os.path.join(PROJECT_ROOT, path)


def load_config():
    """Read config.ini (if present) and return the settings as a dictionary."""
    # The DSCP_CONFIG environment variable may point at another config file;
    # otherwise we use config.ini in the project root.
    path = os.environ.get("DSCP_CONFIG", os.path.join(PROJECT_ROOT, "config.ini"))
    # Create an empty parser object.
    parser = configparser.ConfigParser()
    # read() silently skips a missing file, so every setting below has a
    # default value (the "fallback") and the file is optional.
    parser.read(path, encoding="utf-8")
    # Build one plain dictionary so the rest of the code never touches the
    # parser directly.
    return {
        # The address the CLIENT connects to (the owner's device).
        "server_host": parser.get("network", "server_host", fallback="127.0.0.1"),
        # The address the SERVER listens on. 0.0.0.0 means "every network
        # interface", which lets other devices on the network reach it.
        "bind_host": parser.get("network", "bind_host", fallback="0.0.0.0"),
        # The TCP port. The spec fixes this at 5050.
        "port": parser.getint("network", "port", fallback=5050),
        # Seconds of inactivity before the server sends ERR 408.
        "timeout": parser.getfloat("network", "timeout_seconds", fallback=60.0),
        # Seconds the client waits for a reply (the owner needs time to read
        # the consent screen, so this is longer than the server timeout).
        "reply_timeout": parser.getfloat("network", "reply_timeout_seconds", fallback=300.0),
        # The pre-shared key exactly as written in the file (may be empty).
        "psk": parser.get("security", "psk", fallback=""),
        # The server's certificate (public; the client needs a copy).
        "cert_file": _resolve(parser.get("security", "cert_file", fallback="certs/server.crt")),
        # The server's private key (secret; never leaves the owner's device).
        "key_file": _resolve(parser.get("security", "key_file", fallback="certs/server.key")),
        # The folder where log files are written.
        "log_dir": _resolve(parser.get("logging", "log_dir", fallback="logs")),
    }


def load_psk(config):
    """Return the pre-shared key as bytes, or raise ConfigError."""
    # The DSCP_PSK environment variable wins over the config file. If it is
    # not set, fall back to the value read from config.ini.
    key = os.environ.get("DSCP_PSK", config["psk"]).strip()
    # Refuse to run with no key or with the published placeholder.
    if key == "" or key == PLACEHOLDER_PSK:
        raise ConfigError(
            "No pre-shared key set. Put one in config.ini under [security] psk, "
            "or set the DSCP_PSK environment variable. See README.md."
        )
    # Refuse keys that are too short to be secure.
    if len(key) < MIN_PSK_LENGTH:
        raise ConfigError("The pre-shared key must be at least 16 characters long.")
    # HMAC works on bytes, so encode the text key once here.
    return key.encode("utf-8")


def compute_hmac(key, body):
    """Return the HMAC-SHA256 of 'body' as 64 hexadecimal characters."""
    # hmac.new mixes the secret key with the body using SHA-256. Without the
    # key nobody can produce the right value, so a matching HMAC proves the
    # body was not changed and came from someone who knows the key.
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_hmac(key, body, received_hex):
    """Return True only if 'received_hex' is the correct HMAC for 'body'."""
    # Recompute what the HMAC SHOULD be from the body we actually received.
    expected = compute_hmac(key, body)
    # compare_digest takes the same time whether the strings differ at the
    # first character or the last, so an attacker cannot learn the correct
    # value one character at a time by measuring how long the check takes.
    return hmac.compare_digest(expected, received_hex)


def make_server_context(cert_file, key_file):
    """Build the TLS settings used by the server."""
    # PROTOCOL_TLS_SERVER selects "act as a TLS server" with safe defaults.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Refuse the old, broken protocol versions (SSLv3, TLS 1.0, TLS 1.1).
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Load our certificate (sent to clients) and the matching private key
    # (used to prove we own the certificate).
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    # Return the finished context; the server uses it to wrap each socket.
    return context


def make_client_context(cert_file):
    """Build the TLS settings used by the client."""
    # PROTOCOL_TLS_CLIENT selects "act as a TLS client" with safe defaults.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Same minimum protocol version as the server.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Our certificate is self-signed and the server may be reached by any IP
    # address, so the name written inside the certificate cannot be matched
    # against the address. Name checking is therefore switched off...
    context.check_hostname = False
    # ...but certificate checking stays ON: the handshake fails unless the
    # server proves it holds the private key for a certificate we trust.
    context.verify_mode = ssl.CERT_REQUIRED
    # Trust exactly ONE certificate: our own copy of the server's certificate.
    # This is called "certificate pinning". An impostor without the server's
    # private key cannot pass the handshake.
    context.load_verify_locations(cafile=cert_file)
    # Return the finished context; the client uses it to wrap its socket.
    return context


def setup_logger(name, log_dir):
    """Create a logger that appends to <log_dir>/<name>.log."""
    # Create the log folder if it does not exist yet (no error if it does).
    os.makedirs(log_dir, exist_ok=True)
    # Get (or create) the logger with this name, e.g. "server" or "client".
    logger = logging.getLogger("dscp." + name)
    # Record INFO and anything more serious (WARNING, ERROR).
    logger.setLevel(logging.INFO)
    # Do not also pass records to Python's root logger, which could print
    # them on the screen in the middle of the consent prompt.
    logger.propagate = False
    # Only add the file handler once, even if this function is called twice.
    if not logger.handlers:
        # A FileHandler appends each record to the given file.
        handler = logging.FileHandler(os.path.join(log_dir, name + ".log"), encoding="utf-8")
        # Each line looks like: 2026-11-15 14:03:22,481 INFO CONNECT session=1
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        # Attach the handler so the logger actually writes somewhere.
        logger.addHandler(handler)
    # NOTE: callers must never pass sensitive values (data values, host name,
    # IP or MAC addresses, the PSK) to this logger. Only event names, session
    # numbers, tiers, field NAMES and status codes are logged.
    return logger
