# =============================================================================
# File:           generate_cert.py
# Purpose:        One-time setup script that creates the self-signed TLS
#                 certificate (certs/server.crt) and its private key
#                 (certs/server.key) used by the DSCP server.
#                 Python's standard library cannot create certificates, so
#                 this script uses whichever of these is available:
#                   1. the "openssl" command (built into macOS and Linux,
#                      and included with Git for Windows), or
#                   2. the "cryptography" Python package
#                      (pip install cryptography).
#                 The DSCP server and client themselves need neither.
#
#                 Run from the project root:   python generate_cert.py
# Primary member: Seth (security: TLS, HMAC, logging)
# =============================================================================

# datetime sets the certificate's validity dates (cryptography method only).
import datetime
# os handles folders and file paths.
import os
# shutil.which() looks for a program on the PATH, like typing its name.
import shutil
# subprocess runs the openssl command.
import subprocess
# sys gives access to command-line arguments and exit().
import sys

# Reuse the config loader so the files are written exactly where the server
# and client will look for them.
from shared import security

# The name written inside the certificate. The client pins the certificate
# itself rather than checking this name, so any label works.
COMMON_NAME = "DSCP-Server"
# How long the certificate stays valid.
VALID_DAYS = 365


def find_openssl():
    """Return the path of the openssl program, or None if it is not installed."""
    # First look on the PATH (this is all macOS and Linux need).
    found = shutil.which("openssl")
    if found:
        return found
    # Git for Windows ships openssl but does not put it on the PATH.
    for candidate in (r"C:\Program Files\Git\usr\bin\openssl.exe",
                      r"C:\Program Files\Git\mingw64\bin\openssl.exe"):
        # Use the first one that actually exists on this machine.
        if os.path.isfile(candidate):
            return candidate
    # openssl is not available.
    return None


def generate_with_openssl(openssl, cert_file, key_file):
    """Create the key and certificate by running one openssl command."""
    command = [
        openssl, "req",          # "req" is openssl's certificate tool
        "-x509",                 # output a self-signed certificate
        "-newkey", "rsa:2048",   # and create a new 2048-bit RSA key for it
        "-nodes",                # do not password-protect the key file
        "-sha256",               # sign the certificate with SHA-256
        "-days", str(VALID_DAYS),            # validity period
        "-subj", "/CN=" + COMMON_NAME,       # the name inside the certificate
        "-keyout", key_file,     # where to write the private key
        "-out", cert_file,       # where to write the certificate
    ]
    # Run the command. check=True raises an error if openssl fails;
    # capture_output hides openssl's progress dots.
    subprocess.run(command, check=True, capture_output=True)


def generate_with_cryptography(cert_file, key_file):
    """Create the key and certificate with the 'cryptography' package."""
    # Imported here (not at the top) so the script still starts when the
    # package is not installed and openssl is used instead.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Create a new 2048-bit RSA private key (65537 is the standard exponent).
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Self-signed means the subject (owner) and issuer (signer) are the same.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME)])
    # The current time in UTC, used for the validity dates.
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)                                   # who the certificate is for
        .issuer_name(name)                                    # who signed it (ourselves)
        .public_key(key.public_key())                         # the public half of our key
        .serial_number(x509.random_serial_number())           # a unique number
        .not_valid_before(now - datetime.timedelta(days=1))   # tolerate clock differences
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        # Mark it as a certificate authority so it can be its own trust root.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())                           # sign with our private key
    )
    # Write the private key in PEM text format, without a password.
    with open(key_file, "wb") as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    # Write the certificate in PEM text format.
    with open(cert_file, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))


def main():
    """Create certs/server.crt and certs/server.key."""
    # Find out where the config says the two files belong.
    config = security.load_config()
    cert_file = config["cert_file"]
    key_file = config["key_file"]

    # Never silently replace an existing certificate: clients that pinned the
    # old one would stop trusting the server. "--force" overrides this.
    if os.path.exists(cert_file) and "--force" not in sys.argv:
        print("A certificate already exists at " + cert_file)
        print("Run again with --force to replace it.")
        return

    # Create the certs folder if needed.
    os.makedirs(os.path.dirname(cert_file), exist_ok=True)
    os.makedirs(os.path.dirname(key_file), exist_ok=True)

    # Method 1: the openssl command.
    openssl = find_openssl()
    if openssl:
        try:
            generate_with_openssl(openssl, cert_file, key_file)
            method = "openssl"
        except (OSError, subprocess.CalledProcessError):
            # openssl exists but failed; fall through to method 2.
            openssl = None
    # Method 2: the cryptography package.
    if not openssl:
        try:
            generate_with_cryptography(cert_file, key_file)
            method = "the cryptography package"
        except ImportError:
            # Neither tool is available: explain how to get one and stop.
            print("Could not create the certificate: no 'openssl' command was found and")
            print("the 'cryptography' package is not installed. Fix it with ONE of:")
            print("  pip install cryptography        (then run this script again)")
            print("  install Git for Windows / OpenSSL (then run this script again)")
            sys.exit(1)

    # Tell the user what was created and what to do with each file.
    print("Created with " + method + ":")
    print("  " + cert_file + "   (public  - copy this file to the client device)")
    print("  " + key_file + "   (PRIVATE - never copy or share this file)")


# Run main() only when this file is executed directly.
if __name__ == "__main__":
    main()
