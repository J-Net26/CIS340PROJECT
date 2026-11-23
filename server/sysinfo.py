# =============================================================================
# File:           server/sysinfo.py
# Purpose:        Collects the system information that DSCP can share, split
#                 into the two tiers from the spec:
#                   NS (non-sensitive): CPU / memory / disk usage, temperatures
#                   S  (sensitive):     host name, IP address, MAC address
#                 Works on Windows, macOS and Linux. Anything an operating
#                 system cannot provide is reported as "unavailable" instead
#                 of crashing.
# Primary member: Albert (code / testing)
# =============================================================================

# os is used to find the root of the current drive for the disk reading.
import os
# socket gives the host name and lets us discover the local IP address.
import socket
# uuid.getnode() is the standard-library fallback for the MAC address.
import uuid

# psutil is the one third-party library: it reads CPU, memory, disk, sensors.
import psutil

# The field names in each tier, in the order they are shown to the owner.
NS_FIELDS = ("cpu_percent", "memory_percent", "disk_percent", "temperatures")
S_FIELDS = ("hostname", "ip_address", "mac_address")

# The text used whenever a value cannot be read on this machine.
UNAVAILABLE = "unavailable"


def field_tier(field):
    """Return "NS" or "S" for one field name."""
    # A field is non-sensitive if it is in the NS list, otherwise sensitive.
    return "NS" if field in NS_FIELDS else "S"


def tier_of(fields):
    """Work out which tier label describes a set of field names."""
    # True if at least one of the given fields is a non-sensitive field.
    has_ns = any(field in NS_FIELDS for field in fields)
    # True if at least one of the given fields is a sensitive field.
    has_s = any(field in S_FIELDS for field in fields)
    # Both kinds present means the label is BOTH.
    if has_ns and has_s:
        return "BOTH"
    # Otherwise it is whichever single kind is present.
    return "S" if has_s else "NS"


def _temperatures():
    """Return a dictionary of sensor readings, or "unavailable"."""
    # psutil only has sensors_temperatures() on Linux and FreeBSD. getattr
    # returns None on Windows and macOS instead of raising an error.
    reader = getattr(psutil, "sensors_temperatures", None)
    # No such function on this operating system.
    if reader is None:
        return UNAVAILABLE
    try:
        # Returns {chip_name: [reading, reading, ...]} or {} if no sensors.
        sensors = reader()
    except Exception:
        # Temperatures are optional, so any failure here is not an error for
        # the whole request; we simply report that they are unavailable.
        return UNAVAILABLE
    # An empty result (common in virtual machines) also means unavailable.
    if not sensors:
        return UNAVAILABLE
    # Build a simple {label: degrees_celsius} dictionary for the JSON body.
    readings = {}
    # Go through every chip (for example "coretemp") and its list of readings.
    for chip, entries in sensors.items():
        # enumerate numbers the readings 0, 1, 2... for sensors with no label.
        for index, entry in enumerate(entries):
            # Use the sensor's own label when it has one, else its number.
            label = entry.label if entry.label else str(index)
            # entry.current is the temperature right now, in Celsius.
            readings[chip + "/" + label] = entry.current
    # Return all readings found.
    return readings


def _ip_address():
    """Return this device's local network IP address."""
    # Create a UDP socket. UDP is connectionless, so nothing is transmitted.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # "Connecting" a UDP socket only asks the operating system which
        # network interface it WOULD use to reach that address. 192.0.2.1 is
        # a reserved documentation address; no packet is ever sent to it.
        probe.connect(("192.0.2.1", 9))
        # getsockname() now reports the local address of that interface.
        return probe.getsockname()[0]
    except OSError:
        # No network route (for example Wi-Fi is off). Try the host name.
        try:
            # Look up the address registered for our own host name.
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            # Still nothing: report it rather than crash.
            return UNAVAILABLE
    finally:
        # Always release the probe socket, whichever path we took.
        probe.close()


def _mac_address(ip_address):
    """Return the MAC address of the interface that owns 'ip_address'."""
    # psutil.net_if_addrs() returns {interface_name: [address, address, ...]}.
    for addresses in psutil.net_if_addrs().values():
        # Does this interface carry the IP address we found above?
        if any(a.family == socket.AF_INET and a.address == ip_address for a in addresses):
            # Yes: now look for its hardware (link-layer) address entry.
            for address in addresses:
                # psutil.AF_LINK marks the MAC address on every platform.
                if address.family == psutil.AF_LINK:
                    # Windows writes AA-BB-..., so normalise to aa:bb:...
                    return address.address.replace("-", ":").lower()
    # Fallback: uuid.getnode() returns a MAC address as a 48-bit integer.
    node = uuid.getnode()
    # Take the six bytes from most significant to least significant
    # (shift right by 40, 32, ... 0 bits), format each as two hex digits,
    # and join them with ":" in the usual aa:bb:cc:dd:ee:ff style.
    return ":".join("%02x" % ((node >> shift) & 0xFF) for shift in range(40, -8, -8))


def collect(tier, simulate=None):
    """
    Collect the fields for 'tier' ("NS", "S" or "BOTH") and return them as a
    dictionary {field_name: value}.

    Raises PermissionError if the operating system refuses access (the server
    reports this as ERR 421). Any other exception is a collection failure
    (the server reports it as ERR 448).

    'simulate' may be 421 or 448 to force that error for demonstrations.
    """
    # Test hook: pretend the operating system denied permission.
    if simulate == 421:
        raise PermissionError("simulated permission error")
    # Test hook: pretend the collection broke for some other reason.
    if simulate == 448:
        raise RuntimeError("simulated collection failure")

    # The dictionary we fill in and return.
    data = {}
    try:
        # ---- non-sensitive tier ---------------------------------------------
        if tier in ("NS", "BOTH"):
            # CPU usage measured over half a second (0 would compare against
            # the last call and return a meaningless 0.0 the first time).
            data["cpu_percent"] = psutil.cpu_percent(interval=0.5)
            # Percentage of physical RAM currently in use.
            data["memory_percent"] = psutil.virtual_memory().percent
            # os.sep is "\" or "/"; abspath turns it into the root of the
            # current drive ("C:\" on Windows, "/" elsewhere).
            data["disk_percent"] = psutil.disk_usage(os.path.abspath(os.sep)).percent
            # Sensor readings, or the text "unavailable".
            data["temperatures"] = _temperatures()
        # ---- sensitive tier -------------------------------------------------
        if tier in ("S", "BOTH"):
            # The computer's network name.
            data["hostname"] = socket.gethostname()
            # The local IP address (found without sending any traffic).
            data["ip_address"] = _ip_address()
            # The MAC address of the interface that has that IP address.
            data["mac_address"] = _mac_address(data["ip_address"])
    except psutil.AccessDenied:
        # psutil has its own "permission denied" exception. Convert it to the
        # built-in PermissionError so the server only has to catch one type.
        raise PermissionError("access denied by the operating system")
    # Return everything that was collected.
    return data
