# =============================================================================
# File:           server/consent.py
# Purpose:        The owner's consent screen. It shows who is asking and the
#                 exact data that would be sent, then lets the owner approve,
#                 deny, reduce the tier, or exclude specific fields. Nothing
#                 is transmitted until this module returns "approve".
#                 It also provides keyboard input WITH a timeout, which the
#                 normal input() function cannot do on Windows.
# Primary member: Albert (code / testing)
# =============================================================================

# queue.Queue safely passes typed lines from the keyboard thread to us.
import queue
# sys.stdin is the keyboard (standard input).
import sys
# threading runs the keyboard reader in the background.
import threading

# The tier/field definitions live in sysinfo.py so there is only one copy.
from server.sysinfo import NS_FIELDS, S_FIELDS, field_tier, tier_of

# Every line the owner types is placed in this queue by the reader thread.
_typed_lines = queue.Queue()


def _keyboard_reader():
    """Background thread: copy each typed line into the queue, forever."""
    while True:
        # Block until the owner presses Enter. Returns "" at end of input.
        line = sys.stdin.readline()
        # An empty string (not even "\n") means the keyboard was closed.
        if line == "":
            # Nothing more will ever arrive, so the thread can end.
            return
        # Store the line without its trailing newline.
        _typed_lines.put(line.rstrip("\r\n"))


def start_keyboard_thread():
    """Start the background keyboard reader. Call once when the server starts."""
    # daemon=True means this thread never keeps the program alive on exit.
    threading.Thread(target=_keyboard_reader, daemon=True).start()


def ask(prompt, timeout):
    """
    Show 'prompt' and wait up to 'timeout' seconds for the owner to type a
    line. Returns the typed text, or None if the time ran out.

    Why not input()? input() blocks forever, and the spec requires the server
    to give up after 60 seconds. One permanent reader thread plus a queue
    gives us a timeout that works the same on Windows, macOS and Linux.
    """
    # Throw away anything typed BEFORE this question appeared, so an old
    # keypress can never be mistaken for an answer to a new request.
    while True:
        try:
            # get_nowait() removes one waiting line or raises queue.Empty.
            _typed_lines.get_nowait()
        except queue.Empty:
            # The queue is empty now, so stop discarding.
            break
    # Show the question. end="" keeps the cursor on the same line and
    # flush=True makes it appear immediately.
    print(prompt, end="", flush=True)
    try:
        # Wait for the next typed line, but only for 'timeout' seconds.
        return _typed_lines.get(timeout=timeout).strip()
    except queue.Empty:
        # The owner did not answer in time.
        return None


def _show(name, requested_tier, data):
    """Print the request and exactly what would be sent."""
    # A blank line and a banner so the request stands out in the terminal.
    print()
    print("=" * 60)
    print("DSCP REQUEST")
    # Who is asking, and for which tier.
    print("  Requester : " + name)
    print("  Asked for : " + requested_tier)
    # The tier label that would be sent with the current selection.
    print("  Would send: tier " + tier_of(data) + ", exactly these values:")
    # List every field with its tier tag and its real value.
    for field, value in data.items():
        print("    [" + field_tier(field) + "] " + field + " = " + str(value))
    print("=" * 60)


def ask_consent(name, requested_tier, data, timeout):
    """
    Run the consent dialogue.

    Returns a tuple (decision, data):
      ("approve", {fields to send})  - the owner approved (maybe after trimming)
      ("deny", None)                 - the owner said no
      ("timeout", None)              - the owner did not answer in time
    """
    # Work on a copy so the caller's dictionary is never changed by us.
    data = dict(data)
    # Keep asking until the owner makes a final decision.
    while True:
        # Show the request and the current selection of data.
        _show(name, requested_tier, data)
        # Ask for a decision; each question has its own inactivity timeout.
        answer = ask("[y] approve  [n] deny  [r] reduce tier  [x] exclude fields > ", timeout)
        # None means the timeout expired with no answer.
        if answer is None:
            # Finish the prompt line so later output starts on a clean line.
            print()
            return ("timeout", None)
        # Accept upper or lower case answers.
        answer = answer.lower()

        # ---- approve ---------------------------------------------------------
        if answer in ("y", "yes"):
            # Send exactly what is currently selected.
            return ("approve", data)

        # ---- deny ------------------------------------------------------------
        if answer in ("n", "no"):
            # Nothing will be sent.
            return ("deny", None)

        # ---- reduce the tier -------------------------------------------------
        if answer == "r":
            # Reducing only makes sense while both tiers are still selected.
            if tier_of(data) != "BOTH":
                print("Only one tier is selected, so it cannot be reduced further.")
                # Go back to the top of the loop and ask again.
                continue
            # Ask which of the two tiers to keep.
            keep = ask("Keep which tier? [NS/S] > ", timeout)
            # No answer in time ends the dialogue as a timeout.
            if keep is None:
                print()
                return ("timeout", None)
            # Accept "ns" as well as "NS".
            keep = keep.upper()
            if keep == "NS":
                # Keep only the fields that belong to the non-sensitive tier.
                data = {f: v for f, v in data.items() if f in NS_FIELDS}
            elif keep == "S":
                # Keep only the fields that belong to the sensitive tier.
                data = {f: v for f, v in data.items() if f in S_FIELDS}
            else:
                # Anything else changes nothing.
                print("Not a tier. Nothing was changed.")
            # Show the (possibly reduced) selection and ask again.
            continue

        # ---- exclude specific fields ----------------------------------------
        if answer == "x":
            # Ask for the names of the fields to leave out.
            names = ask("Field names to exclude, separated by commas > ", timeout)
            # No answer in time ends the dialogue as a timeout.
            if names is None:
                print()
                return ("timeout", None)
            # Split at commas and handle each name on its own.
            for field in names.split(","):
                # Remove spaces around the name.
                field = field.strip()
                if field in data:
                    # Remove the field so it will not be sent.
                    del data[field]
                elif field != "":
                    # Tell the owner about names that did not match anything.
                    print("No such field: " + field)
            # If every field was removed there is nothing left to approve.
            if len(data) == 0:
                print("Every field was excluded, so the request is denied.")
                return ("deny", None)
            # Show the trimmed selection and ask again.
            continue

        # ---- anything else ---------------------------------------------------
        # Unknown input never approves anything; just ask again.
        print("Please type y, n, r or x.")
