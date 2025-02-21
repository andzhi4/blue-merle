#!/usr/bin/env python3
import argparse
import random
import re
import string
from enum import Enum

import serial


class Mode(Enum):
    DETERMINISTIC = 1
    RANDOM = 2
    STATIC = 3


# Note: GL750 python does not have logging module, so we have
# to implement a makeshift replacement for global logging control
class Level(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    EXCEPTION = 50


def log_message(level: Level, msg: str) -> None:
    global LOGGING_LEVEL
    if level.value >= LOGGING_LEVEL.value:
        print(f"{level.name}: {msg}")


# some simple wrappers for easier logging calls
def log_debug(msg: str) -> None:
    return log_message(Level.DEBUG, msg)


def log_info(msg: str) -> None:
    return log_message(Level.INFO, msg)


def log_warning(msg: str) -> None:
    return log_message(Level.WARNING, msg)


def log_error(msg: str) -> None:
    return log_message(Level.ERROR, msg)


LOGGING_LEVEL = Level.INFO
IMEI_BASE_LENGTH = 14  # without check digit
# Serial global vars
TTY = "/dev/ttyUSB3"
BAUDRATE = 9600
TIMEOUT = 3

# TAC - Type Allocation code, first 8 digits of modern IMEI,
#       that define make and model of the device.
# More info: https://en.wikipedia.org/wiki/Type_Allocation_Code
TAC_LIST = [
    "35674108",
    "35290611",
    "35397710",
    "35323210",
    "35384110",
    "35982748",
    "35672011",
    "35759049",
    "35266891",
    "35407115",
    "35538025",
    "35480910",
    "35324590",
    "35901183",
    "35139729",
    "35479164",
]


def get_imsi() -> bytes:

    log_debug(f"Obtaining Serial {TTY} with timeout {TIMEOUT}...")
    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        log_debug("Getting IMSI")
        ser.write(b"AT+CIMI\r")
        # TODO: read loop until we have 'enough' of what to expect
        output = ser.read(64)

    log_debug("Output of AT+CIMI (Retrieve IMSI) command: " + output.decode())
    log_debug("Output is of type: " + str(type(output)))
    imsi_d = re.findall(b"[0-9]{15}", output)
    log_debug(f"TEST: Read IMSI is: {imsi_d}")

    return b"".join(imsi_d)


def set_imei(imei: str) -> bool:

    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        cmd = b'AT+EGMR=1,7,"' + imei.encode() + b'"\r'
        ser.write(cmd)
        output = ser.read(64)

    log_debug(cmd.decode())
    log_debug("Output of AT+EGMR (Set IMEI) command: " + output.decode())
    log_debug("Output is of type: " + str(type(output)))

    new_imei = get_imei()
    log_debug("New IMEI: " + new_imei.decode() + " Old IMEI: " + imei)

    if new_imei == imei.encode():
        log_info("IMEI has been successfully changed.")
        return True
    else:
        log_error("IMEI has not been successfully changed.")
        return False


def get_imei() -> bytes:

    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        ser.write(b"AT+GSN\r")
        output = ser.read(64)

    log_debug("Output of AT+GSN (Retrieve IMEI) command: " + output.decode())
    log_debug("Output is of type: " + str(type(output)))
    imei_d = re.findall(b"[0-9]{15}", output)
    log_debug(f"TEST: Read IMEI is {imei_d}")

    return b"".join(imei_d)


def calculate_check_digit(imei_base: str) -> str:
    """
    Luhn algorithm (https://en.wikipedia.org/wiki/Luhn_algorithm)

    Example of a complete IMEI: 490154203237518
    It consists of:
        - TAC(8 digits: 49015420),
        - Serial Number(6 digits: 323751),
        - Check Digit (8).

    To calculate the check digit based on TAC+Serial value (IMEI base) do the following:
    1 - Double each second digit in the IMEI base: 4 18 0 2 5 8 2 0 3 4 3 14 5 2
    2 - Separate this number into single digits: 4 1 8 0 2 5 8 2 0 3 4 3 1 4 5 2
    3 - Add up all the digits: 4+1+8+0+2+5+8+2+0+3+4+3+1+4+5+2 = 52
    4 - Return integer distance to the next multiple of 10: 60 - 52 = 8

    NOTE: this function returns type str for easier concatenation of the result with the rest of an IMEI
    """

    if len(imei_base) != IMEI_BASE_LENGTH:
        msg = f"Invalid IMEI base: {imei_base}! Length mismatch"
        log_error(msg)
        raise ValueError(msg)
    sum = 0
    for i, digit in enumerate(reversed(imei_base)):
        n = int(digit)
        if i % 2 == 0:
            doubled = n * 2
            sum += (doubled - 9) if doubled > 9 else doubled
        else:
            sum += n

    return str((10 - sum % 10) % 10)


def generate_imei(tac: str, imsi_seed=None, mode: Mode = Mode.RANDOM) -> str:

    # In deterministic mode we seed the RNG with the IMSI.
    # As a consequence we will always generate the same IMEI for a given IMSI
    if mode == Mode.DETERMINISTIC:
        if not imsi_seed:
            raise ValueError(
                "IMSI was not provided. To generate deterministic IMEI provide IMSI to use as seed"
            )
        random.seed(imsi_seed)

    # We use provided TAC,
    # Then we fill the rest of the IMEI with random characters
    log_debug(f"IMEI TAC: {tac}")
    random_part_length = IMEI_BASE_LENGTH - len(tac)
    log_debug(f"Length of the random IMEI part: {random_part_length}")
    imei_base = tac + "".join(random.sample(string.digits, random_part_length))
    log_debug(f"IMEI without check digit: {imei_base}")

    imei = imei_base + calculate_check_digit(imei_base)
    log_debug(f"Resulting IMEI: {imei}")

    return imei


def validate_imei(imei: str) -> bool:

    # before anything check if length is 15 characters (8 TAC + 6 SN + 1 CHECK)
    # and it only contains digits
    if (len(imei) != IMEI_BASE_LENGTH + 1) or (not imei.isdigit()):
        log_error(f"NOT A VALID IMEI: {imei}. Must be 15 digits")
        return False
    imei_base, check_digit = imei[:-1], imei[-1]
    log_debug(f"{imei_base=}, {check_digit=}")

    check_digit_calculated = calculate_check_digit(imei_base)

    if check_digit == check_digit_calculated:
        log_info(f"{imei} is CORRECT")
        return True

    log_error(f"NOT A VALID IMEI: {imei}")
    return False


def main() -> int:
    global LOGGING_LEVEL
    mode = Mode.RANDOM
    imsi_d = None

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "-v", "--verbose", help="Enables verbose output", action="store_true"
    )
    ap.add_argument(
        "-g",
        "--generate-only",
        help="Only generates an IMEI rather than setting it",
        action="store_true",
    )
    modes = ap.add_mutually_exclusive_group()
    modes.add_argument(
        "-d",
        "--deterministic",
        help="Switches IMEI generation to deterministic mode",
        action="store_true",
    )
    modes.add_argument("-s", "--static", help="Sets user-defined IMEI", action="store")
    modes.add_argument("-r", "--random", help="Sets random IMEI", action="store_true")

    args = ap.parse_args()
    if args.verbose:
        LOGGING_LEVEL = Level.DEBUG
    if args.deterministic:
        mode = Mode.DETERMINISTIC
        imsi_d = get_imsi()
    if args.random:
        mode = Mode.RANDOM
    if args.static is not None:
        mode = Mode.STATIC
        static_imei = args.static

    if mode == Mode.STATIC:
        if validate_imei(static_imei):
            set_imei(static_imei)
        else:
            return -1
    else:
        random_tac = random.choice(TAC_LIST)
        imei = generate_imei(random_tac, imsi_d, mode)
        log_info(f"Generated new IMEI: {imei}")
        if not args.generate_only:
            if not set_imei(imei):
                return -1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
