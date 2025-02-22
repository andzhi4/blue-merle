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


def log_exception(msg: str) -> None:
    return log_message(Level.EXCEPTION, msg)


LOGGING_LEVEL = Level.INFO
IMEI_BASE_LENGTH = 14  # without check digit
# Serial global vars
TTY = "/dev/ttyUSB3"
BAUDRATE = 9600
TIMEOUT = 3


def get_imsi() -> str:

    log_debug(f"Obtaining Serial {TTY} with timeout {TIMEOUT}...")
    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        log_debug("Getting IMSI")
        ser.write(b"AT+CIMI\r")
        # TODO: read loop until we have 'enough' of what to expect
        output = ser.read(64)

    log_debug("Output of AT+CIMI (Retrieve IMSI) command: " + output.decode())
    log_debug("Output is of type: " + str(type(output)))
    imsi_d = re.findall(b"[0-9]{15}", output)
    if not imsi_d:
        raise ValueError("Cannot retrieve IMSI")
    log_debug(f"TEST: Read IMSI is: {imsi_d}")

    return b"".join(imsi_d).decode()


def set_imei(imei: str) -> bool:

    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        cmd = b'AT+EGMR=1,7,"' + imei.encode() + b'"\r'
        ser.write(cmd)
        output = ser.read(64)

    log_debug(cmd.decode())
    log_debug("Output of AT+EGMR (Set IMEI) command: " + output.decode())
    log_debug("Output is of type: " + str(type(output)))

    # Read the new IMEI back to see if it was properly written
    new_imei = get_imei()
    log_debug("New IMEI: " + new_imei + " Old IMEI: " + imei)

    if new_imei == imei:
        log_info("IMEI has been successfully changed.")
        return True
    else:
        log_error(
            f"IMEI has not been successfully changed. Expected: {imei}, returned: {new_imei}"
        )
        raise ValueError("Error seting IMEI")


def get_imei() -> str:

    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        ser.write(b"AT+GSN\r")
        output = ser.read(64)

    log_debug("Output of AT+GSN (Retrieve IMEI) command: " + output.decode())
    log_debug("Output is of type: " + str(type(output)))
    imei = re.findall(b"[0-9]{15}", output)
    if not imei:
        raise ValueError("Cannot retrieve IMEI")
    log_debug(f"TEST: Read IMEI is {imei}")

    return b"".join(imei).decode()


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


def generate_imei(tac: str, imsi_seed: str | None = None) -> str:

    # In deterministic mode we seed the RNG with the IMSI.
    # As a consequence we will always generate the same IMEI for a given IMSI
    if imsi_seed:
        random.seed(imsi_seed)
    if len(tac) != 8 or not (tac.isdigit()):
        raise ValueError(f"Invalid TAC {tac}")
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


def get_random_tac(make: str | None = None) -> str:
    # TAC - Type Allocation code, first 8 digits of modern IMEI,
    #       that define make and model of the device.
    # More info: https://en.wikipedia.org/wiki/Type_Allocation_Code
    # fmt: off
    tac: dict[str, list[str]] = {
        "xiaomi": ["86881303"],
        "oneplus": ["86551004","86492106"],
        "samsung": ["32930400","35684610","35480910","35324590","35901183","35139729","35479164","35299018"],
        "google": ["35964309","35751110","35751310","35131133"],
        "apple": ["35325807","35299209","35103627","35676211","35925406","35438506","35326907","35674108","35290611","35397710","35323210","35384110","35982748","35672011","35759049","35266891","35407115","35538025","35302011","35614409","35660608","35638810"],
    }
    # fmt: on
    # return random make tac, or a random tac from superset of all available tacs
    if make:
        log_debug(f"getting random TAC for {make}")
        if make.lower() not in tac:
            raise KeyError(f"Unknown make. Choose from {', '.join(tac.keys())}")
        return random.choice(tac[make.lower()])
    else:
        log_debug(f"getting random TAC")
        return random.choice([v for vl in tac.values() for v in vl])


def main() -> int:
    global LOGGING_LEVEL
    mode = Mode.RANDOM

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
    ap.add_argument(
        "-m",
        "--make",
        help="Prefer TAC from specified make",
        action="store",
        default=None,
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
    if args.random:
        mode = Mode.RANDOM
    if args.static is not None:
        mode = Mode.STATIC
    try:
        match mode:
            case Mode.STATIC:
                imei = args.static
            case Mode.RANDOM:
                imei = generate_imei(get_random_tac(args.make))
            case Mode.DETERMINISTIC:
                imei = generate_imei(get_random_tac(args.make), imsi_seed=get_imsi())
            case _:
                raise TypeError("Mode not supported")

        if not validate_imei(imei):
            raise ValueError(f"Invalid IMEI Provided: {imei}")

        print(f"Generated IMEI: {imei}")
        if args.generate_only:
            log_info("User requested generate_only, not setting new IMEI")
            return 0

        result = set_imei(imei)
        if not result:
            raise RuntimeError("Unable to set new IMEI")
        return 0
    except Exception as e:
        log_exception(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
