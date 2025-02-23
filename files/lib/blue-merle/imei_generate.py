#!/usr/bin/env python3
import argparse
import random
import re
import string
from enum import Enum
from typing import Dict, Union

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


class IMEI:
    __slots__ = ("__imei",)  # Only these attributes can exist
    IMEI_LENGTH: int = 15
    TAC_LENGTH: int = 8

    def __init__(self, val: str | int | bytes):
        self.__imei: bytes = None  # Double underscore for name mangling
        self.imei = val  # This will use the setter

    @property
    def imei(self) -> bytes:
        return self.__imei

    @imei.setter
    def imei(self, val: str | int | bytes):
        value = val if isinstance(val, bytes) else str(val).encode()
        if not self.validate(value):
            raise ValueError(f"Invalid IMEI provided: {value}")
        else:
            self.__imei = value

    @classmethod
    def validate(cls, imei: str | int | bytes):
        imei = imei.decode() if isinstance(imei, bytes) else str(imei)
        if (len(imei) != cls.IMEI_LENGTH) or (not imei.isdigit()):
            log_error(f"NOT A VALID IMEI: {imei}. Must be {cls.IMEI_LENGTH} digits")
            return False
        imei_base, check_digit = imei[:-1], imei[-1]
        log_debug(f"{imei_base=}, {check_digit=}")

        check_digit_calculated = cls.calculate_check_digit(imei_base)

        if check_digit == check_digit_calculated:
            log_debug(f"{imei} is CORRECT")
            return True

        log_error(f"NOT A VALID IMEI: {imei}")
        return False

    @classmethod
    def calculate_check_digit(csl, imei_base: str) -> str:
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

        if len(imei_base) != csl.IMEI_LENGTH - 1:
            msg = f"Invalid IMEI base: {imei_base}, Length mismatch. Expected: {csl.IMEI_LENGTH - 1}, got {len(imei_base)}"
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

    @classmethod
    def generate(
        cls,
        tac: Union[str, int, bytes, None] = None,
        imsi_seed: Union[str, int, bytes, None] = None,
    ) -> "IMEI":

        # In deterministic mode we seed the RNG with the IMSI.
        # As a consequence we will always generate the same IMEI for a given IMSI
        if imsi_seed:
            random.seed(imsi_seed)

        if tac:
            tac: str = tac.decode() if isinstance(tac, bytes) else str(tac)
            if len(tac) != 8 or not (tac.isdigit()):
                raise ValueError(f"Invalid TAC {tac}")
        else:
            # NOTE: make sure it makes sense to generate completely random IMEIs
            tac: str = "".join(random.sample(string.digits, cls.TAC_LENGTH))
            log_debug(f"Generated TAC: {tac}")

        # We use provided TAC,
        # Then we fill the rest of the IMEI with random characters
        log_debug(f"IMEI TAC: {tac}")
        random_part_length = cls.IMEI_LENGTH - cls.TAC_LENGTH - 1
        imei_base = tac + "".join(random.sample(string.digits, random_part_length))

        imei = IMEI(imei_base + cls.calculate_check_digit(imei_base))
        log_debug(f"Resulting IMEI: {imei}")

        return imei

    def get_bytes(self) -> bytes:
        return self.imei

    def __eq__(self, other: "IMEI"):
        if isinstance(other, IMEI):
            return self.imei == other.imei
        raise TypeError(f"Cannot compare instance of IMEI with {type(other)}")

    def __str__(self) -> str:
        return self.imei.decode()

    def __repr__(self):
        return f"IMEI: {self.__str__()}"


class SerialOps:
    """Generic class to handle AT commands"""

    Config = Dict[
        str, Union[str, int, bool]
    ]  # Mudi has Python 3.10, thus no "type" keyword

    _default_config: Config = {
        "port": "/dev/ttyUSB3",
        "baudrate": 9600,
        "timeout": 3,
        "exclusive": True,
    }

    def __init__(self, config: Config = None):
        self.config = {**self._default_config, **(config or {})}
        log_debug(f"")

    def issue_at_command(self, command: bytes) -> bytes:
        "Issue an AT command using instance config"
        log_debug(f"Issuing {command.decode} command...")
        with serial.Serial(**self.config) as ser:
            ser.write(command)
            # TODO: read loop until we have 'enough' of what to expect
            output = ser.read(64)
        return output


class ModemOps(SerialOps):
    "Collection of functions that perform AT commands on Mudi modem"

    def __init__(self, config: SerialOps.Config = None):
        super().__init__(config)

    def get_imsi(self) -> str:
        output = self.issue_at_command(b"AT+CIMI\r")
        log_debug("Output of AT+CIMI (Retrieve IMSI) command: " + output.decode())
        imsi_d = re.findall(b"[0-9]{15}", output)
        if not imsi_d:
            raise ValueError("Cannot retrieve IMSI")
        log_debug(f"TEST: Read IMSI is: {imsi_d}")

        return b"".join(imsi_d).decode()

    def set_imei(self, imei: IMEI) -> bool:
        cmd = b'AT+EGMR=1,7,"' + imei.get_bytes() + b'"\r'
        output = self.issue_at_command(cmd)
        log_debug(f"command: {cmd.decode()}, output: {output.decode()}")

        # Read the new IMEI back to see if it was properly written
        new_imei = self.get_imei()
        log_debug(f"New IMEI: {new_imei}, Old IMEI: {imei}")

        if new_imei == imei:
            log_debug("IMEI has been successfully changed.")
            return True
        else:
            msg = f"Error changing IMEI. Expected: {imei}, returned: {new_imei}"
            log_error(msg)
            raise ValueError(msg)

    def get_imei(self) -> IMEI:
        cmd = b"AT+GSN\r"
        output = self.issue_at_command(cmd)
        log_debug(f"command: {cmd.decode()}, output: {output.decode()}")
        imei = re.findall(b"[0-9]{15}", output)
        if not imei:
            raise ValueError("Cannot retrieve IMEI")
        log_debug(f"TEST: Read IMEI is {imei}")

        return IMEI(b"".join(imei))


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
        "apple": ["35325807","35299209","35103627","35676211","35925406","35438506","35326907","35674108","35290611","35397710","35323210","35384110","35982748","35672011","35759049","35266891","35407115","35538025","35302011","35614409","35660608","35638810", "35388419"],
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
    modem = ModemOps()

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
                imei = IMEI(args.static)
            case Mode.RANDOM:
                imei = IMEI.generate(get_random_tac(args.make))
            case Mode.DETERMINISTIC:
                imei = IMEI.generate(
                    get_random_tac(args.make), imsi_seed=modem.get_imsi()
                )
            case _:
                raise TypeError("Mode not supported")

        print(f"Generated IMEI: {imei}")
        if args.generate_only:
            log_info("User requested generate_only, not setting new IMEI")
            return 0

        result = mode.set_imei(imei)
        if not result:
            raise RuntimeError("Unable to set new IMEI")
        return 0
    except Exception as e:
        log_exception(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
