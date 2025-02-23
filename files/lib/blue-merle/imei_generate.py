#!/usr/bin/env python3
import argparse
import random
import re
import string
from enum import Enum
from typing import Dict, TypedDict, Union

import serial


# Note: GL750 python does not have logging module, so we have
# to implement a makeshift replacement for global logging control
class Level(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    EXCEPTION = 50


class Logger:
    def __init__(self, level: Level = Level.INFO):
        self._level = level

    @property
    def level(self) -> Level:
        return self._level

    @level.setter
    def level(self, value: Level) -> None:
        if not isinstance(value, Level):
            raise ValueError("Level must be a Level enum value")
        self._level = value

    def _log(self, level: Level, msg: str, caller: str | None = None) -> None:
        if level.value >= self._level.value:
            print(f"{level.name} [{caller or ''}]: {msg}")

    # dict that maps class attributes to logging levels
    _level_logger: dict[str, Level] = {level.name.lower(): level for level in Level}

    def __getattr__(self, name):
        """
        This allows us to call logger.debug(), logger.info() without
        hardcoding a function for every available level.
        """
        if name in self._level_logger:
            return lambda msg, caller=None: self._log(
                level=self._level_logger[name], msg=msg, caller=caller
            )

        raise AttributeError(f"'Logger' object has no attribute '{name}'")


# global logger instance
logger = Logger()


class IMEI:
    __slots__ = ("__imei",)  # Only these attributes can exist
    IMEI_LENGTH: int = 15
    TAC_LENGTH: int = 8

    def __init__(self, val: str | int | bytes):
        self.__imei: bytes  # Double underscore for name mangling
        self.imei = val  # type: ignore

    @property
    def imei(self) -> bytes:
        return self.__imei

    @imei.setter
    def imei(self, val: str | int | bytes):
        value = val if isinstance(val, bytes) else str(val).encode()
        if not self.validate(value):
            raise ValueError(f"Invalid IMEI provided: {value.decode()}")
        else:
            self.__imei = value

    @classmethod
    def validate(cls, imei: str | int | bytes):
        caller = "validate"
        imei = imei.decode() if isinstance(imei, bytes) else str(imei)
        if (len(imei) != cls.IMEI_LENGTH) or (not imei.isdigit()):
            logger.error(
                f"Invalid IMEI: {imei}. Must be {cls.IMEI_LENGTH} digits", caller=caller
            )
            return False
        imei_base, check_digit = imei[:-1], imei[-1]
        logger.debug(f"{imei_base=}, {check_digit=}", caller=caller)

        check_digit_calculated = cls.calculate_check_digit(imei_base)

        if check_digit == check_digit_calculated:
            logger.debug(f"{imei} is correct", caller=caller)
            return True

        logger.error(f"Invalid IMEI: {imei}")
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
            logger.error(msg)
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
        caller = "generate"
        # In deterministic mode we seed the RNG with the IMSI.
        # As a consequence we will always generate the same IMEI for a given IMSI
        if imsi_seed:
            random.seed(imsi_seed)

        if tac:
            tac_str = tac_str.decode() if isinstance(tac, bytes) else str(tac)  # type: ignore
            if len(tac_str) != 8 or not (tac_str.isdigit()):
                raise ValueError(f"Invalid TAC {tac_str}")
        else:
            # NOTE: make sure it makes sense to generate completely random IMEIs
            tac_str = "".join(random.sample(string.digits, cls.TAC_LENGTH))

        # We use provided TAC,
        # Then we fill the rest of the IMEI with random characters
        logger.debug(f"IMEI TAC: {tac_str}", caller=caller)
        random_part_length = cls.IMEI_LENGTH - cls.TAC_LENGTH - 1
        imei_base = tac_str + "".join(random.sample(string.digits, random_part_length))

        imei = IMEI(imei_base + cls.calculate_check_digit(imei_base))
        logger.debug(f"generated IMEI: {imei}", caller=caller)

        return imei

    def get_bytes(self) -> bytes:
        return self.imei

    def __eq__(self, other: object):
        if not isinstance(other, IMEI):
            return NotImplemented
        return self.imei == other.imei

    def __str__(self) -> str:
        return self.imei.decode()

    def __repr__(self):
        return f"IMEI: {self.__str__()}"


class SerialOps:
    """Generic class to handle AT commands"""

    class Config(TypedDict, total=False):
        port: Union[str, None]
        baudrate: int
        bytesize: int
        parity: str
        stopbits: float
        timeout: Union[float, None]
        xonxoff: bool
        rtscts: bool
        write_timeout: Union[float, None]
        dsrdtr: bool
        inter_byte_timeout: Union[float, None]
        exclusive: Union[bool, None]

    _default_config: Config = {
        "port": "/dev/ttyUSB3",
        "baudrate": 9600,
        "timeout": 3,
        "exclusive": True,
    }

    def __init__(self, config: Config = {}):
        self.config = {**self._default_config, **(config or {})}

    def issue_at_command(self, command: bytes) -> bytes:
        "Issue an AT command using instance config"
        caller = "issue_AT_command"
        logger.debug(f"issuing command: {command.decode()}", caller=caller)
        with serial.Serial(**self.config) as ser:  # type: ignore
            ser.write(command)
            # TODO: read loop until we have 'enough' of what to expect
            output = ser.read(64)
            logger.debug(f"result: {output.decode().strip()}", caller=caller)
        return output


class ModemOps(SerialOps):
    "Collection of functions that perform AT commands on Mudi modem"

    def __init__(self, config: SerialOps.Config = {}):
        super().__init__(config)

    def get_imsi(self) -> str:
        caller = "get_imsi"
        cmd = b"AT+CIMI\r"
        output = self.issue_at_command(cmd)
        imsi_d = re.findall(b"[0-9]{15}", output)
        if not imsi_d:
            raise ValueError("Cannot retrieve IMSI")
        logger.debug(f"retrieved IMSI: {imsi_d}", caller=caller)

        return b"".join(imsi_d).decode()

    def set_imei(self, imei: IMEI) -> bool:
        caller = "set_imei"

        initial_imei = self.get_imei()
        logger.info(f"Current modem IMEI: {initial_imei}", caller=caller)
        set_imei_cmd = b'AT+EGMR=1,7,"' + imei.get_bytes() + b'"\r'
        _ = self.issue_at_command(set_imei_cmd)

        # Read the new IMEI back to see if it was properly written
        new_imei = self.get_imei()
        logger.debug(f"New IMEI: {new_imei}, Old IMEI: {initial_imei}", caller=caller)

        if new_imei == imei and new_imei != initial_imei:
            logger.info(
                f"IMEI has been successfully changed: {initial_imei} -> {new_imei}",
                caller=caller,
            )
            return True
        else:
            msg = f"Error changing IMEI. Current modem IMEI: {new_imei}"
            logger.error(msg, caller=caller)
            raise ValueError(msg)

    def get_imei(self) -> IMEI:
        caller = "get_imei"
        cmd = b"AT+GSN\r"
        output = self.issue_at_command(cmd)
        imei = re.findall(b"[0-9]{15}", output)
        if not imei:
            raise ValueError("Cannot retrieve IMEI")
        logger.debug(f"retrieved IMEI is {imei}", caller=caller)

        return IMEI(b"".join(imei))


def get_random_tac(make: str | None = None) -> str:
    # TAC - Type Allocation code, first 8 digits of modern IMEI,
    #       that define make and model of the device.
    # More info: https://en.wikipedia.org/wiki/Type_Allocation_Code
    # fmt: off
    caller = 'get_random_tac'
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
        logger.debug(f"getting random TAC for {make}", caller=caller)
        if make.lower() not in tac:
            raise KeyError(f"Unknown make. Choose from {', '.join(tac.keys())}")
        return random.choice(tac[make.lower()])
    else:
        logger.debug(f"getting random TAC", caller=caller)
        return random.choice([v for vl in tac.values() for v in vl])


class Mode(Enum):
    DETERMINISTIC = 1
    RANDOM = 2
    STATIC = 3


def main() -> int:
    global logger
    mode = Mode.RANDOM
    modem = ModemOps()
    caller = "main"

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
        logger.level = Level.DEBUG
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

        logger.info(f"Generated IMEI: {imei}", caller=caller)
        if args.generate_only:
            logger.info("Dry run, not setting new IMEI", caller=caller)
            return 0

        result = modem.set_imei(imei)
        if not result:
            raise RuntimeError("Unable to set new IMEI")
        return 0
    except Exception as e:
        logger.exception(str(e), caller=caller)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
