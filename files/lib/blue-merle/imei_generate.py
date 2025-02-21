#!/usr/bin/env python3
import random
import string
import argparse
from typing import Literal
import serial
import re
from enum import Enum


class Mode(Enum):
    DETERMINISTIC = 1
    RANDOM = 2
    STATIC = 3


ap = argparse.ArgumentParser()
ap.add_argument("-v", "--verbose", help="Enables verbose output",
                action="store_true")
ap.add_argument("-g", "--generate-only", help="Only generates an IMEI rather than setting it",
                   action="store_true")
modes = ap.add_mutually_exclusive_group()
modes.add_argument("-d", "--deterministic", help="Switches IMEI generation to deterministic mode", action="store_true")
modes.add_argument("-s", "--static", help="Sets user-defined IMEI",
                   action="store")
modes.add_argument("-r", "--random", help="Sets random IMEI",
                   action="store_true")


IMEI_BASE_LENGTH = 14  # without validation digit

# TAC - Type Allocation code, first 8 digits of modern IMEI, 
#       that define make and model of the device.
# More info: https://en.wikipedia.org/wiki/Type_Allocation_Code
TAC_LIST = ["35674108", "35290611", "35397710", "35323210", "35384110",
               "35982748", "35672011", "35759049", "35266891", "35407115",
               "35538025", "35480910", "35324590", "35901183", "35139729",
               "35479164"]

verbose = False
mode: Mode = Mode.RANDOM

# Serial global vars
TTY = '/dev/ttyUSB3'
BAUDRATE = 9600
TIMEOUT = 3


def get_imsi() -> bytes:
    if (verbose):
        print(f'Obtaining Serial {TTY} with timeout {TIMEOUT}...')
    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        if (verbose):
            print('Getting IMSI')
        ser.write(b'AT+CIMI\r')
        # TODO: read loop until we have 'enough' of what to expect
        output = ser.read(64)

    if (verbose):
        print(b'Output of AT+CIMI (Retrieve IMSI) command: ' + output)
        print('Output is of type: ' + str(type(output)))
    imsi_d = re.findall(b'[0-9]{15}', output)
    if (verbose):
        print("TEST: Read IMSI is", imsi_d)

    return b"".join(imsi_d)


def set_imei(imei: str) -> bool:
    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        cmd = b'AT+EGMR=1,7,\"'+imei.encode()+b'\"\r'
        ser.write(cmd)
        output = ser.read(64)

    if (verbose):
        print(cmd)
        print(b'Output of AT+EGMR (Set IMEI) command: ' + output)
        print('Output is of type: ' + str(type(output)))

    new_imei = get_imei()
    if (verbose):
        print(b"New IMEI: "+new_imei+b" Old IMEI: "+imei.encode())

    if new_imei == imei.encode():
        print("IMEI has been successfully changed.")
        return True
    else:
        print("IMEI has not been successfully changed.")
        return False


def get_imei() -> bytes:
    with serial.Serial(TTY, BAUDRATE, timeout=TIMEOUT, exclusive=True) as ser:
        ser.write(b'AT+GSN\r')
        output = ser.read(64)

    if (verbose):
        print(b'Output of AT+GSN (Retrieve IMEI) command: ' + output)
        print('Output is of type: ' + str(type(output)))
    imei_d = re.findall(b'[0-9]{15}', output)
    if (verbose):
        print("TEST: Read IMEI is", imei_d)

    return b"".join(imei_d)

def calculate_check_digit(imei_without_check):
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

    """
    sum = 0
    for i, digit in enumerate(reversed(imei_without_check)):
        n = int(digit)
        if i % 2 == 0:
            doubled = n * 2
            sum += (doubled - 9) if doubled > 9 else doubled
        else:
            sum += n
    
    return str((10 - sum % 10) % 10)


def generate_imei(tac: str, imsi_seed = None, mode: Mode = Mode.RANDOM) -> str:
    # In deterministic mode we seed the RNG with the IMSI.
    # As a consequence we will always generate the same IMEI for a given IMSI
    if (mode == Mode.DETERMINISTIC):
        if not imsi_seed:
            raise ValueError('IMSI was not provided. To generate deterministic IMEI provide IMSI to use as seed')
        random.seed(imsi_seed)

    # We choose a random prefix from the predefined list.
    # Then we fill the rest with random characters
    if (verbose):
        print(f"IMEI TAC: {tac}")
    random_part_length = IMEI_BASE_LENGTH - len(tac)
    if (verbose):
        print(f"Length of the random IMEI part: {random_part_length}")
    imei_base = tac + "".join(random.sample(string.digits, random_part_length))
    if (verbose):
        print(f"IMEI without validation digit: {imei_base}")

    imei = imei_base + calculate_check_digit(imei_base)
    if (verbose):
        print(f"Resulting IMEI: {imei}")

    return imei


def validate_imei(imei: str) -> bool:
    # before anything check if length is 14 characters
    if len(imei) != IMEI_BASE_LENGTH:
        print(f"NOT A VALID IMEI: {imei} - IMEI must be {IMEI_BASE_LENGTH} characters in length")
        return False
    imei_base, check_digit = imei[:-1], imei[-1]
    if (verbose):
        print(imei_base)
    
    check_digit_calculated = calculate_check_digit(imei_base)

    if check_digit == check_digit_calculated:
        print(f"{imei} is CORRECT")
        return True

    print(f"NOT A VALID IMEI: {imei}")
    return False


if __name__ == '__main__':
    args = ap.parse_args()
    imsi_d = None
    if args.verbose:
        verbose = args.verbose
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
            exit(-1)
    else:
        random_tac = random.choice(TAC_LIST)
        imei = generate_imei(random_tac, imsi_d, mode)
        if (verbose):
            print(f"Generated new IMEI: {imei}")
        if not args.generate_only:
            if not set_imei(imei):
                exit(-1)

    exit(0)
