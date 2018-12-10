from Crypto.Hash import SHA512
from Crypto.Random import random


# HASH FUNCTIONS:

# public cab = b"1"
def f(data=None):
    """
    Create a new 512 hash object with cab = b"1"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"1")
    hsh.update(data)
    return hsh


# public cab = b"2"
def g(data_1=None, data_2=None):
    """
    Create a new 512 hash object with cab = b"2"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"2")
    hsh.update(data_1)
    hsh.update(data_2)
    return hsh


# public cab = b"3"
def h0(data_1=None, data_2=None):
    """
    Create a new 512 hash object with cab = b"3"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"3")
    hsh.update(data_1)
    hsh.update(data_2)
    return hsh


# public cab = b"4"
def h1(data1=None, data2=None, data3=None, data4=None, data5=None, data6=None):
    """
    Create a new 512 hash object with cab = b"4"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"4")
    hsh.update(data1)
    hsh.update(data2)
    hsh.update(data3)
    hsh.update(data4)
    hsh.update(data5)
    hsh.update(data6)
    return hsh


# public cab = b"5"
def h2(data1=None, data2=None, data3=None, data4=None, data5=None, data6=None):
    """
    Create a new 512 hash object with cab = b"5"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"5")
    hsh.update(data1)
    hsh.update(data2)
    hsh.update(data3)
    hsh.update(data4)
    hsh.update(data5)
    hsh.update(data6)
    return hsh


def xor(data1=None, data2=None):
    """
    Does a "bitwise exclusive or".
    Each bit of the output is the same as the corresponding bit in data1 if that bit in data2 is 0,
    and it's the complement of the bit in data1 if that bit in data2 is 1.
    data1: default = None; the first bit string of the operation
    data2: default = None; the second bit string of the operation
    """

    return bytearray(a ^ b for a, b in zip(*map(bytearray, [data1, data2])))


def password_generator(num_users=1000, password_length=20):
    """
    Returns a list of [num_users] random passwords with size password_length.
    num_users: default = 1000; number of passwords that will be generated (override to generate less/more passwords)
    password_length: default = 20; override to provide smaller/larger passwords
    """

    password_list = []
    for ind in range(num_users):
        password = random.randint(0, 2 ** password_length - 1)
        password_list.append(password)
    return password_list


""" setUp() """

id_server = "server1"  # Server's identification string
