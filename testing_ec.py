# from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Random import random

from fastecdsa import keys, curve
from fastecdsa.point import Point


# HASH FUNCTIONS:

# public cab = b"1"
def f(data=None):
    """
    Create a new 256 hash object with cab = b"1"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA256.new()
    hsh.update(b"1")
    hsh.update(data)
    return hsh


# public cab = b"2"
def g(data_1=None, data_2=None):
    """
    Create a new 256 hash object with cab = b"2"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA256.new()
    hsh.update(b"2")
    hsh.update(data_1)
    hsh.update(data_2)
    return hsh


# public cab = b"3"
def h0(data_1=None, data_2=None):
    """
    Create a new 256 hash object with cab = b"3"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA256.new()
    hsh.update(b"3")
    hsh.update(data_1)
    hsh.update(data_2)
    return hsh


# public cab = b"4"
def h1(data1=None, data2=None, data3=None, data4=None, data5=None, data6=None):
    """
    Create a new 256 hash object with cab = b"4"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA256.new()
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
    Create a new 256 hash object with cab = b"5"
    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA256.new()
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

#: Dictionary of Curve parameters.
#:
#: Curves will only have the following entries:
#:
#:  - name (str)    : The name of the curve
#:  - p (long)      : The value of p in the curve equation.
#:  - a (long)      : The value of a in the curve equation.
#:  - b (long)      : The value of b in the curve equation.
#:  - q (long)      : The order of the base point of the curve.
#:  - gx (long)     : The x coordinate of the base point of the curve.
#:  - gy (long)     : The y coordinate of the base point of the curve.
#:  - oid (str)     : The object identifier of the curve (optional).

# We have chosen the curve P256/secp256r1, proposed by NIST/NSA
ec = curve.P256  # E(G)

#: For this curve, the domain parameters are:
#:
#:  p: 115792089210356248762697446949407573530086143415290314195533631308867097853951
#:
#:  a: -3
#:  b: 41058363725152142129326129780047268409114441015993725554835256314039467401291
#:
#:  q: 115792089210356248762697446949407573529996955224135760342422259061068512044369
#:
#:  gx: 48439561293906451759052585252797914202762949526041747995844080717082404635286
#:  gy: 36134250956749795798585127919587881956611106672985015071877198253568414405109
#:
#:  oid: b'*\x86H\xce=\x03\x01\x07'

# So the base point is
P = Point(ec.gx, ec.gy, ec)

# And we generate a keypair (i.e. both keys) for this curve
priv_key, pub_key = keys.gen_keypair(ec)

# We need to select another point of the curve, Q
d = keys.gen_private_key(ec)
Q = priv_key * P  # P * priv_key works fine too i.e. order doesn't matter


''' PUBLIC INFORMATION: '''

#: ec                   # Elliptic curve E(G)
#: P                    # point P of E(G)
#: Q                    # another point Q of G
#: ec.p                 # group order p
#: f, g, h0, h1, h2     # hash functions


exp_pub_key = priv_key * P

print("exp_pub_key:", exp_pub_key) # good
print("pub_key:", pub_key)
print("priv_key:", priv_key, "\n")



"""The reason there are two ways to generate a keypair is that generating the public key requires
a point multiplication, which can be expensive. That means sometimes you may want to delay
generating the public key until it is actually needed."""



# generate a private key for curve P256
priv_key2 = keys.gen_private_key(ec)

# get the public key corresponding to the private key we just generated
pub_key2 = keys.get_public_key(priv_key2, ec)

print(priv_key2)
print(pub_key2)
