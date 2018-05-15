import string
import time

from Crypto.Hash import SHA256
from Crypto.Hash import SHA512

from Crypto.Util import number
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Hash import SHA

''' Number of users of the user group Γ '''
n_users = 10


# def hash_n(cab=b"cab1", data=None):
#
#     """
#     Create a new hash object.
#
#     cab: default = b"cab1"; the different prefixes of hash functions
#                             we will use:
#                             - b"cab1" for the first hash function (F)
#                             - b"cab2" for the second hash function (G)
#                             - b"cab3" for the third hash function (H1)
#                             - b"cab4" for the fourth hash function (H2)
#                             - b"cab5" for the fifth hash function (H3)
#     data: default = None; the very first chunk of the message to hash.
#     """
#
#     h1 = SHA256.new()
#     h1.update(cab)
#     h2 = SHA256.new()
#     h2.update(data)
#     return h1.hexdigest() + h2.hexdigest()

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
def h1(data=None):
    """
    Create a new 512 hash object with cab = b"3"

    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"3")
    hsh.update(data)
    return hsh


# public cab = b"4"
def h2(data=None):
    """
    Create a new 512 hash object with cab = b"4"

    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"4")
    hsh.update(data)
    return hsh


# public cab = b"5"
def h3(data=None):
    """
    Create a new 512 hash object with cab = b"5"

    data: default = None; the very first chunk of the message to hash.
    """

    hsh = SHA512.new()
    hsh.update(b"5")
    hsh.update(data)
    return hsh


def password_generator(size=8, chars=string.ascii_letters + string.digits + string.punctuation):
    # !@#$%^&*()?
    """
    Returns a string of random characters, useful in generating temporary
    passwords for automated password resets.

    size: default = 8; override to provide smaller/larger passwords
    chars: default = A-Za-z0-9!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~; override to provide more/less diversity

    Source: http://stackoverflow.com/a/2257449
    """
    return ''.join(random.choice(chars) for _ in range(size))


# print(password_generator(int(input('How many characters in your password?'))))

""" Let Γ be a user-group (or simply group) of n users {C1, . . . , Cn}.
Each user Ci in Γ is initially provided a distinct low entropy password pwi,
while S holds a list of these passwords. """
list_pwd = []
for i in range(0, n_users):
    list_pwd.append(password_generator(8))

# print(list_pwd)

# User's password should be in Server's list
index = random.choice(range(1, n_users))
# print(index+1)
usr_pwd = list_pwd[index]
# print(usr_pwd)

# Hash tests
hash1 = f(b"hola")
print(hash1.hexdigest())

hash2 = f(b"adios")
print(hash2.hexdigest())


# PWFi and PWGi
PWFi = []
PWGi = []
i = 1
for k in list_pwd:
    # PWFi = F(pwi)
    PWFi.append(f(k.encode('utf-8')))
    # PWGi = G(i, pwi)
    PWGi.append(g(str(i).encode('utf-8'), k.encode('utf-8')))
    i = i+1

''' print("PWGi:")
for elem in PWGi:
    print(elem.hexdigest()) '''


""" To measure times """
starting_point = time.time()
# print(starting_point)


#: Dictionary of ElGamal parameters.
#:
#: A public key will only have the following entries:
#:
#:  - **y**, the public key.
#:  - **g**, the generator.
#:  - **p**, the modulus.
#:
#: A private key will also have:
#:
#:  - **x**, the private key.

key = ElGamal.generate(512, Random.new().read)

# Tests
print("Modulus:", key.p)
print("Order of the group:", key.p - 1)

print("Generator:", key.g)

print("Public key:", key.y)
print("Size:", key.y.bit_length())

print("Private key:", key.x)
print("Size:", key.x.bit_length())


elapsed_time = time.time() - starting_point
print(elapsed_time, "s")  # seconds

elapsed_time_ms = (time.time() - starting_point) * 1000
print(elapsed_time_ms, "ms")  # milliseconds


""" Phase 1 """
''' Ci chooses randomly and uniformly x,r ∈ Zp and computes X = g^x. '''
# The attribute y in key --the public key-- is X = g^x
X = key.x
# We use ElGamal's implementation so we can generate r ∈ Zp
r = number.getRandomRange(2, key.p-1, Random.new().read)

''' Next, Ci generates a query Q(i) for the i-th data in OT protocol as
# Q(i) = g^r h^G(i,pwi) = g^r h^PWGi. '''
gr = pow(key.g, r, key.p)

# We need to create another generator, h

# See Algorithm 4.80 in Handbook of Applied Cryptography
# Note that the order of the group is n=p-1=2q, where q is prime
while 1:
    # We must avoid h=2 because of Bleichenbacher's attack described
    # in "Generating ElGamal signatures without knowning the secret key",
    # 1996
    #
    h = number.getRandomRange(3, key.p, Random.new().read)
    # q = (key.p-1)*(number.inverse(2, key.p))
    q = (key.p - 1)//2
    safe = 1
    if pow(h, 2, key.p) == 1:
        safe = 0
    if safe and pow(h, q, key.p) == 1:
        safe = 0
    # Discard h if it divides p-1 because of the attack described
    # in Note 11.67 (iii) in HAC
    if safe and divmod(key.p-1, h)[1] == 0:
        safe = 0
    # h^{-1} must not divide p-1 because of Khadir's attack
    # described in "Conditions of the generator for forging ElGamal
    # signature", 2011
    ginv = number.inverse(h, key.p)
    if safe and divmod(key.p-1, ginv)[1] == 0:
        safe = 0
    if safe:
        break

# print(h)

gi = PWGi[index]
# print(gi.hexdigest())

hp = pow(h, number.bytes_to_long(gi.digest()), key.p)

Qi = gr*hp % key.p
print(Qi)

"""" Ci sends (Γ, X, Q(i)) to S. """
# We have all of the pieces





# from Crypto.Cipher import AES
#
# obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
# message = "The answer is no"
# ciphertext = obj.encrypt(message)
# print(ciphertext)
#
# obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
# print(obj2.decrypt(ciphertext))
