# import sys
import time

from Crypto.Util import number
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
#:  - name (str) :  The name of the curve
#:  - p (long)   :  The value of p in the curve equation.
#:  - a (long)   :  The value of a in the curve equation.
#:  - b (long)   :  The value of b in the curve equation.
#:  - q (long)   :  The order of the base point of the curve.
#:  - gx (long)  :  The x coordinate of the base point of the curve.
#:  - gy (long)  :  The y coordinate of the base point of the curve.
#:  - oid (str)  :  The object identifier of the curve (optional).

# We have chosen the curve P256/secp256r1, proposed by NIST/NSA
ec = curve.P256  # E(G)

#: For this curve, the domain parameters are:  sería necesario incluir esta información ????????????????????????????????
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

print("priv_key:", priv_key, "\n")

''' # Test if pub_key = priv_key * base_point
calc_pub_key = priv_key * P
print("calc_pub_key:", calc_pub_key)
print("pub_key:", pub_key, "\n") '''

# We need to select another point of the curve, Q
d = keys.gen_private_key(ec)  # generate another private key for curve P256
print("d:", d)
Q = d * P  # P * d works fine too i.e. order doesn't matter
# get the public key corresponding to the scalar (private key) we just generated
Q_2 = keys.get_public_key(d, ec)

print("Q:", Q)
print("Q_2:", Q_2)


''' PUBLIC INFORMATION: '''

#: ec                   # Elliptic curve E(G)
#: P                    # point P of E(G)
#: Q                    # another point Q of E(G)
#: ec.p                 # group order p
#: f, g, h0, h1, h2     # hash functions


# Possible values for 'number of users in the group Γ' (i.e., of passwords in the password database at the sender)
numUsersValues = [100]
# Possible values for 'number of bits of the passwords'
pwdBitLenValues = [30]


""" File with elapsed times (results) """

file = open("results_ec.txt", 'w')
file.write("number of users\tpassword bit length\telapsed time (s)\n")  # header
file.close()


for numUsers in numUsersValues:

    for pwdBitLen in pwdBitLenValues:

        print("\n==============================")
        print("Number of users: ", numUsers)
        print("Length of the key: ", pwdBitLen, "bits")
        print("==============================\n")

        # Variable with the execution times of the different executions (now empty)
        timesList = []

        ''' Let Γ be a user-group (or simply group) of n users {C1,...,Cn}.
        Each user Ci in Γ is initially provided a distinct low entropy password pwi,
        while S holds a list of these passwords. '''

        pwdList = password_generator(numUsers, pwdBitLen)

        # We run the protocol 60 times to get an average time of execution (more representative)
        n_times = 1
        for t in range(n_times):

            index = random.choice(range(len(pwdList)))  # User's password should be in Server's list
            pwdUser = pwdList[index]

            # Starting point for runtime calculation
            starting_point = time.perf_counter()

            ''' We set PWFi = F(pwi) and PWGi = G(i,pwi). '''
            PWFi = []
            PWGi = []
            i = 1
            for k in pwdList:
                PWFi.append(f(str(k).encode('utf-8')))  # PWFi = F(pwi)                                     # str in k
                PWGi.append(g(str(i).encode('utf-8'), str(k).encode('utf-8')))  # PWGi = G(i, pwi)          # str in k
                i = i + 1

            """ Phase 1 """

            ''' Ci chooses randomly and uniformly x,r ∈ Zp and computes X = x * P. '''

            X = pub_key  # The private key is chosen randomly and uniformly in Zp, so it can be x;
            # and public key = priv_key * P, so X = pub_key
            r = keys.gen_private_key(ec)  # We can generate r ∈ Zp as a private key
            print("r:", r, "\n")

            ''' Next, Ci generates a query Q(i) for the i-th data in OT protocol as
            Q(i) = r * P + G(i,pwi) * Q = r * P + PWGi * Q. '''

            # tmp_gr = pow(key.g, r, key.p)
            # gi = PWGi[index]
            # tmp_hs = number.bytes_to_long(gi.digest()) % key.p
            # tmp_hp = pow(h, tmp_hs, key.p)

            # Qi = tmp_gr * tmp_hp % key.p
            gi = PWGi[index]
            tmp_hs = number.bytes_to_long(gi.digest()) % ec.p  # módulo ????????????????????????????????????????????????
            tmp_hs_2 = number.bytes_to_long(gi.digest())  # no varía casi nunca (para casos extremos) ------------------
            print(tmp_hs)
            print(tmp_hs_2, "\n")  # -----------------------------------------------------------------------------------------

            Qi = r * P + tmp_hs * Q
            print("Qi:", Qi, "\n")

            ''' Ci sends (Γ, X, Q(i)) to S. '''
            '''
            We have all of the pieces:

                Γ -> pwdList
                X -> X
                Q(i) -> Qi
            '''

            """ Phase 2 """

            ''' S chooses randomly and uniformly y, k1,...,kn ∈ Zp and computes Y = g^y
            and αj, βj for 1 ≤ j ≤ n as follows:􏱅􏱆 􏱇 􏱈
                                                αj =Y*g^F(pwj) = Y*g^PWFj, βj = H0(Q(i)(h^PWGj)^−1)^kj ,j) ⊕ αj. '''

            y_min = keys.gen_private_key(ec)  # We can generate y ∈ Zp as a private key
            Y = y_min * P

            kn = []  # k1,...,kn ∈ Zp as private keys
            for i in range(numUsers):
                kn.append(keys.gen_private_key(ec))

            # for i in kn:
                # print(i)

            alfai = []  # αj for 1 ≤ j ≤ n
            for pwf in PWFi:
                tmp_hs = number.bytes_to_long(pwf.digest()) % ec.p  # módulo ???????????????????????????????????????????
                tmp_result = Y + tmp_hs * P
                alfai.append(tmp_result)

            for i in alfai:
                print(i)

            betai = []  # βj for 1 ≤ j ≤ n
            for n in range(numUsers):
                tmp_hs = number.bytes_to_long(PWGi[n].digest()) % ec.p  # módulo ???????????????????????????????????????
                tmp_result = kn[n] * (Qi - tmp_hs * Q)
                # print(tmp_result)
                tmp_hash = h0(str(tmp_result).encode('utf-8'), str(n + 1).encode('utf-8'))
                # print(tmp_hash.digest())

                # print(len(tmp_hash.digest()))

                # equis = alfai[n].x
                # yy = alfai[n].y

                # print(len(number.long_to_bytes(equis, len(tmp_hash.digest()))))
                # print(len(number.long_to_bytes(yy, len(tmp_hash.digest()))), "\n")

                print(len(alfai[n].__str__().encode('utf-8')))

                ''' if len(tmp_hash.digest()) != alfai[n].__sizeof__():
                    raise ValueError('XOR operands have different sizes')
                else:
                    tmp_xor = xor(tmp_hash.digest(), number.long_to_bytes(alfai[n], len(tmp_hash.digest())))
                    betai.append(tmp_xor) '''
