import sys
import time

from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Util import number
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


def str_to_point(string="", curv=curve.P256):
    """
    Returns a Point of the curve 'curv' from the point-formatted string 'string'.
    string: default = ""; the string that is going to be turned into a Point (it must be point-formatted,
                        i.e. it has had to be created from a point using 'str', 'unicode' or 'repr' functions)
    curv: default = curve.P256; the default curve where the point is going to be
    """

    parts = string.split("\n")
    x = int(parts[0].split(" ")[1], 16)  # The x coordinate of the base point of the curve (int)
    y = int(parts[1].split(" ")[1], 16)  # The y coordinate of the base point of the curve (int)
    # Creation of the point
    return Point(x, y, curv)


""" setUp() """

id_server = "server1"  # Server's identification string

#: Dictionary of Curve parameters.
#:
#: Curves will have the following entries:
#:
#:  - name (str) :  The name of the curve.
#:  - p (long)   :  The value of p in the curve equation.
#:  - a (long)   :  The value of a in the curve equation.
#:  - b (long)   :  The value of b in the curve equation.
#:  - q (long)   :  The order of the base point of the curve.
#:  - gx (long)  :  The x coordinate of the base point of the curve.
#:  - gy (long)  :  The y coordinate of the base point of the curve.
#:  - oid (str)  :  The object identifier of the curve (optional).

# We have chosen the curve P256/secp256r1, proposed by NIST/NSA
ec = curve.P256  # E(G)

#: For this curve, the domain parameters are:  # sería necesario incluir esta información ???????????????????????????????
#:
#:  p: 115792089210356248762697446949407573530086143415290314195533631308867097853951
#:  a: -3
#:  b: 41058363725152142129326129780047268409114441015993725554835256314039467401291
#:  q: 115792089210356248762697446949407573529996955224135760342422259061068512044369
#:  gx: 48439561293906451759052585252797914202762949526041747995844080717082404635286
#:  gy: 36134250956749795798585127919587881956611106672985015071877198253568414405109
#:  oid: b'*\x86H\xce=\x03\x01\x07'
#:
#:
#: Visit http://www.secg.org/sec2-v2.pdf to check this information is correct.

# Therefore the base point is:
P = Point(ec.gx, ec.gy, ec)


# We generate a keypair (i.e. both keys) for this curve
priv_key, pub_key = keys.gen_keypair(ec)

# We need to select another point of the curve, Q
d = keys.gen_private_key(ec)  # generate another private key (scalar) for curve P256
Q = d * P
'''
P * d works fine too, i.e. order doesn't matter. Also keys.get_public_key(d, ec) works fine,
i.e. getting the public key corresponding to the private key we just generated
'''


''' PUBLIC INFORMATION: '''

#: ec                   # Elliptic curve E(G); the group
#: P                    # point P of E(G)
#: Q                    # another point Q of E(G)
#: ec.p                 # group order p
#: f, g, h0, h1, h2     # hash functions


# Possible values for 'number of users in the group Γ' (i.e., of passwords in the password database at the sender)
numUsersValues = [1000, 5000, 10000, 15000, 20000]
# Possible values for 'number of bits of the passwords'
pwdBitLenValues = list(range(20, 51, 10))


""" File with elapsed times (results_ec) """

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
        n_times = 60
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

            '''
            The private key is chosen randomly and uniformly in Zp, so it can be x;
            and public key is priv_key * P, so X = pub_key
            '''
            X = pub_key
            r = keys.gen_private_key(ec)  # We can generate r ∈ Zp as a private key

            ''' Next, Ci generates a query Q(i) for the i-th data in OT protocol as
            Q(i) = r * P + G(i,pwi) * Q = r * P + PWGi * Q. '''

            gi = PWGi[index]
            tmp_hs = number.bytes_to_long(gi.digest()) % ec.p  # módulo? [no varía casi nunca (para casos extremos)] ????
            Qi = r * P + tmp_hs * Q

            ''' Ci sends (Γ, X, Q(i)) to S. '''
            '''
            We have all of the pieces:

                Γ -> pwdList
                X -> X
                Q(i) -> Qi
            '''

            """ Phase 2 """

            ''' S chooses randomly and uniformly y, k1,...,kn ∈ Zp and computes Y = y * P
            and αj, βj for 1 ≤ j ≤ n as follows:􏱅􏱆 􏱇 􏱈
                                            αj =Y*g^F(pwj) = Y + PWFj * P, βj = H0(kj * (Q(i) - PWGj * Q), j) ⊕ αj. '''

            y_min = keys.gen_private_key(ec)  # We can generate y ∈ Zp as a private key
            Y = y_min * P

            kn = []  # k1,...,kn ∈ Zp as private keys
            for i in range(numUsers):
                kn.append(keys.gen_private_key(ec))

            alfai = []  # αj for 1 ≤ j ≤ n
            for pwf in PWFi:
                tmp_hs = number.bytes_to_long(pwf.digest()) % ec.p  # módulo ????????????????????????????????????????????
                tmp_result = Y + tmp_hs * P
                alfai.append(tmp_result)

            betai = []  # βj for 1 ≤ j ≤ n
            for n in range(numUsers):
                tmp_hs = number.bytes_to_long(PWGi[n].digest()) % ec.p  # módulo ????????????????????????????????????????
                tmp_result = kn[n] * (Qi - tmp_hs * Q)
                tmp_hash = h0(str(tmp_result).encode('utf-8'), str(n + 1).encode('utf-8'))

                '''
                In order to do the xor operation, we turn the Point alfai[n] into bytes
                (First: Point -> string; Second: string -> bytes)
                '''
                bytes_alfai = str(alfai[n]).encode('utf-8')  # Bytes

                '''
                Then, we turn the result of the hash operation into bytes.
                We use the 'long_to_bytes' function in order to achieve the same byte-length in both operands of the xor
                '''
                tmp_hash_completed = number.long_to_bytes(number.bytes_to_long(tmp_hash.digest()), len(bytes_alfai))
                # The second parameter causes the front of the byte string to be padded with
                # binary zeros so that the length is a multiple of 'len(bytes_alfai)'

                tmp_xor = xor(tmp_hash_completed, bytes_alfai)
                betai.append(tmp_xor)

            ''' Let A(Q(i)) = (β1,...,βn,k1 * P,...,kn * P), and let KS = y * X. '''

            Pkn = []  # We already have β1,...,βn; but we have to calculate k1 * P,...,kn * P
            for scl in kn:
                Pk = scl * P
                '''
                We insert the Pk points bytearray-shaped to make the next concatenation
                '''
                Pkn.append(bytearray(str(Pk).encode('utf-8')))

            AQi = betai + Pkn  # AQi will be the concatenation of betai and Pkn lists

            KS = y_min * X

            ''' S computes the authenticator AuthS and the session key skS as follows
            AuthS = H2(Γ,S,X,A(Q(i)),Y,KS) and skS = H1(Γ,S,X,A(Q(i)),Y,KS). '''

            AuthS = h2(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
                       str(AQi).encode('utf-8'), str(Y).encode('utf-8'), str(KS).encode('utf-8'))

            skS = h1(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
                     str(AQi).encode('utf-8'), str(Y).encode('utf-8'), str(KS).encode('utf-8'))

            ''' S sends (S,A(Q(i)),AuthS) to Ci. '''
            '''
            We have all of the pieces:

                S -> id_server
                A(Q(i)) -> AQi
                AuthS -> AuthS
            '''

            """ Phase 3 """

            ''' Ci extracts αi from A(Q(i)) as αi = βi ⊕ H0(r * (ki * P), i). '''

            # βi will be in [index] position of A(Q(i)) and ki * P will be in [numUsers+index] position
            beta = AQi[index]

            tmp_Pki = AQi[numUsers + index]
            # Pki is a bytearray-shaped Point. First, we have to turn this bytearray into a string
            str_Pki = bytes(tmp_Pki).decode()
            # And then, we turn the string into a Point using the 'str_to_point' function previously implemented
            Pki = str_to_point(str_Pki)

            tmp_mul = r * Pki  # r generated before
            tmp_hs = h0(str(tmp_mul).encode('utf-8'), str(index + 1).encode('utf-8'))

            '''
            As before, we turn the result of the hash operation into bytes.
            We use the 'long_to_bytes' function in order to achieve the same byte-length in both operands of the xor
            '''
            tmp_hash_completed = number.long_to_bytes(number.bytes_to_long(tmp_hs.digest()), len(beta))
            # The second parameter causes the front of the byte string to be padded
            # with binary zeros so that the length is a multiple of 'len(beta)'

            str_alfa = bytes(xor(beta, tmp_hash_completed)).decode()

            # As alfa is a Point, we turn the string into a Point using the 'str_to_point' function
            alfa = str_to_point(str_alfa)

            ''' Ci computes Y = αi - PWFi * P, KC = x * Y. '''

            tmp_fi = PWFi[index]
            tmp_hs = number.bytes_to_long(tmp_fi.digest()) % ec.p  # módulo ?????????????????????????????????????????????
            Y_c = alfa - tmp_hs * P

            KC = priv_key * Y  # KC = x * Y

            ''' Ci computes AuthC = H2(Γ,S,X,A(Q(i)),Y,KC) and checks whether AuthS =? AuthC '''

            AuthC = h2(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
                       str(AQi).encode('utf-8'), str(Y_c).encode('utf-8'), str(KC).encode('utf-8'))

            ''' If AuthS is valid, Ci accepts and computes the session-key skC as
            skC = H1(Γ,S,X,A(Q(i)),Y,KC). '''
            '''If AuthS is invalid then Ci aborts the protocol. '''

            if AuthC.hexdigest() == AuthS.hexdigest():  # Accept
                skC = h1(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
                         str(AQi).encode('utf-8'), str(Y_c).encode('utf-8'), str(KC).encode('utf-8'))

                print(t + 1, "... Successful")

            else:
                print("Incorrect Authentication. Aborting protocol...")
                sys.exit(1)

            # End point for runtime calculation
            end_point = time.perf_counter()

            # Elapsed time
            elapsed_time = end_point - starting_point  # In seconds
            timesList.append(elapsed_time)

        """ Calculating the average of the times """

        average = sum(timesList) / len(timesList)

        print("\nElapsed time (average): ", average, "s\n")

        """ Saving time results in a file """

        file = open("results_ec.txt", 'a')
        file.write(str(numUsers) + "\t" + str(pwdBitLen) + "\t" + str(average).replace(".", ",") + "\n")
        file.close()

    file = open("results_ec.txt", 'a')
    file.write("\n")
    file.close()
