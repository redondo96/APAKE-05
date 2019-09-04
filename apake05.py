import sys
import time

from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto.Util import number


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

# We need to select another generator, h
q = (key.p - 1) // 2  # View ElGamal's implementation to find the value of q
h = pow(key.g, number.getRandomRange(1, q, Random.new().read), key.p)


''' PUBLIC INFORMATION: '''

#: Group G
#: key.g                # generator g of G
#: h                    # generator h of G
#: key.p                # group order p
#: f, g, h0, h1, h2     # hash functions


# Possible values for 'number of users in the group Γ' (i.e., of passwords in the password database at the sender)
numUsersValues = [1000]  # , 5000, 10000, 15000, 20000]
# Possible values for 'number of bits of the passwords'
pwdBitLenValues = [32, 64, 128, 256, 512]


""" File with elapsed times (results) """

file = open("results.txt", 'w')
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

        # We run the protocol 60 times to get an average time of execution (more representative)
        n_times = 60
        for t in range(n_times):

            ''' Let Γ be a user-group (or simply group) of n users {C1,...,Cn}.
            Each user Ci in Γ is initially provided a distinct low entropy password pwi,
            while S holds a list of these passwords. '''

            pwdList = password_generator(numUsers, pwdBitLen)

            index = random.choice(range(len(pwdList)))  # User's password should be in Server's list
            pwdUser = pwdList[index]

            ''' We set PWFi = F(pwi) and PWGi = G(i,pwi). '''
            PWFi = []
            PWGi = []
            i = 1
            for k in pwdList:
                PWFi.append(f(str(k).encode('utf-8')))  # PWFi = F(pwi)                                     # str in k
                PWGi.append(g(str(i).encode('utf-8'), str(k).encode('utf-8')))  # PWGi = G(i, pwi)          # str in k
                i = i + 1

            # Starting point for runtime calculation
            starting_point = time.perf_counter()

            """ Phase 1 """

            ''' Ci chooses randomly and uniformly x,r ∈ Zp and computes X = g^x. '''

            X = key.y  # The public key of ElGamal key is y = g^x, so X = y
            r = number.getRandomRange(2, key.p - 1, Random.new().read)  # We generate r ∈ Zp

            ''' Next, Ci generates a query Q(i) for the i-th data in OT protocol as
            Q(i) = g^r h^G(i,pwi) = g^r h^PWGi. '''

            Qi = (pow(key.g, r, key.p)) * (pow(h, (number.bytes_to_long(PWGi[index].digest()) % key.p), key.p)) % key.p

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
                                                αj =Y*g^F(pwj) = Y*g^PWFj, βj = H0((Q(i)(h^PWGj)^−1)^kj, j) ⊕ αj. '''

            y_min = number.getRandomRange(2, key.p - 1, Random.new().read)  # We generate y ∈ Zp
            Y = pow(key.g, y_min, key.p)

            kn = []  # k1,...,kn ∈ Zp
            for i in range(numUsers):
                kn.append(number.getRandomRange(2, key.p - 1, Random.new().read))

            alfai = []  # αj for 1 ≤ j ≤ n
            for pwf in PWFi:
                alfai.append(Y * (pow(key.g, (number.bytes_to_long(pwf.digest()) % key.p), key.p)) % key.p)

            betai = []  # βj for 1 ≤ j ≤ n
            for n in range(numUsers):
                # We divide the instruction into several lines to make it more readable
                tmp_exp1 = pow(h, (number.bytes_to_long(PWGi[n].digest()) % key.p), key.p)
                tmp_mul = Qi * (number.inverse(tmp_exp1, key.p)) % key.p
                tmp_exp2 = pow(tmp_mul, kn[n], key.p)
                tmp_hash = h0(str(tmp_exp2).encode('utf-8'), str(n + 1).encode('utf-8'))

                if len(tmp_hash.digest()) != len(number.long_to_bytes(alfai[n], len(tmp_hash.digest()))):
                    raise ValueError('XOR operands have different sizes')
                else:
                    betai.append(xor(tmp_hash.digest(), number.long_to_bytes(alfai[n], len(tmp_hash.digest()))))

            ''' Let A(Q(i)) = (β1,...,βn,g^k1,...,g^kn), and let KS = X^y. '''

            gkn = []  # We already have β1,...,βn; but we have to calculate g^k1,...,g^kn
            for exp in kn:
                gkn.append(pow(key.g, exp, key.p))

            AQi = betai + gkn  # AQi will be the concatenation of betai and gkn lists

            KS = pow(X, y_min, key.p)

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

            ''' Ci extracts αi from A(Q(i)) as αi = βi ⊕ H0((g^ki)^r, i). '''

            beta = AQi[index]  # βi will be in [index] position of A(Q(i)) and g^ki will be in [numUsers+index] position
            gki = int(AQi[numUsers + index])  # It is an integer

            tmp_hs = h0(str(pow(gki, r, key.p)).encode('utf-8'), str(index + 1).encode('utf-8'))  # r generated before

            if len(beta) != len(tmp_hs.digest()):
                raise ValueError('XOR operands have different sizes')
            else:
                alfa = number.bytes_to_long(xor(beta, tmp_hs.digest())) % key.p  # αi is an integer

            ''' Ci computes Y = αi(g^PWFi)^−1, KC = Y^x. '''

            tmp_exp = pow(key.g, (number.bytes_to_long(PWFi[index].digest()) % key.p), key.p)
            Y_c = alfa * (number.inverse(tmp_exp, key.p)) % key.p

            KC = pow(Y_c, key.x, key.p)  # KC = Y^x

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

        file = open("results.txt", 'a')
        file.write(str(numUsers) + "\t" + str(pwdBitLen) + "\t" + str(average).replace(".", ",") + "\n")
        file.close()

    file = open("results.txt", 'a')
    file.write("\n")
    file.close()
