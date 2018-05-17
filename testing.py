import string
import time
import ast

from Crypto.Util import number
from Crypto.Hash import SHA512
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal


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


def xor(data1, data2):
    """
    Does a "bitwise exclusive or".
    Each bit of the output is the same as the corresponding bit in data1 if that bit in data2 is 0,
    and it's the complement of the bit in data1 if that bit in data2 is 1.

    data1: the first bit string of the operation
    data2: the second bit string of the operation
    """
    return bytearray(a ^ b for a, b in zip(*map(bytearray, [data1, data2])))


""" setUp() """

numUsers = 10  # Number of users of the user group Γ (i.e., of passwords in the password database at the sender)
pwdBitlen = 8  # Number of bits of a password

id_server = "server1"  # Server's identification string

''' Let Γ be a user-group (or simply group) of n users {C1,...,Cn}.
Each user Ci in Γ is initially provided a distinct low entropy password pwi,
while S holds a list of these passwords. '''

pwdList = []
for i in range(numUsers):
    pwd = random.randint(0, 2 ** pwdBitlen - 1)
    pwdList.append(pwd)

print("pwdList:", pwdList)

index = random.choice(range(numUsers))  # User's password should be in Server's list
pwdUser = pwdList[index]

print("index (from 1 to numUsers):", index+1)
print("pwdUser:", pwdUser)


''' We set PWFi = F(pwi) and PWGi = G(i,pwi). '''
PWFi = []
PWGi = []
i = 1
for k in pwdList:
    PWFi.append(f(str(k).encode('utf-8')))  # PWFi = F(pwi)                                     # str in k
    PWGi.append(g(str(i).encode('utf-8'), str(k).encode('utf-8')))  # PWGi = G(i, pwi)          # str in k
    i = i + 1

''' print("PWFi:")
for elem in PWFi:
    print(len(elem.digest())*8) '''

print("\nPWGi:")
for elem in PWGi:
    print(elem.hexdigest())


""" To measure times """
starting_point = time.time()


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

# Tests ElGamal:
print("\nModulus:", key.p)
print("Order of the group:", key.p - 1, "\n")

print("Generator:", key.g)
print("size of the generator g in bits:", number.size(key.g), "\n")

print("Public key:", key.y)
print("size of the public key in bits:", number.size(key.y), "\n")

print("Private key:", key.x)
print("size of the private key in bits:", number.size(key.x), "\n")


# We need to select another generator, h
q = (key.p - 1) // 2  # View ElGamal's implementation to find the value of q
h = pow(key.g, number.getRandomRange(1, q, Random.new().read), key.p)
print("Generator h:", h)
print("size of the generator h in bits:", number.size(h), "\n")


""" Saving information in a file """

f = open("apake05.txt", 'w')
f.write("Password list:\n")
f.write(str(pwdList))
f.write("\ngenerator g:\n")
f.write(str(key.g))
f.write("\ngenerator h:\n")
f.write(str(h) + "\n")
f.close()


""" Reading information from file """

password_list = []
ge = 0
hache = 0
with open("apake05.txt", 'r') as fp:
    for i, line in enumerate(fp):
        if i == 1:
            password_list = ast.literal_eval(line)  # 2nd line
        elif i == 3:
            ge = int(line)  # 4th line
        elif i == 5:
            hache = int(line)  # 6th line

''' # Testing access to the read list
for i in list(password_list):
    print("password_list:", i)
print("\nge:", ge)
print("hache:", hache) '''


elapsed_time = time.time() - starting_point
print(elapsed_time, "s")  # seconds

elapsed_time_ms = (time.time() - starting_point) * 1000
print(elapsed_time_ms, "ms")  # milliseconds


""" Phase 1 """
''' Ci chooses randomly and uniformly x,r ∈ Zp and computes X = g^x. '''

X = key.y  # The public key of ElGamal key is y = g^x, so X = y
r = number.getRandomRange(2, key.p-1, Random.new().read)  # We generate r ∈ Zp

''' Next, Ci generates a query Q(i) for the i-th data in OT protocol as
Q(i) = g^r h^G(i,pwi) = g^r h^PWGi. '''

tmp_gr = pow(key.g, r, key.p)
gi = PWGi[index]
# To check if it is well chosen
print("\ngi:", gi.hexdigest())  # i-th data in PWGi
tmp_hp = pow(h, number.bytes_to_long(gi.digest()), key.p)

Qi = tmp_gr * tmp_hp % key.p
print("\nQuery Qi:", Qi)
print("size of Qi in bits:", number.size(Qi))

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

y_min = number.getRandomRange(2, key.p-1, Random.new().read)  # We generate y ∈ Zp
Y = pow(key.g, y_min, key.p)

kn = []  # k1,...,kn ∈ Zp
for i in range(numUsers):
    kn.append(number.getRandomRange(2, key.p-1, Random.new().read))

# print("\nk1...n:", kn)


alfai = []  # αj for 1 ≤ j ≤ n
for pwf in PWFi:
    tmp_hs = number.bytes_to_long(pwf.digest()) % key.p
    tmp_exp = pow(key.g, tmp_hs, key.p)
    tmp_mul = Y * tmp_exp % key.p
    alfai.append(tmp_mul)

print("\nαi:", alfai)
print("List with size:", len(alfai))

betai = []  # βj for 1 ≤ j ≤ n
for n in range(numUsers):
    tmp_hs = number.bytes_to_long(PWGi[n].digest()) % key.p
    tmp_exp1 = pow(h, tmp_hs, key.p)
    tmp_inv = number.inverse(tmp_exp1, key.p)
    tmp_mul = Qi * tmp_inv % key.p
    tmp_exp2 = pow(tmp_mul, kn[n], key.p)
    tmp_hash = h0(str(tmp_exp2).encode('utf-8'), str(n+1).encode('utf-8'))
    if len(tmp_hash.digest()) != len(number.long_to_bytes(alfai[n], len(tmp_hash.digest()))):
        raise ValueError('XOR operands have different sizes')
    else:
        tmp_xor = xor(tmp_hash.digest(), number.long_to_bytes(alfai[n], len(tmp_hash.digest())))
        betai.append(tmp_xor)

print("\nβi:", betai)
print("List with size:", len(betai))

''' Let A(Q(i)) = (β1,...,βn,g^k1,...,g^kn), and let KS = X^y. '''

gkn = []  # We already have β1,...,βn; but we have to calculate g^k1,...,g^kn
for exp in kn:
    gk = pow(key.g, exp, key.p)
    gkn.append(gk)

print("\ngkn:", gkn)

AQi = betai + gkn  # AQi will be the concatenation of betai and gkn lists
print("\nA(Q(i)):", AQi)
print("List with size:", len(AQi))

KS = pow(X, y_min, key.p)
print("\nKs:", KS)

''' S computes the authenticator AuthS and the session key skS as follows
AuthS = H2(Γ,S,X,A(Q(i)),Y,KS) and skS = H1(Γ,S,X,A(Q(i)),Y,KS). '''

AuthS = h2(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
           str(AQi).encode('utf-8'), str(Y).encode('utf-8'), str(KS).encode('utf-8'))

print("\nAuthS", AuthS.hexdigest())
# print("With size:", len(AuthS.digest())*8)

skS = h1(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
         str(AQi).encode('utf-8'), str(Y).encode('utf-8'), str(KS).encode('utf-8'))

print("\nskS:", skS.hexdigest())
# print("With size:", len(skS.digest())*8)

''' S sends (S,A(Q(i)),AuthS) to Ci. '''
'''
We have all of the pieces:

    S -> id_server
    A(Q(i)) -> AQi
    AuthS -> AuthS
'''


""" Phase 3 """
''' Ci extracts αi from A(Q(i)) as αi = βi ⊕ H0((g^ki)^r,i). '''

beta = AQi[index]  # βi will be in the [index] position of A(Q(i)) and g^ki will be in the [numUsers+index] position
gki = int(AQi[numUsers+index])  # It is an integer
print("\nbeta:", beta)
print("\ngki:", gki)

tmp_exp = pow(gki, r, key.p)  # r generated before
tmp_hs = h0(str(tmp_exp).encode('utf-8'), str(index+1).encode('utf-8'))
if len(beta) != len(tmp_hs.digest()):
    raise ValueError('XOR operands have different sizes')
else:
    alfa = number.bytes_to_long(xor(beta, tmp_hs.digest())) % key.p  # αi is an integer

# Check if extracted αi and server's αi match
print("\nalfa:", alfa)
print("alfai[index]:", alfai[index])


''' Ci computes Y = αi(g^PWFi )^−1, KC = Y^x. '''

tmp_fi = PWFi[index]
tmp_hs = number.bytes_to_long(tmp_fi.digest()) % key.p
tmp_exp = pow(key.g, tmp_hs, key.p)
tmp_inv = number.inverse(tmp_exp, key.p)
Y_c = alfa * tmp_inv % key.p

# Check if computed Y (Y_c) and server's Y match
print("\nComputed Y (Y_c):", Y_c)
print("Server's Y:", Y)

KC = pow(Y_c, key.x, key.p)  # KC = Y^x
print("\nKc:", KC)


''' Ci computes AuthC = H2(Γ,S,X,A(Q(i)),Y,KC) and checks whether AuthS =? AuthC '''

AuthC = h2(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
           str(AQi).encode('utf-8'), str(Y_c).encode('utf-8'), str(KC).encode('utf-8'))

print("\nAuthC:", AuthC.hexdigest())
print("AuthS:", AuthS.hexdigest())

''' If AuthS is valid, Ci accepts and computes the session-key skC as
skC = H1(Γ,S,X,A(Q(i)),Y,KC). If AuthS is invalid then Ci aborts the protocol. '''

if AuthC.hexdigest() == AuthS.hexdigest():  # Accept
    skC = h1(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
             str(AQi).encode('utf-8'), str(Y_c).encode('utf-8'), str(KC).encode('utf-8'))

    print("\nSuccessful.")
    print("skC:", skC.hexdigest())

else:
    print("\nIncorrect Authentication. Aborting protocol...")
