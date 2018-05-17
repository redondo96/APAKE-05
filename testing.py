import string
import time
import ast

from Crypto.Hash import SHA512

from Crypto.Util import number
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
    return bytearray(a ^ b for a, b in zip(*map(bytearray, [data1, data2])))


""" setUp() """

''' Number of users of the user group Γ '''
numUsers = 10  # Number of users (i.e., of passwords in the password database at the sender)
''' Number of users of the user group Γ '''
pwdBitlen = 8  # Number of bits of a password

""" Let Γ be a user-group (or simply group) of n users {C1, . . . , Cn}.
Each user Ci in Γ is initially provided a distinct low entropy password pwi,
while S holds a list of these passwords. """
pwdList = []
for i in range(numUsers):
    pwd = random.randint(0, 2 ** pwdBitlen - 1)
    pwdList.append(pwd)

# print(pwdList)

# User's password should be in Server's list
index = random.choice(range(0, numUsers))
print("index (from 1 to numUsers):", index+1)
usr_pwd = pwdList[index]
# print(usr_pwd)

# Server's identification string
id_server = "server1"


# PWFi and PWGi
PWFi = []
PWGi = []
i = 1
for k in pwdList:
    # PWFi = F(pwi)
    PWFi.append(f(str(k).encode('utf-8')))  # str in k
    # PWGi = G(i, pwi)
    PWGi.append(g(str(i).encode('utf-8'), str(k).encode('utf-8')))  # str in k
    i = i + 1

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
X = key.y
# We use ElGamal's implementation so we can generate r ∈ Zp
r = number.getRandomRange(2, key.p - 1, Random.new().read)

''' Next, Ci generates a query Q(i) for the i-th data in OT protocol as
# Q(i) = g^r h^G(i,pwi) = g^r h^PWGi. '''
gr = pow(key.g, r, key.p)

# We need to create another generator, h
# q is
q = (key.p - 1) // 2

h = pow(key.g, number.getRandomRange(1, q, Random.new().read), key.p)
# print(h)


""" Saving information in a file """

f = open("apake05.txt", 'w')
f.write("Password list:\n")
f.write(str(pwdList) + "\n")
f.write("generator g:\n")
f.write(str(key.g) + "\n")
f.write("generator h:\n")
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
            ge = line  # 4th line
        elif i == 5:
            hache = line  # 6th line

# Testing access to the read list
for i in list(password_list):
    print("password_list:", i)
print("ge:", ge)
print("hache:", hache)


gi = PWGi[index]
# print(gi.hexdigest())

hp = pow(h, number.bytes_to_long(gi.digest()), key.p)

Qi = gr * hp % key.p
print(Qi)

"""" Ci sends (Γ, X, Q(i)) to S. """
# We have all of the pieces


""" Phase 2 """
''' S chooses randomly and uniformly y, k1,...,kn ∈ Zp and computes Y = gy
and αi,βj for 1 ≤ j ≤ n as follows:􏱅􏱆 􏱇 􏱈
                                    αj =Y*g^F(pwj) = Y*g^PWFj, βj = H0(Q(i)(h^PWGj)^−1)^kj ,j) ⊕ αj. '''

# We use ElGamal's implementation so we can generate y ∈ Zp
y = number.getRandomRange(2, key.p - 1, Random.new().read)

Y = pow(key.g, y, key.p)

# k1,...,kn ∈ Zp
kn = []
for i in range(0, numUsers):
    kn.append(number.getRandomRange(2, key.p - 1, Random.new().read))

# print(kn)


alfai = []
for pwf in PWFi:
    tmp = pow(key.g, number.bytes_to_long(pwf.digest()), key.p)
    mul = Y * tmp % key.p
    alfai.append(mul)

print(alfai)

betai = []
for n in range(numUsers):
    exp1 = pow(h, number.bytes_to_long(PWGi[n].digest()), key.p)
    inv = number.inverse(exp1, key.p)
    mul = Qi * inv % key.p
    exp2 = pow(mul, kn[n], key.p)
    hs = h0(str(exp2).encode('utf-8'), str(n+1).encode('utf-8'))
    if len(hs.digest()) != len(number.long_to_bytes(alfai[n], len(hs.digest()))):
        raise ValueError('different sizes')
    else:
        x_or = xor(hs.digest(), number.long_to_bytes(alfai[n]))
        betai.append(x_or)

print(betai)

''' Let A(Q(i)) = (β1,...,βn,g^k1,...,g^kn), and let KS = X^y. '''
# We already have β1,...,βn; but we have to calculate g^k1,...,g^kn

gkn = []
for exp in kn:
    gk = pow(key.g, exp, key.p)
    gkn.append(gk)

# print(gkn)

# AQi will be the concatenation of betai and gkn lists
AQi = betai + gkn
print("A(Q(i)):", AQi)

# Ks
Ks = pow(X, y, key.p)
print(Ks)

''' S computes the authenticator AuthS and the session key skS as follows
AuthS = H2(Γ,S,X,A(Q(i)),Y,KS) and skS = H1(Γ,S,X,A(Q(i)),Y,KS). '''

AuthS = h2(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
           str(AQi).encode('utf-8'), str(Y).encode('utf-8'), str(Ks).encode('utf-8'))
# print(AuthS.hexdigest())

skS = h1(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
         str(AQi).encode('utf-8'), str(Y).encode('utf-8'), str(Ks).encode('utf-8'))

""" S sends (S,A(Q(i)),AuthS) to Ci. """
# We have all of the pieces


""" Phase 3 """
''' Ci extracts αi from A(Q(i)) as αi = βi ⊕ H0((g^ki)^r,i). '''
# βi will be in the [index] position of A(Q(i)) and g^ki will be in the [numUsers+index] position
beta = AQi[index]
gki = int(AQi[numUsers+index])
print("beta:", beta)
print("gki:", gki)

exp = pow(gki, r, key.p)
hs = h0(str(exp).encode('utf-8'), str(i+1).encode('utf-8'))
alfa = number.bytes_to_long(xor(beta, hs.digest()))
print("alfa:", alfa)

print("alfai[index]:", alfai[index])


''' Ci computes Y = αi(g^PWFi )^−1, KC = Y^x. '''
fi_c = PWFi[index]
exp = pow(key.g, number.bytes_to_long(fi_c.digest()), key.p)
inv = number.inverse(exp, key.p)
Y_c = alfa * inv % key.p

Kc = pow(Y_c, key.x, key.p)
print("Kc:", Kc)


''' Ci computes AuthC = H2(Γ,S,X,A(Q(i)),Y,KC) and checks whether AuthS =? AuthC '''
AuthC = h2(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
           str(AQi).encode('utf-8'), str(Y_c).encode('utf-8'), str(Kc).encode('utf-8'))

print("AuthC:", AuthC.hexdigest())
print("AuthS:", AuthS.hexdigest())

''' If AuthS is valid, Ci accepts and computes the session-key skC as
skC = H1(Γ,S,X,A(Q(i)),Y,KC). If AuthS is invalid then Ci aborts the protocol. '''

if AuthC.hexdigest() == AuthS.hexdigest():
    skC = h1(str(pwdList).encode('utf-8'), id_server.encode('utf-8'), str(X).encode('utf-8'),
             str(AQi).encode('utf-8'), str(Y_c).encode('utf-8'), str(Kc).encode('utf-8'))
else:
    print("Incorrect Authentication. Aborting protocol...")

