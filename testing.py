import string
import time

from Crypto.Hash import SHA256

from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Hash import SHA

n_users = 10


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

list_pwd = []
for i in range(0, n_users):
    list_pwd.append(password_generator(8))

print(list_pwd)

# User's password should be in Server's list
usr_pwd = random.choice(list_pwd)
print(usr_pwd)

starting_point = time.time()
print(starting_point)

time.sleep(8)

elapsed_time = time.time() - starting_point
print(elapsed_time)  # seconds

elapsed_time_ms = (time.time() - starting_point)*1000
print(elapsed_time_ms)  # milliseconds

hash = SHA256.new()


key = ElGamal.generate(2048, Random.new().read)
print(key)

# from Crypto.Cipher import AES
#
# obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
# message = "The answer is no"
# ciphertext = obj.encrypt(message)
# print(ciphertext)
#
# obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
# print(obj2.decrypt(ciphertext))


