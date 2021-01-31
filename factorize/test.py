import random
from Crypto.Util.number import isPrime

def genPrimes(size):
    base = random.getrandbits(size // 2) << size // 2
    base = base | (1 << 1023) | (1 << 1022) | 1
    while True:
        temp = base | random.getrandbits(size // 2)
        if isPrime(temp):
            p = temp
            break
    while True:
        temp = base | random.getrandbits(size // 2)
        if isPrime(temp):
            q = temp
            break
    return (p, q)
p,q = genPrimes(1024)
assert bin(p)[2:514] == bin(q)[2:514]