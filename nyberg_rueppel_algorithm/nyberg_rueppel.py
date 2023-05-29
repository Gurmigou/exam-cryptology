import hashlib
import random
from sympy import isprime


class NybergRueppelAlgorithm:
    def generate_keys(self):
        q = self.generate_prime(256)
        p = 2 * q + 1
        while not isprime(p):
            q = self.generate_prime(256)
            p = 2 * q + 1

        g = random.randint(2, p - 1)
        x = random.randint(2, q - 1)
        y = pow(g, x, p)

        return (p, q, g, y, x)

    def modular_inverse(self, a, m):
        if a < 0:
            a = m + (a % m)
        _, x, _ = self.extended_gcd(a, m)
        return x % m

    def generate_prime(self, bit_length):
        while True:
            p = random.getrandbits(bit_length)
            if isprime(p):
                return p

    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def verify(self, message, signature, public_key):
        p, q, g, y = public_key
        r, s = signature

        if r < 1 or r > q - 1 or s < 1 or s > q - 1:
            return False

        h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        w = self.modular_inverse(s, q)
        u1 = (h * w) % q
        u2 = (r * w) % q
        v = (pow(g, u1, p) * pow(y, u2, p)) % p % q

        return v == r

    def sign(self, message, private_key):
        p, q, g, y, x = private_key
        h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        k = random.randint(2, q - 1)
        r = pow(g, k, p) % q
        s = (self.modular_inverse(k, q) * (h + x * r)) % q

        return (r, s)
