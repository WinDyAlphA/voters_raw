from dsa import *
from backend.crypto_utils.algebra import mod_inv
from backend.dsa import H

p = PARAM_P
q = PARAM_Q
g = PARAM_G

m = 'An important message !'
k = 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759
x = 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3

h = H(str.encode(m)) % q

r = 0
s = 0

while True:
    r = pow(g, k, p) % q
    if r == 0:
        continue

    k_inv = mod_inv(k, q)
    s = (k_inv * ((h + x * r)) % q) % q
    if s == 0:
        continue
    else:
        break

print(hex(r))
print(hex(s))

