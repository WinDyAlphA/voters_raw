from dsa import *
from crypto_utils.algebra import mod_inv
from dsa import H

p = PARAM_P
q = PARAM_Q
g = PARAM_G

# Valeurs spécifiées dans l'énoncé
m = 'An important message !'
k = 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759
x = 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3

# Valeurs attendues
expected_r = 0x5ddf26ae653f5583e44259985262c84b483b74be46dec74b07906c5896e26e5a
expected_s = 0x194101d2c55ac599e4a61603bc6667dcc23bd2e9bdbef353ec3cb839dcce6ec1

# Calcul du hash
h = H(str.encode(m)) % q

print("\nValeurs intermédiaires:")
print(f"h = {hex(h)}")
print(f"k = {hex(k)}")
print(f"x = {hex(x)}")

# Calcul de r et s
r = pow(g, k, p) % q
if r == 0:
    print("Erreur: r est nul")
    exit(1)

k_inv = mod_inv(k, q)
s = (k_inv * ((h + x * r) % q)) % q
if s == 0:
    print("Erreur: s est nul")
    exit(1)

# Affichage des résultats
print("\nRésultats obtenus:")
print(f"r = {hex(r)}")
print(f"s = {hex(s)}")
print("\nValeurs attendues:")
print(f"r = {hex(expected_r)}")
print(f"s = {hex(expected_s)}")
print("\nVérification:")
print(f"r correct: {r == expected_r}")
print(f"s correct: {s == expected_s}")

# Vérification de la signature
y = pow(g, x, p)  # Calcul de la clé publique
is_valid = DSA_verify(str.encode(m), (r, s), y)
print(f"\nSignature valide: {is_valid}")

