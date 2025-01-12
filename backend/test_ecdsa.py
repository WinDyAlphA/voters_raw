from ecdsa import *
from crypto_utils.rfc7748 import computeVcoordinate

# Paramètres de la courbe
p = p  # Le module premier
q = ORDER  # L'ordre du groupe
BaseU = BaseU  # Point de base U
BaseV = computeVcoordinate(BaseU)  # Point de base V

# Valeurs spécifiées dans l'énoncé
m = 'A very very important message !'
k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8

# Valeurs attendues
expected_r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
expected_s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

# Calcul du hash
h = H(str.encode(m)) % ORDER  # Réduction modulo l'ordre du groupe

# Calcul du point kG = (x1, y1)
kG = mult(k, BaseU, BaseV, p)

# Calcul de r = x1 mod n
r = kG[0] % ORDER
if r == 0:
    print("Erreur: r est nul")
    exit(1)

# Calcul de s = k^(-1)(h + x·r) mod n
k_inv = mod_inv(k, ORDER)
s = (k_inv * ((h + x * r) % ORDER)) % ORDER
if s == 0:
    print("Erreur: s est nul")
    exit(1)

# Affichage des résultats
print("Résultats obtenus:")
print(f"r = {hex(r)}")
print(f"s = {hex(s)}")
print("\nValeurs attendues:")
print(f"r = {hex(expected_r)}")
print(f"s = {hex(expected_s)}")
print("\nVérification:")
print(f"r correct: {r == expected_r}")
print(f"s correct: {s == expected_s}")

# Calcul de la clé publique Q = xG
Q = mult(x, BaseU, BaseV, p)

# Vérification de la signature
is_valid = ECDSA_verify(str.encode(m), (r, s), Q)
print(f"\nSignature valide: {is_valid}") 