"""
EC ElGamal is already additive! Explain why:

Dans EC-ElGamal, le chiffrement d'un message m est :
- r = kG
- c = mG + kY (où Y est la clé publique)

Quand on additionne deux chiffrés (r1,c1) et (r2,c2) :
(r1+r2, c1+c2) = (k1G + k2G, m1G + k1Y + m2G + k2Y)
                = ((k1+k2)G, (m1+m2)G + (k1+k2)Y)

C'est exactement la forme d'un chiffrement de (m1+m2) avec k = k1+k2 !
Donc EC-ElGamal est naturellement additif, contrairement à ElGamal classique
qui est multiplicatif.
"""

from ecelgamal import (
    ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt,
    p, BaseU, BaseV
)
from crypto_utils.rfc7748 import add, mult

# Génération des clés
private_key, public_key = ECEG_generate_keys()

# Messages à chiffrer
messages = [1, 0, 1, 1, 0]  # m1 à m5
print(f"\nMessages originaux: {messages}")
print(f"Somme attendue: {sum(messages)}")

# Chiffrement des messages
encrypted = []
for i, m in enumerate(messages, 1):
    enc = ECEG_encrypt(m, public_key)
    encrypted.append(enc)
    print(f"\nChiffré {i} (r{i}, c{i}):")
    print(f"r{i} = ({hex(enc[0][0])}, {hex(enc[0][1])})")
    print(f"c{i} = ({hex(enc[1][0])}, {hex(enc[1][1])})")

# Addition des chiffrés
r_sum = encrypted[0][0]  # Premier r
c_sum = encrypted[0][1]  # Premier c

# Addition des autres chiffrés
for r, c in encrypted[1:]:
    r_sum = add(r_sum[0], r_sum[1], r[0], r[1], p)
    c_sum = add(c_sum[0], c_sum[1], c[0], c[1], p)

print("\nSomme des chiffrés (r, c):")
print(f"r = ({hex(r_sum[0])}, {hex(r_sum[1])})")
print(f"c = ({hex(c_sum[0])}, {hex(c_sum[1])})")

# Déchiffrement de la somme
m = ECEG_decrypt(private_key, r_sum, c_sum)
print(f"\nSomme déchiffrée (m): {m}")

# Vérification
print(f"Vérification: {m == sum(messages)}") 