"""
ElGamal peut être rendu additif ! Voici comment :

Au lieu de chiffrer directement m, on chiffre g^m :
- Dans la version multiplicative : c = m * y^k mod p
- Dans la version additive : c = g^m * y^k mod p

Quand on multiplie deux chiffrés (r1,c1) et (r2,c2) :
(r1*r2, c1*c2) = (g^k1 * g^k2, g^m1 * y^k1 * g^m2 * y^k2)
                = (g^(k1+k2), g^(m1+m2) * y^(k1+k2))

C'est exactement la forme d'un chiffrement de (m1+m2) !
Le déchiffrement donne g^(m1+m2), il faut ensuite calculer le logarithme discret
pour retrouver m1+m2.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from backend.elgamal import (
 EG_generate_keys, EGA_encrypt, EGA_decrypt, PARAM_P, PARAM_G
)


# Messages à chiffrer (votes)
messages = [1, 0, 1, 1, 0]  # m1 à m5
print(f"\nMessages originaux: {messages}")
print(f"Somme attendue: {sum(messages)}")

# Génération des clés
private_key, public_key = EG_generate_keys()

# Chiffrement des messages
encrypted = []
for i, m in enumerate(messages, 1):
    enc = EGA_encrypt(m, public_key)
    encrypted.append(enc)
    print(f"\nChiffré {i} (r{i}, c{i}):")
    print(f"r{i} = {hex(enc[0])}")
    print(f"c{i} = {hex(enc[1])}")

# Multiplication des chiffrés
r_prod = encrypted[0][0]  # Premier r
c_prod = encrypted[0][1]  # Premier c

# Multiplication des autres chiffrés
for r, c in encrypted[1:]:
    r_prod = (r_prod * r) % PARAM_P
    c_prod = (c_prod * c) % PARAM_P

print("\nProduit des chiffrés (r, c):")
print(f"r = {hex(r_prod)}")
print(f"c = {hex(c_prod)}")

# Déchiffrement du produit
m_sum = EGA_decrypt(private_key, r_prod, c_prod)
print(f"\nSomme déchiffrée (m): {m_sum}")

# Vérification
print(f"\nVérification m == sum(messages): {m_sum == sum(messages)}") 