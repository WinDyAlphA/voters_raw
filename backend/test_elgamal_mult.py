"""
ElGamal est homomorphique multiplicatif ! Voici pourquoi :

Dans ElGamal classique, le chiffrement d'un message m est :
- r = g^k mod p
- c = m * y^k mod p (où y est la clé publique)

Quand on multiplie deux chiffrés (r1,c1) et (r2,c2) :
(r1*r2, c1*c2) = (g^k1 * g^k2, m1*y^k1 * m2*y^k2)
                = (g^(k1+k2), m1*m2 * y^(k1+k2))

C'est exactement la forme d'un chiffrement de (m1*m2) avec k = k1+k2 !
"""

from elgamal import EG_generate_keys, EGM_encrypt, EGM_decrypt, PARAM_P
from crypto_utils.algebra import int_to_bytes

# Messages à chiffrer (en hexadécimal)
m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

print("\nMessages originaux:")
print(f"m1 = {hex(m1)}")
print(f"m2 = {hex(m2)}")

# Calcul du produit attendu
expected_product = (m1 * m2) % PARAM_P
print(f"\nProduit attendu: {hex(expected_product)}")

# Génération des clés
private_key, public_key = EG_generate_keys()

# Chiffrement des messages
r1, c1 = EGM_encrypt(m1, public_key)
r2, c2 = EGM_encrypt(m2, public_key)

print("\nChiffrés:")
print(f"(r1, c1) = ({hex(r1)}, {hex(c1)})")
print(f"(r2, c2) = ({hex(r2)}, {hex(c2)})")

# Multiplication des chiffrés
r3 = (r1 * r2) % PARAM_P
c3 = (c1 * c2) % PARAM_P

print("\nProduit des chiffrés:")
print(f"(r3, c3) = ({hex(r3)}, {hex(c3)})")

# Déchiffrement du produit
m3 = EGM_decrypt(private_key, r3, c3)
print(f"\nProduit déchiffré (m3): {hex(m3)}")

# Vérification
print(f"\nVérification m3 == m1 * m2: {m3 == expected_product}")

# Décodage de m3
decoded = int_to_bytes(m3)
print(f"\nMessage décodé: {decoded}") 