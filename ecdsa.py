from backend.crypto_utils.rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from secrets import randbelow
from backend.crypto_utils.algebra import mod_inv
from typing import Tuple

# Paramètres de la courbe
p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

# Points de base
BaseU = 9
BaseV = computeVcoordinate(BaseU)

def validate_point(x: int, y: int, p: int) -> bool:
    """
    Vérifie si un point est sur la courbe Montgomery
    y² = x³ + 486662x² + x (mod p)
    """
    a = 486662
    left = (y * y) % p
    right = (x * x * x + a * x * x + x) % p
    return left == right

def H(message: bytes) -> int:
    """
    Fonction de hachage SHA-256 pour ECDSA
    
    Args:
        message: Le message à hacher
        
    Returns:
        int: Le hash du message
    """
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

def ECDSA_generate_nonce(private_key: int, message: bytes, order: int = ORDER) -> int:
    """
    Génère un nonce k pour ECDSA de manière déterministe (RFC 6979)
    
    Args:
        private_key: La clé privée
        message: Le message à signer
        order: L'ordre du groupe
        
    Returns:
        int: Le nonce k
        
    Note:
        En production, utiliser RFC 6979 pour la génération déterministe du nonce
    """
    # En production, implémenter RFC 6979
    k = randbelow(order-1) + 1
    return k

def ECDSA_generate_keys(p: int = p) -> Tuple[int, Tuple[int, int]]:
    """
    Génère une paire de clés ECDSA
    
    Args:
        p: Le module premier de la courbe
        
    Returns:
        Tuple[int, Tuple[int, int]]: (clé privée, clé publique)
        La clé publique est un point (x,y) sur la courbe
        
    Raises:
        ValueError: Si les paramètres sont invalides
    """
    # Génère une clé privée dans [1, ORDER-1]
    private_key = randbelow(ORDER-1) + 1
    
    # Calcule la clé publique Q = d*G
    public_key = mult(private_key, BaseU, BaseV, p)
    
    # Vérifie que la clé publique est sur la courbe
    if not validate_point(public_key[0], public_key[1], p):
        raise ValueError("Erreur: La clé publique générée n'est pas sur la courbe")
    
    return private_key, public_key

def ECDSA_sign(message: bytes, private_key: int, p: int = p) -> Tuple[int, int]:
    """
    Signe un message avec ECDSA
    
    Args:
        message: Le message à signer
        private_key: La clé privée
        p: Le module premier de la courbe
        
    Returns:
        Tuple[int, int]: La signature (r, s)
        
    Raises:
        ValueError: Si les paramètres ou la clé sont invalides
    """
    if not 0 < private_key < ORDER:
        raise ValueError("Clé privée invalide")
    
    # Calcule le hash du message
    h = H(message)
    
    while True:
        # Génère un nonce k
        k = ECDSA_generate_nonce(private_key, message)
        
        # Calcule R = k*G et prend l'abscisse
        R = mult(k, BaseU, BaseV, p)
        r = R[0] % ORDER
        if r == 0:
            continue
        
        # Calcule s = k^(-1)(h + d*r) mod n
        k_inv = mod_inv(k, ORDER)
        s = (k_inv * (h + private_key * r)) % ORDER
        if s == 0:
            continue
            
        return r, s

def ECDSA_verify(message: bytes, signature: Tuple[int, int], public_key: Tuple[int, int], 
                 p: int = p) -> bool:
    """
    Vérifie une signature ECDSA
    
    Args:
        message: Le message signé
        signature: La signature (r, s)
        public_key: La clé publique (point sur la courbe)
        p: Le module premier de la courbe
        
    Returns:
        bool: True si la signature est valide
        
    Raises:
        ValueError: Si les paramètres, la signature ou la clé sont invalides
    """
    # Vérifie que la clé publique est sur la courbe
    if not validate_point(public_key[0], public_key[1], p):
        raise ValueError("Clé publique invalide")
    
    r, s = signature
    if not (0 < r < ORDER and 0 < s < ORDER):
        raise ValueError("Signature invalide")
    
    # Calcule w = s^(-1) mod n
    w = mod_inv(s, ORDER)
    
    # Calcule le hash du message
    h = H(message)
    
    # Calcule u1 = hw mod n et u2 = rw mod n
    u1 = (h * w) % ORDER
    u2 = (r * w) % ORDER
    
    # Calcule u1*G + u2*Q
    point1 = mult(u1, BaseU, BaseV, p)
    point2 = mult(u2, public_key[0], public_key[1], p)
    R = add(point1[0], point1[1], point2[0], point2[1], p)
    
    # Vérifie si x_R mod n = r
    return R[0] % ORDER == r
