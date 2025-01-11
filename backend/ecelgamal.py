from crypto_utils.rfc7748 import x25519, add, sub, mult
from crypto_utils.algebra import mod_inv, int_to_bytes, mod_sqrt
from secrets import randbelow
from typing import Tuple, Optional

# Constantes de la courbe
p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

# Points de base
BaseU = 9
BaseV = mod_sqrt((pow(BaseU, 3, p) + 486662 * pow(BaseU, 2, p) + BaseU) % p, p)

def validate_point(x: int, y: int, p: int) -> bool:
    """
    Vérifie si un point est sur la courbe Montgomery
    y² = x³ + 486662x² + x (mod p)
    """
    a = 486662
    left = (y * y) % p
    right = (x * x * x + a * x * x + x) % p
    return left == right

def bruteECLog(C1: int, C2: int, p: int) -> int:
    """
    ATTENTION: Cette fonction ne doit pas être utilisée en production.
    Elle est vulnérable aux attaques temporelles et n'est présente que pour des tests.
    """
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message: int) -> Tuple[int, int]:
    """
    Encode un bit en point sur la courbe
    
    Args:
        message: Doit être 0 ou 1
        
    Returns:
        Tuple[int, int]: Point sur la courbe
        
    Raises:
        ValueError: Si le message n'est pas 0 ou 1
    """
    if not isinstance(message, int) or message not in (0, 1):
        raise ValueError("Le message doit être 0 ou 1")
    
    if message == 0:
        return (1, 0)
    
    # Pour message = 1, on retourne le point de base
    # On vérifie que le point est bien sur la courbe
    if not validate_point(BaseU, BaseV, p):
        raise ValueError("Point de base invalide")
    return (BaseU, BaseV)

def ECEG_generate_keys(p: int = p) -> Tuple[int, Tuple[int, int]]:
    """
    Génère une paire de clés pour EC-ElGamal de manière cryptographiquement sûre
    
    Args:
        p: Le module premier
        
    Returns:
        Tuple[int, Tuple[int, int]]: (clé privée, clé publique)
        La clé publique est un point (x,y) sur la courbe
        
    Raises:
        ValueError: Si les paramètres sont invalides
    """
    # Génère une clé privée aléatoire dans [1, ORDER-1]
    private_key = randbelow(ORDER-2) + 1
    
    # Calcule la clé publique H = private_key * G
    public_key = mult(private_key, BaseU, BaseV, p)
    
    # Vérifie que la clé publique est un point valide sur la courbe
    if not validate_point(public_key[0], public_key[1], p):
        raise ValueError("Erreur: La clé publique générée n'est pas sur la courbe")
    
    return private_key, public_key

def ECEG_encrypt(message: int, public_key: Tuple[int, int], p: int = p) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Chiffre un message (0 ou 1) avec EC-ElGamal
    """
    # Vérifie que le message est 0 ou 1
    if message not in (0, 1):
        raise ValueError("Le message doit être 0 ou 1")
    
    # Génère un nombre aléatoire k
    k = randbelow(ORDER)
    
    # Calcule C1 = k*G
    C1 = mult(k, BaseU, BaseV, p)
    
    # Encode le message comme un point
    if message == 0:
        M = (1, 0)  # Point à l'infini pour 0
    else:
        M = (BaseU, BaseV)  # Point de base pour 1
    
    # Calcule S = k*public_key
    S = mult(k, public_key[0], public_key[1], p)
    
    # Calcule C2 = M + S
    C2 = add(M[0], M[1], S[0], S[1], p)
    
    return (C1, C2)

def ECEG_decrypt(private_key: int, C1: Tuple[int, int], C2: Tuple[int, int], p: int = p) -> int:
    """
    Déchiffre un message avec EC-ElGamal
    """
    # Calcule S = private_key * C1
    S = mult(private_key, C1[0], C1[1], p)
    
    # Calcule -S
    neg_S = (S[0], -S[1] % p)
    
    # Calcule M = C2 - S
    M = add(C2[0], C2[1], neg_S[0], neg_S[1], p)
    
    # Décode le message
    if M == (1, 0):  # Point à l'infini
        return 0
    elif M == (BaseU, BaseV):  # Point de base
        return 1
    elif M == (BaseU, (-BaseV % p)):  # Point de base négatif
        return 1
    else:
        # Pour les votes combinés, compte le nombre de fois que le point de base apparaît
        current = (1, 0)  # Point à l'infini
        base = (BaseU, BaseV)
        
        for i in range(10):  # Limite à 10 votes pour éviter une boucle infinie
            if current == M:
                return i
            current = add(current[0], current[1], base[0], base[1], p)
        
        # Essaie avec le point négatif
        current = (1, 0)
        base = (BaseU, (-BaseV % p))
        
        for i in range(10):
            if current == M:
                return i
            current = add(current[0], current[1], base[0], base[1], p)
            
        raise ValueError(f"Impossible de déchiffrer le point {M}")

