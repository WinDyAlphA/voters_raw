from crypto_utils.algebra import mod_inv, int_to_bytes
from secrets import randbelow
from typing import Tuple

# Paramètres du groupe (Nombre premier sûr et son générateur)
PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def validate_params() -> bool:
    """
    Vérifie que les paramètres du groupe sont valides
    """
    # Vérifie que p est premier (test basique)
    if PARAM_P < 2 or PARAM_Q < 2:
        return False
    
    # Vérifie que g est un générateur valide
    if PARAM_G <= 1 or PARAM_G >= PARAM_P:
        return False
    
    # Vérifie que g^q ≡ 1 (mod p)
    if pow(PARAM_G, PARAM_Q, PARAM_P) != 1:
        return False
        
    return True

def EG_generate_keys(p: int = PARAM_P, g: int = PARAM_G) -> Tuple[int, int]:
    """
    Génère une paire de clés ElGamal de manière cryptographiquement sûre
    
    Args:
        p: Le module premier
        g: Le générateur du groupe
        
    Returns:
        Tuple[int, int]: (clé privée, clé publique)
        
    Raises:
        ValueError: Si les paramètres sont invalides
    """
    if not validate_params():
        raise ValueError("Paramètres du groupe invalides")
    
    # Génère une clé privée aléatoire dans [1, q-1]
    private_key = randbelow(PARAM_Q-2) + 1
    
    # Calcule la clé publique h = g^x mod p
    public_key = pow(g, private_key, p)
    
    return private_key, public_key

def EG_encrypt(message: int, public_key: int, p: int = PARAM_P, g: int = PARAM_G) -> Tuple[int, int]:
    """
    Chiffre un message avec ElGamal (version multiplicative générale)
    
    Args:
        message: Le message à chiffrer
        public_key: La clé publique du destinataire
        p: Le module premier
        g: Le générateur du groupe
        
    Returns:
        Tuple[int, int]: (r, c) le texte chiffré
    """
    if not validate_params():
        raise ValueError("Paramètres du groupe invalides")
    
    if not 0 < message < p:
        raise ValueError("Message invalide")
    
    # Génère un nombre aléatoire k
    k = randbelow(PARAM_Q-2) + 1
    
    # Calcule r = g^k mod p
    r = pow(g, k, p)
    
    # Calcule c = m * y^k mod p
    c = (message * pow(public_key, k, p)) % p
    
    return r, c

def EG_decrypt(private_key: int, c1: int, c2: int, p: int = PARAM_P) -> int:
    """
    Déchiffre un message avec ElGamal
    
    Args:
        private_key: La clé privée
        c1, c2: Le texte chiffré
        p: Le module premier
        
    Returns:
        int: Le message déchiffré
        
    Raises:
        ValueError: Si les paramètres ou le chiffré sont invalides
    """
    if not validate_params():
        raise ValueError("Paramètres du groupe invalides")
    
    if not 0 < private_key < PARAM_Q:
        raise ValueError("Clé privée invalide")
    
    # Calcule s = c1^x mod p
    s = pow(c1, private_key, p)
    
    # Calcule m = c2 * s^(-1) mod p
    s_inv = mod_inv(s, p)
    m = (c2 * s_inv) % p
    
    # Décode le message : 1 -> 0, g -> 1
    if m == 1:
        return 0
    elif m == PARAM_G:
        return 1
    else:
        # Pour le vote, compte le nombre de g multiplié
        count = 0
        temp = 1
        while temp != m and count < PARAM_Q:
            temp = (temp * PARAM_G) % p
            count += 1
        if temp == m:
            return count
        raise ValueError("Déchiffrement invalide")

def EGA_encrypt(message: int, public_key: int, p: int = PARAM_P, g: int = PARAM_G) -> Tuple[int, int]:
    """
    Chiffre un message avec ElGamal (version additive)
    
    Args:
        message: Le message à chiffrer (doit être 0 ou 1)
        public_key: La clé publique du destinataire
        p: Le module premier
        g: Le générateur du groupe
        
    Returns:
        Tuple[int, int]: (c1, c2) le texte chiffré
    """
    if not validate_params():
        raise ValueError("Paramètres du groupe invalides")
    
    if message not in (0, 1):
        raise ValueError("Message invalide")
    
    # Encode le message : m -> g^m
    encoded = pow(g, message, p)
    
    # Génère un nombre aléatoire k
    k = randbelow(PARAM_Q-2) + 1
    
    # Calcule c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # Calcule c2 = g^m * y^k mod p
    c2 = (encoded * pow(public_key, k, p)) % p
    
    return c1, c2

def EGA_decrypt(private_key: int, c1: int, c2: int, p: int = PARAM_P, g: int = PARAM_G) -> int:
    """
    Déchiffre un message avec ElGamal (version additive)
    
    Args:
        private_key: La clé privée
        c1, c2: Le texte chiffré
        p: Le module premier
        g: Le générateur du groupe
        
    Returns:
        int: Le message déchiffré (0 ou 1)
    """
    if not validate_params():
        raise ValueError("Paramètres du groupe invalides")
    
    if not 0 < private_key < PARAM_Q:
        raise ValueError("Clé privée invalide")
    
    # Calcule s = c1^x mod p
    s = pow(c1, private_key, p)
    
    # Calcule m = c2 * s^(-1) mod p
    s_inv = mod_inv(s, p)
    m = (c2 * s_inv) % p
    
    # Décode le message en cherchant l'exposant
    # m = g^message mod p
    message = 0
    temp = 1
    while temp != m and message < PARAM_Q:
        message += 1
        temp = pow(g, message, p)
    
    if temp != m:
        raise ValueError("Déchiffrement invalide")
    
    return message

def EGM_decrypt(private_key: int, c1: int, c2: int, p: int = PARAM_P) -> int:
    """
    Déchiffre un message avec ElGamal (version multiplicative classique)
    
    Args:
        private_key: La clé privée
        c1, c2: Le texte chiffré
        p: Le module premier
        
    Returns:
        int: Le message déchiffré
    """
    if not validate_params():
        raise ValueError("Paramètres du groupe invalides")
    
    if not 0 < private_key < PARAM_Q:
        raise ValueError("Clé privée invalide")
    
    # Calcule s = c1^x mod p
    s = pow(c1, private_key, p)
    
    # Calcule m = c2 * s^(-1) mod p
    s_inv = mod_inv(s, p)
    m = (c2 * s_inv) % p
    
    return m
