from crypto_utils.algebra import mod_inv
from Crypto.Hash import SHA256, HMAC
from secrets import randbelow
from typing import Tuple
from crypto_utils.algebra import int_to_bytes

## parameters from MODP Group 24 -- Extracted from RFC 5114
PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def validate_params() -> bool:
    """
    Vérifie que les paramètres DSA sont valides
    """
    if PARAM_P < 2 or PARAM_Q < 2:
        return False
    
    if PARAM_G <= 1 or PARAM_G >= PARAM_P:
        return False
    
    # Vérifie que g^q ≡ 1 (mod p)
    if pow(PARAM_G, PARAM_Q, PARAM_P) != 1:
        return False
        
    return True

def H(message: bytes) -> int:
    """
    Fonction de hachage SHA-256 pour DSA
    
    Args:
        message: Le message à hacher
        
    Returns:
        int: Le hash du message
    """
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

def bits2int(bits: bytes, qlen: int) -> int:
    """
    Convertit une séquence d'octets en entier
    
    Args:
        bits: Les octets à convertir
        qlen: La taille en bits de l'ordre du groupe
        
    Returns:
        int: L'entier résultant
    """
    ret = int.from_bytes(bits, byteorder='big')
    # Tronque si nécessaire
    if len(bits) * 8 > qlen:
        ret = ret >> (len(bits) * 8 - qlen)
    return ret

def bits2octets(bits: bytes, q: int, qlen: int) -> bytes:
    """
    Convertit des bits en octets modulo q
    
    Args:
        bits: Les bits à convertir
        q: Le module
        qlen: La taille en bits de q
        
    Returns:
        bytes: Les octets résultants
    """
    z1 = bits2int(bits, qlen)
    z2 = z1 % q
    return int_to_bytes(z2)

def DSA_generate_nonce(private_key: int, message: bytes, q: int = PARAM_Q) -> int:
    """
    Génère un nonce k pour DSA de manière déterministe selon RFC 6979
    
    Args:
        private_key: La clé privée
        message: Le message à signer
        q: L'ordre du sous-groupe
        
    Returns:
        int: Le nonce k
    """
    # 1. Calcule h1 = H(message)
    h1 = H(message)
    
    # Calcule la taille en bits de q
    qlen = q.bit_length()
    
    # 2. Convertit la clé privée en octets
    x = int_to_bytes(private_key)
    
    # 3. Convertit h1 en octets
    h1_bytes = int_to_bytes(h1)
    
    # 4. Initialise
    v = b'\x01' * 32  # SHA256 produit 32 octets
    k = b'\x00' * 32
    
    # 5. Calcule K = HMAC_K(V || 0x00 || x || h1)
    k = HMAC.new(k, v + b'\x00' + x + h1_bytes, SHA256).digest()
    
    # 6. Calcule V = HMAC_K(V)
    v = HMAC.new(k, v, SHA256).digest()
    
    # 7. Calcule K = HMAC_K(V || 0x01 || x || h1)
    k = HMAC.new(k, v + b'\x01' + x + h1_bytes, SHA256).digest()
    
    # 8. Calcule V = HMAC_K(V)
    v = HMAC.new(k, v, SHA256).digest()
    
    # 9. Génère T
    while True:
        t = b''
        while len(t) * 8 < qlen:
            v = HMAC.new(k, v, SHA256).digest()
            t += v
            
        # Convertit T en un nonce
        nonce = bits2int(t, qlen)
        
        # Vérifie que le nonce est valide
        if 0 < nonce < q:
            return nonce
            
        # Si non valide, continue avec K = HMAC_K(V || 0x00)
        k = HMAC.new(k, v + b'\x00', SHA256).digest()
        v = HMAC.new(k, v, SHA256).digest()

def DSA_generate_keys(p: int = PARAM_P, q: int = PARAM_Q, g: int = PARAM_G) -> Tuple[int, int]:
    """
    Génère une paire de clés DSA
    
    Args:
        p: Le module premier
        q: L'ordre du sous-groupe
        g: Le générateur
        
    Returns:
        Tuple[int, int]: (clé privée, clé publique)
        
    Raises:
        ValueError: Si les paramètres sont invalides
    """
    if not validate_params():
        raise ValueError("Paramètres DSA invalides")
    
    # Génère la clé privée x dans [1, q-1]
    private_key = randbelow(q-2) + 1
    
    # Calcule la clé publique y = g^x mod p
    public_key = pow(g, private_key, p)
    
    return private_key, public_key

def DSA_sign(message: bytes, private_key: int) -> Tuple[int, int]:
    """
    Signe un message avec DSA
    """
    if not 0 < private_key < PARAM_Q:
        raise ValueError("Clé privée invalide")
    
    # Calcule le hash du message
    h = H(message)
    
    while True:
        # Génère un nonce k de manière déterministe
        k = DSA_generate_nonce(private_key, message)
        
        # Calcule r = (g^k mod p) mod q
        r = pow(PARAM_G, k, PARAM_P) % PARAM_Q
        if r == 0:
            continue
        
        # Calcule s = k^(-1)(h + x*r) mod q
        k_inv = mod_inv(k, PARAM_Q)
        s = (k_inv * (h + private_key * r)) % PARAM_Q
        if s == 0:
            continue
            
        return r, s

def DSA_verify(message: bytes, signature: Tuple[int, int], public_key: int, 
               p: int = PARAM_P, q: int = PARAM_Q, g: int = PARAM_G) -> bool:
    """
    Vérifie une signature DSA
    
    Args:
        message: Le message signé
        signature: La signature (r, s)
        public_key: La clé publique
        p, q, g: Les paramètres DSA
        
    Returns:
        bool: True si la signature est valide
    """
    if not validate_params():
        raise ValueError("Paramètres DSA invalides")
    
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        raise ValueError("Signature invalide")
    
    if not 0 < public_key < p:
        raise ValueError("Clé publique invalide")
    
    # Calcule le hash du message et le réduit modulo q
    h = H(message) % q
    
    # Calcule w = s^(-1) mod q
    w = mod_inv(s, q)
    
    # Calcule u1 = hw mod q
    u1 = (h * w) % q
    
    # Calcule u2 = rw mod q
    u2 = (r * w) % q
    
    # Calcule v = ((g^u1 * y^u2) mod p) mod q
    v = ((pow(g, u1, p) * pow(public_key, u2, p)) % p) % q
    
    # Vérifie si v = r
    return v == r
