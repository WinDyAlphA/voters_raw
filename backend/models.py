from dataclasses import dataclass
from typing import List, Tuple, Union

@dataclass
class Ballot:
    """Représente un bulletin de vote chiffré avec sa signature"""
    encrypted_votes: List[Tuple]  # Liste de votes chiffrés
    signature: Tuple[int, int]    # Signature du bulletin (r, s)
    public_key: Union[Tuple[int, int], int]  # Clé publique éphémère (tuple pour EC, int pour ElGamal)
    voter_id: int                 # Identifiant du votant 