from typing import List, Tuple, Dict, Union
from dataclasses import dataclass
from secrets import randbelow
import json
from crypto_utils.rfc7748 import add
from crypto_utils.algebra import int_to_bytes
from config import NUM_VOTERS, NUM_CANDIDATES

from ecelgamal import (
    ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt,
    p as EC_P, ORDER as EC_ORDER, BaseU, BaseV
)
from elgamal import (
    EG_generate_keys, EGM_encrypt, EG_decrypt,
    PARAM_P, PARAM_Q, PARAM_G
)
from ecdsa import (
    ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
)
from dsa import (
    DSA_generate_keys, DSA_sign, DSA_verify
)
from database import ElectionDatabase

@dataclass
class Ballot:
    """Représente un bulletin de vote chiffré avec sa signature"""
    encrypted_votes: List[Tuple]  # Liste de 5 votes chiffrés
    signature: Tuple[int, int]    # Signature du bulletin (r, s)
    public_key: Union[Tuple[int, int], int]  # Clé publique éphémère (tuple pour EC, int pour ElGamal)
    voter_id: int                 # Identifiant du votant

class VotingSystem:
    def __init__(self, use_ec: bool = True, num_candidates: int = 2):
        """Initialise le système de vote"""
        self.use_ec = use_ec
        self.num_candidates = num_candidates
        self.db = ElectionDatabase()
        
        # Génère les clés de l'élection
        if use_ec:
            self.priv_key, self.pub_key = ECEG_generate_keys()
        else:
            self.priv_key, self.pub_key = EG_generate_keys()

    def create_vote(self, candidate: int) -> List[int]:
        """Crée un vote pour un candidat (liste de 0 et 1)"""
        if not 0 <= candidate < self.num_candidates:
            raise ValueError("Candidat invalide")
        # Vérifie que le vote est valide (un seul 1, le reste des 0)
        vote = [1 if i == candidate else 0 for i in range(self.num_candidates)]
        if sum(vote) != 1:
            raise ValueError("Vote invalide: un seul candidat doit être choisi")
        return vote

    def encrypt_vote(self, vote_list: List[int], voter_id: int) -> Ballot:
        """Chiffre et signe un vote"""
        # Vérifie que la somme des votes est égale à 1
        if sum(vote_list) != 1:
            raise ValueError("Vote invalide: la somme doit être égale à 1")

        # Chiffre chaque élément du vote avec la clé publique de l'élection
        encrypted_votes = []
        for vote in vote_list:
            if self.use_ec:
                encrypted = ECEG_encrypt(vote, self.pub_key)
            else:
                encrypted = EGM_encrypt(vote, self.pub_key)
            encrypted_votes.append(encrypted)

        # Génère une paire de clés éphémère pour la signature
        if self.use_ec:
            priv_key, pub_key = ECDSA_generate_keys()
        else:
            priv_key, pub_key = DSA_generate_keys()

        # Crée un message à signer
        message = b""
        for encrypted in encrypted_votes:
            if self.use_ec:
                message += int_to_bytes(encrypted[0][0]) + int_to_bytes(encrypted[0][1])
                message += int_to_bytes(encrypted[1][0]) + int_to_bytes(encrypted[1][1])
            else:
                message += int_to_bytes(encrypted[0]) + int_to_bytes(encrypted[1])

        # Signe avec la clé éphémère
        if self.use_ec:
            signature = ECDSA_sign(message, priv_key)
        else:
            signature = DSA_sign(message, priv_key)
            # Pour ElGamal classique, s'assurer que la signature est un tuple
            if not isinstance(signature, tuple):
                signature = (signature, 0)  # ou une autre façon de formater la signature

        return Ballot(
            encrypted_votes=encrypted_votes,
            signature=signature,
            public_key=pub_key,  # pub_key est soit un tuple (EC) soit un int (ElGamal)
            voter_id=voter_id
        )

    def verify_ballot(self, ballot: Ballot) -> bool:
        """Vérifie la signature d'un bulletin"""
        message = b""
        for encrypted in ballot.encrypted_votes:
            if self.use_ec:
                message += int_to_bytes(encrypted[0][0]) + int_to_bytes(encrypted[0][1])
                message += int_to_bytes(encrypted[1][0]) + int_to_bytes(encrypted[1][1])
            else:
                message += int_to_bytes(encrypted[0]) + int_to_bytes(encrypted[1])

        pub_key = self.voter_keys[ballot.voter_id]["public"]
        
        if self.use_ec:
            return ECDSA_verify(message, ballot.signature, pub_key)
        else:
            return DSA_verify(message, ballot.signature, pub_key)

    def homomorphic_combine(self, cipher1: Tuple, cipher2: Tuple) -> Tuple:
        """
        Combine deux chiffrés en utilisant la propriété homomorphique
        
        Args:
            cipher1: Premier chiffré (c1, c2)
            cipher2: Second chiffré (c1, c2)
            
        Returns:
            Tuple: Chiffré combiné représentant la somme (EC-ElGamal) 
            ou le produit (ElGamal classique) des messages
        """
        if self.use_ec:
            # Addition de points pour EC-ElGamal
            c1 = add(cipher1[0][0], cipher1[0][1], 
                    cipher2[0][0], cipher2[0][1], EC_P)
            c2 = add(cipher1[1][0], cipher1[1][1],
                    cipher2[1][0], cipher2[1][1], EC_P)
        else:
            # Multiplication modulaire pour ElGamal classique
            c1 = (cipher1[0] * cipher2[0]) % PARAM_P
            c2 = (cipher1[1] * cipher2[1]) % PARAM_P
        
        return (c1, c2)

    def combine_encrypted_votes(self, ballots: List[Ballot]) -> List[Tuple]:
        """Combine les votes chiffrés en utilisant la propriété homomorphique"""
        if not ballots:
            raise ValueError("Aucun bulletin à combiner")
            
        # Vérifie d'abord toutes les signatures
        for ballot in ballots:
            message = b""
            for encrypted in ballot.encrypted_votes:
                if self.use_ec:
                    message += int_to_bytes(encrypted[0][0]) + int_to_bytes(encrypted[0][1])
                    message += int_to_bytes(encrypted[1][0]) + int_to_bytes(encrypted[1][1])
                else:
                    message += int_to_bytes(encrypted[0]) + int_to_bytes(encrypted[1])

            # Vérifie la signature avec la clé publique éphémère
            if self.use_ec:
                if not ECDSA_verify(message, ballot.signature, ballot.public_key):
                    raise ValueError(f"Signature invalide pour le votant {ballot.voter_id}")
            else:
                if not DSA_verify(message, ballot.signature, ballot.public_key):
                    raise ValueError(f"Signature invalide pour le votant {ballot.voter_id}")

        # Initialise le résultat avec des éléments neutres
        result = []
        for _ in range(NUM_CANDIDATES):
            if self.use_ec:
                result.append(((1, 0), (1, 0)))  # Point neutre pour EC
            else:
                result.append((1, 1))  # Élément neutre pour la multiplication

        # Combine tous les bulletins
        for ballot in ballots:
            for i in range(NUM_CANDIDATES):
                if result[i][0] == (1, 0):  # Premier vote pour ce candidat
                    result[i] = ballot.encrypted_votes[i]
                else:
                    result[i] = self.homomorphic_combine(
                        result[i], 
                        ballot.encrypted_votes[i]
                    )
        
        return result

    def decrypt_result(self, combined_votes: List[Tuple]) -> List[int]:
        """Déchiffre le résultat final"""
        results = []
        for encrypted in combined_votes:
            if self.use_ec:
                decrypted = ECEG_decrypt(self.priv_key, encrypted[0], encrypted[1])
            else:
                decrypted = EG_decrypt(self.priv_key, encrypted[0], encrypted[1])
            results.append(decrypted)
        
        # Ne vérifie plus le nombre total de votes
        return results

def run_election(use_ec: bool = True):
    """Exécute une élection complète"""
    # Initialise le système de vote
    system = VotingSystem(use_ec=use_ec)
    
    # Simule les votes
    ballots = []
    for voter_id in range(NUM_VOTERS):
        # Choix aléatoire d'un candidat
        candidate = randbelow(NUM_CANDIDATES)
        vote = system.create_vote(candidate)
        ballot = system.encrypt_vote(vote, voter_id)
        ballots.append(ballot)
    
    # Combine les votes
    combined = system.combine_encrypted_votes(ballots)
    
    # Déchiffre et affiche les résultats
    results = system.decrypt_result(combined)
    
    print(f"Résultats de l'élection ({'EC-ElGamal' if use_ec else 'ElGamal'}):")
    for i, count in enumerate(results):
        print(f"Candidat {i+1}: {count} votes")
    
    return results 

if __name__ == "__main__":
    results_ec = run_election(use_ec=True)
    results_ec = run_election(use_ec=False)
