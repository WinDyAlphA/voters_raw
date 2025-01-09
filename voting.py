from typing import List, Tuple, Dict
from dataclasses import dataclass
from secrets import randbelow
import json
from rfc7748 import add
from algebra import int_to_bytes

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

NUM_VOTERS = 10
NUM_CANDIDATES = 5

@dataclass
class Ballot:
    """Représente un bulletin de vote chiffré avec sa signature"""
    encrypted_votes: List[Tuple]  # Liste de 5 votes chiffrés
    signature: Tuple[int, int]    # Signature du bulletin
    voter_id: int                 # Identifiant du votant

class VotingSystem:
    def __init__(self, use_ec: bool = True, election_keys=None):
        """
        Initialise le système de vote
        
        Args:
            use_ec: Si True, utilise EC-ElGamal et ECDSA, sinon ElGamal et DSA
            election_keys: Clés de chiffrement pour l'élection (si None, en génère de nouvelles)
        """
        self.use_ec = use_ec
        
        # Génère ou utilise les clés de l'élection
        if election_keys is None:
            if use_ec:
                self.priv_key, self.pub_key = ECEG_generate_keys()
            else:
                self.priv_key, self.pub_key = EG_generate_keys()
        else:
            self.priv_key, self.pub_key = election_keys
            
        # Génère les clés de signature pour chaque votant
        self.voter_keys = {}
        for i in range(NUM_VOTERS):
            if use_ec:
                priv, pub = ECDSA_generate_keys()
            else:
                priv, pub = DSA_generate_keys()
            self.voter_keys[i] = {"private": priv, "public": pub}

    def create_vote(self, candidate: int) -> List[int]:
        """Crée un vote pour un candidat (liste de 0 et 1)"""
        if not 0 <= candidate < NUM_CANDIDATES:
            raise ValueError("Candidat invalide")
        return [1 if i == candidate else 0 for i in range(NUM_CANDIDATES)]

    def encrypt_vote(self, vote_list: List[int], voter_id: int) -> Ballot:
        """Chiffre et signe un vote"""
        # Chiffre chaque élément du vote
        encrypted_votes = []
        for vote in vote_list:
            if self.use_ec:
                encrypted = ECEG_encrypt(vote, self.pub_key)
            else:
                encrypted = EGM_encrypt(vote, self.pub_key)
            encrypted_votes.append(encrypted)

        # Crée un message à signer
        message = b""
        for encrypted in encrypted_votes:
            if self.use_ec:
                # Pour EC-ElGamal, encrypted[0] et encrypted[1] sont des tuples (x,y)
                message += int_to_bytes(encrypted[0][0]) + int_to_bytes(encrypted[0][1])
                message += int_to_bytes(encrypted[1][0]) + int_to_bytes(encrypted[1][1])
            else:
                # Pour ElGamal classique, encrypted[0] et encrypted[1] sont des entiers
                message += int_to_bytes(encrypted[0]) + int_to_bytes(encrypted[1])

        # Signe le bulletin
        if self.use_ec:
            signature = ECDSA_sign(message, self.voter_keys[voter_id]["private"])
        else:
            signature = DSA_sign(message, self.voter_keys[voter_id]["private"])

        return Ballot(encrypted_votes, signature, voter_id)

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

    def combine_encrypted_votes(self, ballots: List[Ballot]) -> List[Tuple]:
        """Combine les votes chiffrés en utilisant la propriété homomorphique"""
        if not ballots:
            raise ValueError("Aucun bulletin à combiner")
            
        # Vérifie d'abord toutes les signatures
        for ballot in ballots:
            if not self.verify_ballot(ballot):
                raise ValueError(f"Signature invalide pour le votant {ballot.voter_id}")

        # Initialise le résultat avec le premier bulletin
        result = []
        for i in range(NUM_CANDIDATES):
            if self.use_ec:
                result.append(((1, 0), (1, 0)))  # Point neutre pour EC
            else:
                result.append((1, 1))  # Élément neutre pour la multiplication

        # Combine tous les bulletins
        for ballot in ballots:
            for i in range(NUM_CANDIDATES):
                if self.use_ec:
                    # Addition de points pour EC-ElGamal
                    if result[i][0] == (1, 0):
                        result[i] = (ballot.encrypted_votes[i][0], ballot.encrypted_votes[i][1])
                    else:
                        c1 = add(result[i][0][0], result[i][0][1], 
                                ballot.encrypted_votes[i][0][0], 
                                ballot.encrypted_votes[i][0][1], EC_P)
                        c2 = add(result[i][1][0], result[i][1][1],
                                ballot.encrypted_votes[i][1][0],
                                ballot.encrypted_votes[i][1][1], EC_P)
                        result[i] = (c1, c2)
                else:
                    # Multiplication modulaire pour ElGamal
                    c1 = (result[i][0] * ballot.encrypted_votes[i][0]) % PARAM_P
                    c2 = (result[i][1] * ballot.encrypted_votes[i][1]) % PARAM_P
                    result[i] = (c1, c2)
                    
        return result

    def decrypt_result(self, combined_votes: List[Tuple]) -> List[int]:
        """Déchiffre le résultat final"""
        results = []
        for encrypted in combined_votes:
            if self.use_ec:
                decrypted = ECEG_decrypt(self.priv_key, encrypted[0], encrypted[1])
                results.append(decrypted)
            else:
                decrypted = EG_decrypt(self.priv_key, encrypted[0], encrypted[1])
                results.append(decrypted)
                
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

results_ec = run_election(use_ec=True)
results_ec = run_election(use_ec=False)
