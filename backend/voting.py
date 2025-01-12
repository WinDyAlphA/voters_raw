from typing import List, Tuple, Dict, Union
from dataclasses import dataclass
from secrets import randbelow
import json
from crypto_utils.rfc7748 import add
from crypto_utils.algebra import int_to_bytes
from config import NUM_VOTERS, NUM_CANDIDATES
from models import Ballot

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

class VotingSystem:
    def __init__(self, use_ec: bool = True, num_candidates: int = 2):
        """Initialise le système de vote"""
        self.use_ec = use_ec
        self.num_candidates = num_candidates
        self.db = ElectionDatabase()
        
        # Génère UNE SEULE paire de clés pour toute l'élection
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
        if sum(vote_list) != 1:
            raise ValueError("Vote invalide: la somme doit être égale à 1")

        # Utilise la clé publique de l'élection pour chiffrer
        encrypted_votes = []
        for vote in vote_list:
            if self.use_ec:
                encrypted = ECEG_encrypt(vote, self.pub_key)
            else:
                encrypted = EGM_encrypt(vote, self.pub_key)
            encrypted_votes.append(encrypted)

        # Génère une paire de clés éphémère UNIQUEMENT pour la signature
        if self.use_ec:
            sig_priv_key, sig_pub_key = ECDSA_generate_keys()
        else:
            sig_priv_key, sig_pub_key = DSA_generate_keys()

        # Signe avec la clé éphémère
        message = b""
        for encrypted in encrypted_votes:
            if self.use_ec:
                message += int_to_bytes(encrypted[0][0]) + int_to_bytes(encrypted[0][1])
                message += int_to_bytes(encrypted[1][0]) + int_to_bytes(encrypted[1][1])
            else:
                message += int_to_bytes(encrypted[0]) + int_to_bytes(encrypted[1])

        if self.use_ec:
            signature = ECDSA_sign(message, sig_priv_key)
        else:
            signature = DSA_sign(message, sig_priv_key)

        return Ballot(
            encrypted_votes=encrypted_votes,
            signature=signature,
            public_key=sig_pub_key,  # Uniquement pour vérifier la signature
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
        """Combine deux chiffrés homomorphiquement"""
        if self.use_ec:
            # Pour EC-ElGamal, on additionne les points composante par composante
            c1 = add(cipher1[0][0], cipher1[0][1], cipher2[0][0], cipher2[0][1], EC_P)
            c2 = add(cipher1[1][0], cipher1[1][1], cipher2[1][0], cipher2[1][1], EC_P)
            return (c1, c2)
        else:
            # Pour ElGamal classique, on multiplie les composantes
            c1 = (cipher1[0] * cipher2[0]) % PARAM_P
            c2 = (cipher1[1] * cipher2[1]) % PARAM_P
            return (c1, c2)

    def combine_encrypted_votes(self, ballots: List[Ballot]) -> List[Tuple]:
        """Combine les votes chiffrés"""
        if not ballots:
            return []
        
        # Initialise avec le premier bulletin
        result = ballots[0].encrypted_votes
        
        # Combine avec les bulletins suivants
        for ballot in ballots[1:]:
            for i, (vote, current) in enumerate(zip(ballot.encrypted_votes, result)):
                # Pour EC-ElGamal, additionne les points
                if self.use_ec:
                    result[i] = (
                        add(vote[0][0], vote[0][1], current[0][0], current[0][1], EC_P),
                        add(vote[1][0], vote[1][1], current[1][0], current[1][1], EC_P)
                    )
                else:
                    result[i] = (
                        (vote[0] * current[0]) % PARAM_P,
                        (vote[1] * current[1]) % PARAM_P
                    )
        
        return result

    def decrypt_result(self, combined_votes: List[Tuple]) -> List[int]:
        """Déchiffre le résultat final"""
        print("Début du déchiffrement...")
        results = []
        
        # Pour chaque paire de votes combinés
        for i, encrypted in enumerate(combined_votes):
            print(f"Déchiffrement du vote {i+1}/{len(combined_votes)}")
            
            try:
                if self.use_ec:
                    decrypted = ECEG_decrypt(self.priv_key, encrypted[0], encrypted[1])
                else:
                    decrypted = EG_decrypt(self.priv_key, encrypted[0], encrypted[1])
                    
                print(f"Vote {i+1} déchiffré avec succès : {decrypted}")
                results.append(decrypted)
                
            except Exception as e:
                print(f"Erreur lors du déchiffrement : {str(e)}")
                raise
        
        print(f"Déchiffrement terminé. Résultats : {results}")
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
