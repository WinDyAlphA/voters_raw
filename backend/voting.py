from typing import List, Tuple, Dict
from dataclasses import dataclass
from secrets import randbelow
import json
from crypto_utils.rfc7748 import add
from crypto_utils.algebra import int_to_bytes

from ecelgamal import (
    ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt,
    p as EC_P, ORDER as EC_ORDER, BaseU, BaseV
)
from elgamal import (
    EG_generate_keys, EGM_encrypt, EG_decrypt,
    EGA_encrypt, EGA_decrypt,
    PARAM_P, PARAM_Q, PARAM_G
)
from ecdsa import (
    ECDSA_generate_keys, ECDSA_sign, ECDSA_verify,
    ORDER as ECDSA_ORDER
)
from dsa import (
    DSA_generate_keys, DSA_sign, DSA_verify,
    PARAM_Q as DSA_ORDER
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
    def __init__(self, use_ec: bool = True, use_multiplicative: bool = False, election_keys=None):
        """
        Initialise le système de vote
        
        Args:
            use_ec: Si True, utilise EC-ElGamal et ECDSA, sinon ElGamal et DSA
            use_multiplicative: Si True, utilise ElGamal multiplicatif, sinon additif
            election_keys: Clés de chiffrement pour l'élection
        """
        self.use_ec = use_ec
        self.use_multiplicative = use_multiplicative
        
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
        # Vérifie que le vote est valide (un seul 1, le reste des 0)
        vote = [1 if i == candidate else 0 for i in range(NUM_CANDIDATES)]
        if sum(vote) != 1:
            raise ValueError("Vote invalide: un seul candidat doit être choisi")
        return vote

    def encrypt_vote(self, vote_list: List[int], voter_id: int) -> Ballot:
        """Chiffre et signe un vote"""
        # Vérifie que la somme des votes est égale à 1
        if sum(vote_list) != 1:
            raise ValueError("Vote invalide: la somme doit être égale à 1")

        # Chiffre chaque élément du vote
        encrypted_votes = []
        for vote in vote_list:
            if self.use_ec:
                encrypted = ECEG_encrypt(vote, self.pub_key)
            else:
                if self.use_multiplicative:
                    # Encode 0 comme 1 et 1 comme g pour la version multiplicative
                    encoded_vote = PARAM_G if vote == 1 else 1
                    encrypted = EGM_encrypt(encoded_vote, self.pub_key)
                else:
                    encrypted = EGA_encrypt(vote, self.pub_key)
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
                if self.use_multiplicative:
                    result.append((1, 1))  # Élément neutre multiplicatif
                else:
                    result.append((1, 1))  # Même élément neutre pour additif

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
                    if self.use_multiplicative:
                        # Version multiplicative
                        c1 = (result[i][0] * ballot.encrypted_votes[i][0]) % PARAM_P
                        c2 = (result[i][1] * ballot.encrypted_votes[i][1]) % PARAM_P
                    else:
                        # Version additive
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
            else:
                if self.use_multiplicative:
                    decrypted = EG_decrypt(self.priv_key, encrypted[0], encrypted[1])
                else:
                    decrypted = EGA_decrypt(self.priv_key, encrypted[0], encrypted[1])
            results.append(decrypted)
        
        # Vérifie que le nombre total de votes est égal au nombre de votants
        total_votes = sum(results)
        if total_votes != NUM_VOTERS:
            raise ValueError(f"Nombre total de votes ({total_votes}) différent du nombre de votants ({NUM_VOTERS})")
                
        return results

def run_election(use_ec: bool = True, use_multiplicative: bool = False):
    """Exécute une élection complète"""
    # Initialise le système de vote
    system = VotingSystem(use_ec=use_ec, use_multiplicative=use_multiplicative)
    
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

def test_signatures():
    """
    Teste le système de signatures (ECDSA et DSA)
    """
    print("\nTest des signatures:")
    print("-" * 50)
    
    # Test avec ECDSA
    print("Test ECDSA:")
    system_ec = VotingSystem(use_ec=True)
    message = b"Test message for ECDSA"
    
    # Test pour chaque votant
    for voter_id in range(3):  # On teste avec 3 votants pour l'exemple
        # Crée et signe un vote
        vote = system_ec.create_vote(0)  # Vote pour le candidat 0
        ballot = system_ec.encrypt_vote(vote, voter_id)
        
        # Vérifie la signature
        is_valid = system_ec.verify_ballot(ballot)
        print(f"Votant {voter_id}: Signature {'valide' if is_valid else 'invalide'}")
        
        # Test avec une signature invalide
        invalid_ballot = Ballot(
            ballot.encrypted_votes,
            (ballot.signature[0], (ballot.signature[1] + 1) % ECDSA_ORDER),
            ballot.voter_id
        )
        is_valid = system_ec.verify_ballot(invalid_ballot)
        print(f"Votant {voter_id} (signature invalide): {'non détectée!' if is_valid else 'correctement rejetée'}")
    
    # Test avec DSA
    print("\nTest DSA:")
    system_dsa = VotingSystem(use_ec=False)
    message = b"Test message for DSA"
    
    # Test pour chaque votant
    for voter_id in range(3):
        # Crée et signe un vote
        vote = system_dsa.create_vote(0)
        ballot = system_dsa.encrypt_vote(vote, voter_id)
        
        # Vérifie la signature
        is_valid = system_dsa.verify_ballot(ballot)
        print(f"Votant {voter_id}: Signature {'valide' if is_valid else 'invalide'}")
        
        # Test avec une signature invalide
        invalid_ballot = Ballot(
            ballot.encrypted_votes,
            (ballot.signature[0], (ballot.signature[1] + 1) % DSA_ORDER),
            ballot.voter_id
        )
        is_valid = system_dsa.verify_ballot(invalid_ballot)
        print(f"Votant {voter_id} (signature invalide): {'non détectée!' if is_valid else 'correctement rejetée'}")

if __name__ == "__main__":
    # Tests avec les différentes versions
    print("\nTest avec EC-ElGamal:")
    results_ec = run_election(use_ec=True)
    
    print("\nTest avec ElGamal multiplicatif:")
    results_mult = run_election(use_ec=False, use_multiplicative=True)
    
    print("\nTest avec ElGamal additif:")
    results_add = run_election(use_ec=False, use_multiplicative=False)
    
    # Tests de signature
    test_signatures()
