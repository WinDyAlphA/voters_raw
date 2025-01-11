import sqlite3
from typing import List, Tuple, Optional
from dataclasses import dataclass
import json
import pickle
from contextlib import contextmanager

class DatabaseError(Exception):
    """Exception personnalisée pour les erreurs de base de données"""
    pass

@contextmanager
def get_db_connection():
    """Gestionnaire de contexte pour la connexion à la base de données"""
    conn = sqlite3.connect('election.db')
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    """Initialise la base de données avec les tables nécessaires"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Table pour les élections
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS elections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            use_ec BOOLEAN NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ongoing',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Table pour les bulletins
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ballots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER,
            voter_id INTEGER,
            encrypted_votes TEXT NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (election_id) REFERENCES elections(id),
            UNIQUE (election_id, voter_id)
        )
        ''')
        
        conn.commit()

def serialize_key(key) -> str:
    """Convertit une clé en chaîne hexadécimale"""
    if isinstance(key, tuple):
        # Pour les clés EC qui sont des tuples de coordonnées
        return f"{key[0]:x},{key[1]:x}"
    # Pour les clés ElGamal qui sont des entiers
    return f"{key:x}"

def deserialize_key(key_str: str):
    """Convertit une chaîne hexadécimale en clé"""
    if ',' in key_str:
        # Pour les clés EC
        x, y = key_str.split(',')
        return (int(x, 16), int(y, 16))
    # Pour les clés ElGamal
    return int(key_str, 16)

class ElectionDatabase:
    def __init__(self):
        """Initialise la base de données"""
        init_database()
    
    def create_election(self, use_ec: bool, public_key, private_key) -> int:
        """Crée une nouvelle élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO elections (use_ec, public_key, private_key)
                VALUES (?, ?, ?)
            ''', (
                use_ec, 
                serialize_key(public_key), 
                serialize_key(private_key)
            ))
            conn.commit()
            return cursor.lastrowid
    
    def store_voter_keys(self, election_id: int, voter_keys: dict):
        """Stocke les clés des votants"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for voter_id, keys in voter_keys.items():
                cursor.execute('''
                    INSERT INTO voter_keys (election_id, voter_id, public_key, private_key)
                    VALUES (?, ?, ?, ?)
                ''', (
                    election_id,
                    voter_id,
                    pickle.dumps(keys["public"]),
                    pickle.dumps(keys["private"])
                ))
            conn.commit()
    
    def store_ballot(self, election_id: int, ballot) -> bool:
        """Stocke un bulletin de vote"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Sérialise les votes chiffrés
                encrypted_votes_str = json.dumps([
                    [serialize_key(c1), serialize_key(c2)]
                    for c1, c2 in ballot.encrypted_votes
                ])
                # Sérialise la signature et la clé publique
                signature_str = json.dumps([serialize_key(s) for s in ballot.signature])
                public_key_str = json.dumps([serialize_key(k) for k in ballot.public_key])
                
                cursor.execute('''
                    INSERT INTO ballots (
                        election_id, voter_id, encrypted_votes, 
                        signature, public_key
                    )
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    election_id,
                    ballot.voter_id,
                    encrypted_votes_str,
                    signature_str,
                    public_key_str
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
    
    def get_election(self, election_id: int) -> Optional[dict]:
        """Récupère les informations d'une élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, use_ec, public_key, private_key, status
                FROM elections WHERE id = ?
            ''', (election_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            return {
                "id": row[0],
                "use_ec": bool(row[1]),
                "public_key": deserialize_key(row[2]),
                "private_key": deserialize_key(row[3]),
                "status": row[4]
            }
    
    def get_voter_keys(self, election_id: int) -> dict:
        """Récupère les clés des votants pour une élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT voter_id, public_key, private_key
                FROM voter_keys WHERE election_id = ?
            ''', (election_id,))
            
            voter_keys = {}
            for row in cursor.fetchall():
                voter_keys[row[0]] = {
                    "public": pickle.loads(row[1]),
                    "private": pickle.loads(row[2])
                }
            return voter_keys
    
    def get_ballots(self, election_id: int) -> List:
        """Récupère tous les bulletins d'une élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT voter_id, encrypted_votes, signature, public_key
                FROM ballots WHERE election_id = ?
                ORDER BY timestamp
            ''', (election_id,))
            
            from voting import Ballot
            ballots = []
            for row in cursor.fetchall():
                # Désérialise les votes chiffrés
                encrypted_votes = [
                    (deserialize_key(c1), deserialize_key(c2))
                    for c1, c2 in json.loads(row[1])
                ]
                # Désérialise la signature et la clé publique
                signature = tuple(
                    deserialize_key(s) for s in json.loads(row[2])
                )
                public_key = tuple(
                    deserialize_key(k) for k in json.loads(row[3])
                )
                
                ballot = Ballot(
                    encrypted_votes=encrypted_votes,
                    signature=signature,
                    public_key=public_key,
                    voter_id=row[0]
                )
                ballots.append(ballot)
            return ballots
    
    def store_results(self, election_id: int, combined_votes, decrypted_results=None):
        """Cette méthode n'est plus nécessaire"""
        pass

    def get_results(self, election_id: int) -> Optional[dict]:
        """Cette méthode n'est plus nécessaire"""
        pass 