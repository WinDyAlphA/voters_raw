import sqlite3
from typing import List, Tuple, Optional
from dataclasses import dataclass
import json
import pickle
from contextlib import contextmanager
import bcrypt

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
        
        # Table pour les utilisateurs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
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
        
        # Création de l'admin par défaut s'il n'existe pas déjà
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO users (username, password_hash, is_admin)
                VALUES (?, ?, ?)
            ''', (
                'admin',
                generate_password_hash('adminpass123'),
                True
            ))
            print("Compte administrateur créé :")
            print("Username: admin")
            print("Password: adminpass123")
        
        conn.commit()

def serialize_key(key) -> str:
    """Convertit une clé en chaîne hexadécimale"""
    if isinstance(key, tuple):
        # Pour les clés EC qui sont des tuples de coordonnées
        return f"ec,{key[0]:x},{key[1]:x}"
    # Pour les clés ElGamal qui sont des entiers
    return f"eg,{key:x}"

def deserialize_key(key_str: str):
    """Convertit une chaîne hexadécimale en clé"""
    parts = key_str.split(',')
    key_type = parts[0]
    
    if key_type == "ec":
        # Pour les clés EC
        return (int(parts[1], 16), int(parts[2], 16))
    else:
        # Pour les clés ElGamal
        return int(parts[1], 16)

def generate_password_hash(password: str) -> str:
    """Génère un hash sécurisé du mot de passe"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password_hash(stored_hash: str, password: str) -> bool:
    """Vérifie si le mot de passe correspond au hash"""
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

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
                # Sérialise la signature
                signature_str = json.dumps([serialize_key(s) for s in ballot.signature])
                # Sérialise la clé publique (qui peut être un tuple ou un int)
                public_key_str = serialize_key(ballot.public_key)
                
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
                # Désérialise la signature
                signature = tuple(
                    deserialize_key(s) for s in json.loads(row[2])
                )
                # Désérialise la clé publique
                public_key = deserialize_key(row[3])
                
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

    def create_user(self, username: str, password: str, is_admin: bool = False) -> bool:
        """Crée un nouvel utilisateur"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, is_admin)
                    VALUES (?, ?, ?)
                ''', (
                    username,
                    generate_password_hash(password),
                    is_admin
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> Optional[dict]:
        """Récupère les informations d'un utilisateur"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, password_hash, is_admin
                FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            return {
                "id": row[0],
                "username": row[1],
                "password_hash": row[2],
                "is_admin": bool(row[3])
            }

    def verify_password(self, username: str, password: str) -> bool:
        """Vérifie le mot de passe d'un utilisateur"""
        user = self.get_user(username)
        if not user:
            return False
        return check_password_hash(user["password_hash"], password) 