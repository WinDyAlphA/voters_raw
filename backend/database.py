import sqlite3
from typing import List, Tuple, Optional
from dataclasses import dataclass
import json
import pickle
from contextlib import contextmanager
import bcrypt
import secrets
import string
from config import NUM_VOTERS
from voting import Ballot
from models import Ballot  # Nouvel import

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
        
        # Table pour les codes d'invitation
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS invitation_codes (
            code TEXT PRIMARY KEY,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_by INTEGER DEFAULT NULL,
            used_at TIMESTAMP DEFAULT NULL,
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (used_by) REFERENCES users(id)
        )
        ''')
        
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
            name TEXT NOT NULL,
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
        
        # Table pour les candidats
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS candidates (
            election_id INTEGER,
            candidate_id INTEGER,
            name TEXT NOT NULL,
            PRIMARY KEY (election_id, candidate_id),
            FOREIGN KEY (election_id) REFERENCES elections(id)
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
        return f"ec,{hex(key[0])[2:]},{hex(key[1])[2:]}"  # Enlève le préfixe '0x'
    # Pour les clés ElGamal qui sont des entiers
    return f"eg,{hex(key)[2:]}"  # Enlève le préfixe '0x'

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
    
    def create_election(self, name: str, use_ec: bool, public_key, private_key, candidates: List[str]) -> int:
        """Crée une nouvelle élection avec UNE SEULE paire de clés"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO elections (name, use_ec, public_key, private_key)
                VALUES (?, ?, ?, ?)
            ''', (
                name,
                use_ec, 
                serialize_key(public_key),  # Une seule clé publique pour l'élection
                serialize_key(private_key)  # Une seule clé privée pour l'élection
            ))
            election_id = cursor.lastrowid
            
            # Ajoute les candidats
            for i, name in enumerate(candidates):
                cursor.execute('''
                    INSERT INTO candidates (election_id, candidate_id, name)
                    VALUES (?, ?, ?)
                ''', (election_id, i, name))
            
            conn.commit()
            return election_id
    
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
                
                # Debug
                print("Signature reçue:", ballot.signature)
                print("Type de signature:", type(ballot.signature))
                
                # Sérialise les votes chiffrés en format JSON
                if isinstance(ballot.encrypted_votes[0][0], tuple):  # EC-ElGamal
                    encrypted_votes_str = json.dumps([
                        [
                            [str(c1[0]), str(c1[1])],
                            [str(c2[0]), str(c2[1])]
                        ]
                        for c1, c2 in ballot.encrypted_votes
                    ])
                else:  # ElGamal classique
                    encrypted_votes_str = json.dumps([
                        [str(c1), str(c2)]
                        for c1, c2 in ballot.encrypted_votes
                    ])
                
                # Sérialise la signature
                # Vérifie si la signature est déjà en format hex
                if isinstance(ballot.signature[0], str) and all(c in '0123456789abcdefABCDEF' for c in ballot.signature[0]):
                    signature_str = json.dumps(ballot.signature)
                else:
                    signature_str = json.dumps([str(s) for s in ballot.signature])
                
                # Debug
                print("Signature sérialisée:", signature_str)
                
                # Sérialise la clé publique
                if isinstance(ballot.public_key, tuple):  # EC-ElGamal
                    public_key_str = f"ec,{ballot.public_key[0]},{ballot.public_key[1]}"
                else:  # ElGamal classique
                    public_key_str = f"eg,{ballot.public_key}"
                
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
                SELECT id, name, use_ec, public_key, private_key, status
                FROM elections
                WHERE id = ?
            ''', (election_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            # Désérialise les clés correctement
            pub_key_str = row[3]
            priv_key_str = row[4]
            
            # Les clés sont stockées au format "ec,x,y" pour EC-ElGamal
            # ou "eg,k" pour ElGamal classique
            if row[2]:  # use_ec
                _, x, y = pub_key_str.split(',')
                public_key = (int(x, 16), int(y, 16))  # Conversion depuis hex
                _, priv = priv_key_str.split(',')
                private_key = int(priv, 16)  # Conversion depuis hex
            else:
                _, pub = pub_key_str.split(',')
                _, priv = priv_key_str.split(',')
                public_key = int(pub, 16)  # Conversion depuis hex
                private_key = int(priv, 16)  # Conversion depuis hex
            
            return {
                "id": row[0],
                "name": row[1],
                "use_ec": bool(row[2]),
                "public_key": public_key,
                "private_key": private_key,
                "status": row[5]
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
    
    def get_ballots(self, election_id: int) -> List[Ballot]:
        """Récupère tous les bulletins d'une élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT voter_id, encrypted_votes, signature, public_key
                FROM ballots
                WHERE election_id = ?
            ''', (election_id,))
            
            ballots = []
            for row in cursor.fetchall():
                try:
                    # Désérialise les votes chiffrés
                    encrypted_votes = json.loads(row[1])
                    if isinstance(encrypted_votes[0][0], list):  # EC-ElGamal
                        encrypted_votes = [
                            (
                                (int(v[0][0]), int(v[0][1])),
                                (int(v[1][0]), int(v[1][1]))
                            )
                            for v in encrypted_votes
                        ]
                    else:  # ElGamal classique
                        encrypted_votes = [
                            (int(v[0]), int(v[1]))
                            for v in encrypted_votes
                        ]
                    
                    # Désérialise la signature
                    signature_raw = json.loads(row[2])
                    # La signature est toujours en hexadécimal
                    signature = tuple(int(s, 16) for s in signature_raw)
                    
                    # Désérialise la clé publique
                    pub_key_str = row[3]
                    if pub_key_str.startswith('ec,'):  # EC-ElGamal
                        _, x, y = pub_key_str.split(',')
                        public_key = (int(x), int(y))
                    else:  # ElGamal classique
                        _, key = pub_key_str.split(',')
                        public_key = int(key)
                    
                    ballot = Ballot(
                        encrypted_votes=encrypted_votes,
                        signature=signature,
                        public_key=public_key,
                        voter_id=row[0]
                    )
                    ballots.append(ballot)
                except Exception as e:
                    print(f"Erreur lors de la désérialisation du bulletin: {e}")
                    print(f"Données brutes: {row}")
                    raise
            
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

    def generate_invitation_code(self, admin_id: int) -> str:
        """Génère un nouveau code d'invitation"""
        # Génère un code aléatoire de 32 caractères
        alphabet = string.ascii_letters + string.digits
        code = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO invitation_codes (code, created_by)
                VALUES (?, ?)
            ''', (code, admin_id))
            conn.commit()
        return code

    def verify_invitation_code(self, code: str) -> bool:
        """Vérifie si un code d'invitation est valide"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT used_by FROM invitation_codes
                WHERE code = ?
            ''', (code,))
            row = cursor.fetchone()
            
            if not row:
                return False  # Code n'existe pas
            
            return row[0] is None  # Code existe et n'a pas été utilisé

    def use_invitation_code(self, code: str, user_id: int) -> bool:
        """Marque un code d'invitation comme utilisé"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE invitation_codes
                    SET used_by = ?, used_at = CURRENT_TIMESTAMP
                    WHERE code = ? AND used_by IS NULL
                ''', (user_id, code))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False 

    def get_elections(self, current_user_id: int) -> List[dict]:
        """Récupère la liste des élections avec leurs statistiques"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    e.id,
                    e.name,
                    e.status,
                    e.created_at,
                    COUNT(b.id) as total_votes,
                    EXISTS(
                        SELECT 1 FROM ballots b2 
                        WHERE b2.election_id = e.id 
                        AND b2.voter_id = ?
                    ) as has_voted
                FROM elections e
                LEFT JOIN ballots b ON e.id = b.election_id
                GROUP BY e.id
                ORDER BY e.created_at DESC
            ''', (current_user_id,))
            
            elections = []
            for row in cursor.fetchall():
                elections.append({
                    "id": row[0],
                    "name": row[1],
                    "status": row[2],
                    "created_at": row[3],
                    "total_votes": row[4] if row[4] else 0,
                    "has_voted": bool(row[5])
                })
            return elections

    def get_candidates(self, election_id: int) -> List[dict]:
        """Récupère les candidats d'une élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT candidate_id, name
                FROM candidates
                WHERE election_id = ?
                ORDER BY candidate_id
            ''', (election_id,))
            
            return [
                {"id": row[0], "name": row[1]}
                for row in cursor.fetchall()
            ] 

    def get_all_elections(self) -> List[dict]:
        """Récupère toutes les élections pour l'admin"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    e.id,
                    e.name,
                    e.status,
                    e.created_at,
                    COUNT(b.id) as total_votes
                FROM elections e
                LEFT JOIN ballots b ON e.id = b.election_id
                GROUP BY e.id
                ORDER BY e.created_at DESC
            ''')
            
            elections = []
            for row in cursor.fetchall():
                elections.append({
                    "id": row[0],
                    "name": row[1],
                    "status": row[2],
                    "created_at": row[3],
                    "total_votes": row[4] if row[4] else 0
                })
            return elections

    def close_election(self, election_id: int) -> bool:
        """Ferme une élection"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE elections
                SET status = 'completed'
                WHERE id = ? AND status = 'ongoing'
            ''', (election_id,))
            conn.commit()
            return cursor.rowcount > 0

def reset_database():
    """Supprime et réinitialise la base de données"""
    import os
    if os.path.exists('election.db'):
        os.remove('election.db')
    init_database() 