import requests
import json
from typing import Dict, Any

BASE_URL = "http://localhost:8000"

def print_response(response: requests.Response):
    """Affiche la réponse de l'API de manière formatée"""
    print("\nStatut:", response.status_code)
    try:
        print("Réponse:", json.dumps(response.json(), indent=2, ensure_ascii=False))
    except:
        print("Réponse:", response.text)
    print("-" * 50)

def make_request(method: str, endpoint: str, data: Dict[str, Any] = None, token: str = None) -> requests.Response:
    """Effectue une requête à l'API"""
    url = f"{BASE_URL}/{endpoint}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        else:
            raise ValueError(f"Méthode HTTP non supportée: {method}")
            
        return response
    
    except requests.exceptions.ConnectionError:
        print(f"Erreur: Impossible de se connecter à {url}")
        print("Assurez-vous que l'API est en cours d'exécution")
        exit(1)

def test_auth():
    """Test des fonctionnalités d'authentification"""
    print("\n=== Test de l'authentification ===\n")
    
    # 1. Création d'un utilisateur normal
    print("1. Création d'un utilisateur normal")
    response = make_request("POST", "auth/register", {
        "username": "user1",
        "password": "password123"
    })
    print_response(response)
    
    # 2. Tentative de création d'un utilisateur avec le même nom
    print("\n2. Tentative de création d'un utilisateur avec le même nom")
    response = make_request("POST", "auth/register", {
        "username": "user1",
        "password": "autrepassword"
    })
    print_response(response)
    
    # 3. Connexion avec mauvais mot de passe
    print("\n3. Tentative de connexion avec mauvais mot de passe")
    response = make_request("POST", "auth/login", {
        "username": "user1",
        "password": "wrongpassword"
    })
    print_response(response)
    
    # 4. Connexion réussie
    print("\n4. Connexion réussie")
    response = make_request("POST", "auth/login", {
        "username": "user1",
        "password": "password123"
    })
    print_response(response)
    
    if response.status_code == 200:
        token = response.json()["access_token"]
        
        # 5. Test d'accès à une route protégée
        print("\n5. Test d'accès à une route protégée (status)")
        response = make_request("GET", "election/status", token=token)
        print_response(response)
        
        # 6. Test d'accès à une route admin sans droits
        print("\n6. Test d'accès à une route admin sans droits")
        response = make_request("POST", "election/init", 
                              data={"use_ec": True}, 
                              token=token)
        print_response(response)
    
    # 7. Création d'un admin (à faire manuellement en production!)
    print("\n7. Création d'un compte admin")
    response = make_request("POST", "auth/register", {
        "username": "admin",
        "password": "adminpass123"
    })
    print_response(response)
    
    # 8. Connexion admin
    print("\n8. Connexion admin")
    response = make_request("POST", "auth/login", {
        "username": "admin",
        "password": "adminpass123"
    })
    print_response(response)
    
    if response.status_code == 200:
        admin_token = response.json()["access_token"]
        
        # 9. Test d'accès à une route admin avec droits
        print("\n9. Test d'accès à une route admin avec droits")
        response = make_request("POST", "election/init", 
                              data={"use_ec": True}, 
                              token=admin_token)
        print_response(response)

def create_first_admin():
    """Crée le premier administrateur dans la base de données"""
    from database import ElectionDatabase
    db = ElectionDatabase()
    if db.create_user("admin2", "adminpass123", is_admin=True):
        print("Admin créé avec succès!")
        print("Username: admin2")
        print("Password: adminpass123")
    else:
        print("Erreur lors de la création de l'admin")

if __name__ == "__main__":
    print("Démarrage des tests d'authentification...")
    print("Assurez-vous que l'API est en cours d'exécution (python backend/api.py)")
    
    choice = input("Voulez-vous créer un admin (A) ou lancer les tests (T) ? [A/T] ").upper()
    
    if choice == 'A':
        create_first_admin()
    else:
        try:
            test_auth()
            print("\nTests terminés avec succès!")
        except Exception as e:
            print(f"\nErreur lors des tests: {str(e)}")
            raise 