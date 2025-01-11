import requests
import json
import time
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

def make_request(method: str, endpoint: str, data: Dict[str, Any] = None) -> requests.Response:
    """Effectue une requête à l'API"""
    url = f"{BASE_URL}/{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url)
        elif method.upper() == "POST":
            response = requests.post(url, json=data)
        else:
            raise ValueError(f"Méthode HTTP non supportée: {method}")
            
        return response
    
    except requests.exceptions.ConnectionError:
        print(f"Erreur: Impossible de se connecter à {url}")
        print("Assurez-vous que l'API est en cours d'exécution (python backend/api.py)")
        exit(1)

def test_voting_system():
    """Test complet du système de vote"""
    print("\n=== Test du système de vote ===\n")
    
    # 1. Initialisation de l'élection
    print("1. Initialisation de l'élection avec EC-ElGamal")
    response = make_request("POST", "election/init", {"use_ec": False})
    print_response(response)
    
    # 2. Vérification du statut initial
    print("\n2. Vérification du statut initial")
    response = make_request("GET", "election/status")
    print_response(response)
    
    # 3. Test d'un vote invalide (votant invalide)
    print("\n3. Test d'un vote invalide (votant invalide)")
    response = make_request("POST", "vote", {
        "voter_id": 999,
        "candidate": 0
    })
    print_response(response)
    
    # 4. Soumission de votes valides
    print("\n4. Soumission de votes valides")
    for voter_id in range(10):  # NUM_VOTERS = 10
        candidate = voter_id % 5  # NUM_CANDIDATES = 5
        print(f"\nVote du votant {voter_id} pour le candidat {candidate}")
        response = make_request("POST", "vote", {
            "voter_id": voter_id,
            "candidate": candidate
        })
        print_response(response)
        
        # Vérification du statut après chaque vote
        status_response = make_request("GET", "election/status")
        print("\nStatut après le vote:")
        print_response(status_response)
        
        # Petite pause pour éviter de surcharger l'API
        time.sleep(0.5)
    
    # 5. Tentative de vote en double
    print("\n5. Tentative de vote en double (votant 0)")
    response = make_request("POST", "vote", {
        "voter_id": 0,
        "candidate": 1
    })
    print_response(response)
    
    # 6. Récupération des résultats finaux
    print("\n6. Récupération des résultats finaux")
    response = make_request("GET", "results")
    print_response(response)
    
    # 7. Nouvelle élection avec ElGamal classique
    print("\n7. Initialisation d'une nouvelle élection avec ElGamal classique")
    response = make_request("POST", "election/init", {"use_ec": True})
    print_response(response)

if __name__ == "__main__":
    print("Démarrage des tests de l'API du système de vote...")
    print("Assurez-vous que l'API est en cours d'exécution (python backend/api.py)")
    print("Appuyez sur Entrée pour continuer...")
    input()
    
    try:
        test_voting_system()
        print("\nTests terminés avec succès!")
        
    except Exception as e:
        print(f"\nErreur lors des tests: {str(e)}")
        raise 