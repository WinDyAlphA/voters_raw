# Système de Vote Électronique Sécurisé

## Introduction

Ce projet, réalisé dans le cadre du cours de cryptographie appliquée, implémente un système de vote électronique sécurisé pour une élection avec 10 votants et 5 candidats. Le système utilise des techniques cryptographiques avancées pour garantir :
- La confidentialité des votes via le chiffrement homomorphique
- L'éligibilité des votants via les signatures numériques

## Spécifications du Système

### Format des Votes
Chaque vote est représenté par une liste de 5 éléments (0 ou 1) où :
- Un vote pour le candidat C1 donne : (1, 0, 0, 0, 0)
- Un vote pour le candidat C2 donne : (0, 1, 0, 0, 0)
- Et ainsi de suite...

### Paramètres Cryptographiques
- **ElGamal et DSA** : Utilisation du groupe MODP Group 24
- **EC-ElGamal et ECDSA** : Utilisation de la courbe curve25519
- **Fonction de hachage** : SHA256 pour DSA et ECDSA

## Implémentation

### Composants du Système
```
backend/
├── voting.py          # Système de vote principal
├── ecelgamal.py      # Chiffrement EC-ElGamal
├── elgamal.py        # Chiffrement ElGamal classique
├── ecdsa.py          # Signatures ECDSA
├── dsa.py            # Signatures DSA
└── crypto_utils/     # Utilitaires cryptographiques
```

### Fonctionnalités Principales

1. **Gestion des Clés**
   - Génération et distribution des clés de signature pour chaque votant
   - Génération des clés de chiffrement pour l'élection

2. **Processus de Vote**
   - Création du bulletin : 5 messages chiffrés (un par candidat)
   - Signature du bulletin par le votant
   - Vérification de la signature à la réception

3. **Dépouillement**
   - Agrégation homomorphique des bulletins chiffrés
   - Déchiffrement du résultat final
   - Comptage des votes par candidat

### Modes de Fonctionnement

Le système supporte deux modes cryptographiques :

1. **Mode Classique**
   - Chiffrement : ElGamal (multiplication homomorphique)
   - Signature : DSA
   - Paramètres : MODP Group 24

2. **Mode Courbes Elliptiques**
   - Chiffrement : EC-ElGamal (addition homomorphique)
   - Signature : ECDSA
   - Paramètres : curve25519

## Sécurité

### Confidentialité des Votes
- Chiffrement individuel de chaque élément du vote
- Utilisation des propriétés homomorphiques pour l'agrégation
- Déchiffrement uniquement du résultat final agrégé

### Éligibilité des Votants
- Signature unique pour chaque votant
- Vérification systématique des signatures
- Protection contre les votes non autorisés

## Tests et Validation

### Déroulement des Tests

Le système effectue une série de tests automatisés qui simulent une élection complète :

1. **Test d'Élection Complète**
   ```
   Résultats de l'élection (EC-ElGamal):
   Candidat 1: 2 votes
   Candidat 2: 3 votes
   Candidat 3: 1 votes
   Candidat 4: 2 votes
   Candidat 5: 2 votes
   
   Résultats de l'élection (ElGamal):
   Candidat 1: 1 votes
   Candidat 2: 2 votes
   Candidat 3: 3 votes
   Candidat 4: 2 votes
   Candidat 5: 2 votes
   ```

2. **Test des Signatures**
   ```
   Test des signatures:
   --------------------------------------------------
   Test ECDSA:
   Votant 0: Signature valide
   Votant 0 (signature invalide): correctement rejetée
   Votant 1: Signature valide
   Votant 1 (signature invalide): correctement rejetée
   Votant 2: Signature valide
   Votant 2 (signature invalide): correctement rejetée

   Test DSA:
   Votant 0: Signature valide
   Votant 0 (signature invalide): correctement rejetée
   Votant 1: Signature valide
   Votant 1 (signature invalide): correctement rejetée
   Votant 2: Signature valide
   Votant 2 (signature invalide): correctement rejetée
   ```

### Étapes de Test

1. **Initialisation**
   - Génération des clés de l'élection
   - Distribution des clés de signature aux votants

2. **Simulation des Votes**
   - Création de bulletins pour chaque votant
   - Chiffrement des choix individuels
   - Signature des bulletins

3. **Vérification des Signatures**
   - Test des signatures valides
   - Test de détection des signatures invalides
   - Vérification pour chaque mode cryptographique

4. **Agrégation et Dépouillement**
   - Combinaison homomorphique des votes
   - Déchiffrement du résultat final
   - Vérification du total des votes

### Validation des Résultats

Le système vérifie automatiquement :
- La somme totale des votes égale au nombre de votants
- La détection correcte des signatures invalides
- La cohérence des résultats après déchiffrement

## Installation et Utilisation

1. Installation des dépendances :
```bash
pip install -r requirements.txt
```

2. Exécution des tests :
```bash
python3 backend/voting.py
```

## Conclusion

Cette implémentation démontre la faisabilité d'un système de vote électronique sécurisé combinant :
- La confidentialité via le chiffrement homomorphique
- L'authentification via les signatures numériques
- La flexibilité via le support de différents schémas cryptographiques



