# Système de Vote Cryptographique

Cette application est un système de vote électronique sécurisé utilisant le chiffrement ElGamal et EC-ElGamal. Elle permet d'organiser des élections en ligne tout en garantissant l'anonymat des votants et l'intégrité des votes.

## Architecture

L'application est composée de deux parties principales :
- Un backend en Python (FastAPI) qui gère la logique de vote et le chiffrement
- Un frontend en React qui fournit l'interface utilisateur

Le chiffrement des votes est effectué côté serveur pour des raisons techniques, la complexité de l'implémentation d'ElGamal en JavaScript étant trop importante. Dans une version future, le chiffrement pourrait être déplacé côté client pour une meilleure sécurité.

## Prérequis

- Docker
- Docker Compose

## Installation et Démarrage

Pour lancer l'application en mode développement :

1. Clonez le dépôt et accédez au répertoire racine, lancez les containers :

```bash
git clone -b frontendlogin https://github.com/votre-utilisateur/voters_raw.git
cd voters_raw
docker compose up --build
```

L'application sera accessible sur :
- Frontend : http://localhost:3000
- API Backend : http://localhost:8000

## Compte Administrateur

Un compte administrateur est créé par défaut avec les identifiants suivants :
- Nom d'utilisateur : admin
- Mot de passe : adminpass123

L'administrateur peut :
- Créer de nouvelles élections
- Générer des codes d'invitation pour les nouveaux utilisateurs
- Voir les résultats des élections terminées
- Clôturer les élections en cours

## Utilisation

1. L'administrateur crée une nouvelle élection et génère des codes d'invitation
2. Les utilisateurs s'inscrivent avec les codes d'invitation
3. Les utilisateurs peuvent voter pour les élections en cours
4. L'administrateur peut clôturer une élection et voir les résultats

## Sécurité

Le système utilise deux types de chiffrement :
- ElGamal classique
- EC-ElGamal (cryptographie sur courbes elliptiques)

Les votes sont chiffrés individuellement et combinés de manière homomorphe, ce qui permet de calculer le résultat final sans jamais déchiffrer les votes individuels.


## Limitations Connues

- Le chiffrement est effectué côté serveur
- Les clés privées sont stockées sur le serveur
- L'application n'est pas conçue pour gérer un très grand nombre de votants

## Pour arrêter les containers

```bash
docker compose down -v
```

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une pull request pour proposer des améliorations.

## Réponses aux Questions

### Taille des entrées/sorties des algorithmes

#### ElGamal Classique

**Entrées :**
- Message (vote) : 1 bit par candidat (ex: [1,0,0] pour voter pour le premier candidat)
- Clé publique : 2048 bits (p: 1024 bits, g: 1024 bits)
- Clé privée : 1024 bits

**Sorties :**
- Vote chiffré : Deux nombres de 1024 bits chacun (c1, c2)
- Signature : Deux nombres de 1024 bits chacun (r, s)

#### EC-ElGamal

**Entrées :**
- Message (vote) : 1 bit par candidat (même format que ElGamal classique)
- Clé publique : Point sur la courbe (deux coordonnées de 256 bits chacune)
- Clé privée : 256 bits

**Sorties :**
- Vote chiffré : Deux points sur la courbe (chacun composé de deux coordonnées de 256 bits)
- Signature : Deux nombres de 256 bits chacun

Dans les deux cas, la taille des entrées/sorties est indépendante du nombre de candidats car nous utilisons un vecteur de votes où seule une position contient 1 et les autres 0.

#### DSA (Digital Signature Algorithm)

**Entrées :**
- Message à signer : Hash SHA-256 du message (256 bits)
- Paramètres publics :
  - p : nombre premier (2048 bits)
  - q : diviseur premier de p-1 (256 bits)
  - g : générateur du sous-groupe d'ordre q (2048 bits)
- Clé privée : x (256 bits)
- Clé publique : y = g^x mod p (2048 bits)

**Sorties :**
- Signature : Paire de nombres (r, s) de 256 bits chacun

#### EC-DSA (Elliptic Curve Digital Signature Algorithm)

**Entrées :**
- Message à signer : Hash SHA-256 du message (256 bits)
- Paramètres de la courbe :
  - Point générateur G sur la courbe (deux coordonnées de 256 bits)
  - Ordre n du point G (256 bits)
- Clé privée : d (256 bits)
- Clé publique : Point Q = dG (deux coordonnées de 256 bits)

**Sorties :**
- Signature : Paire de nombres (r, s) de 256 bits chacun

La principale différence entre DSA et EC-DSA réside dans la taille des paramètres publics et des clés. EC-DSA utilise des clés plus courtes (256 bits) pour un niveau de sécurité équivalent à DSA avec des clés de 2048 bits, grâce à l'utilisation de la cryptographie sur courbes elliptiques.
