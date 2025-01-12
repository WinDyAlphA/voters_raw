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
docker-compose up --build
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

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une pull request pour proposer des améliorations.