from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict
import uvicorn
from config import NUM_VOTERS, NUM_CANDIDATES
from voting import VotingSystem, Ballot
from auth import get_current_user, get_current_admin, create_access_token
from datetime import timedelta
from database import ElectionDatabase, reset_database
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Système de Vote Cryptographique")

# Initialisation de la base de données
db = ElectionDatabase()

# Stockage en mémoire pour notre démo
voting_system: VotingSystem = None
ballots: List[Ballot] = []

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VoteRequest(BaseModel):
    election_id: int
    candidate: int

class CandidateCreate(BaseModel):
    name: str

class ElectionConfig(BaseModel):
    name: str
    use_ec: bool = True
    candidates: List[CandidateCreate]

class ElectionResults(BaseModel):
    results: List[int]
    total_votes: int

class UserCreate(BaseModel):
    username: str
    password: str
    invitation_code: str

class UserLogin(BaseModel):
    username: str
    password: str

class InvitationCodeResponse(BaseModel):
    code: str

class ElectionInfo(BaseModel):
    id: int
    name: str
    status: str
    created_at: str
    total_votes: int
    has_voted: bool

class CandidateInfo(BaseModel):
    id: int
    name: str

@app.post("/election/init")
async def initialize_election(
    config: ElectionConfig,
    current_user: dict = Depends(get_current_admin)
):
    """Initialise une nouvelle élection"""
    if not config.name.strip():
        raise HTTPException(status_code=400, detail="Le nom de l'élection est requis")
    if len(config.candidates) < 2:
        raise HTTPException(
            status_code=400, 
            detail="Il faut au moins 2 candidats"
        )
    if len(config.candidates) > 20:
        raise HTTPException(
            status_code=400, 
            detail="Maximum 20 candidats autorisés"
        )
    
    try:
        voting_system = VotingSystem(use_ec=config.use_ec, num_candidates=len(config.candidates))
        election_id = db.create_election(
            name=config.name,
            use_ec=config.use_ec,
            public_key=voting_system.pub_key,
            private_key=voting_system.priv_key,
            candidates=[c.name for c in config.candidates]
        )
        return {
            "message": f"Élection '{config.name}' initialisée avec succès",
            "election_id": election_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/election/status")
async def get_election_status(
    current_user: dict = Depends(get_current_user)
):
    """Retourne le statut actuel de l'élection"""
    if not voting_system:
        raise HTTPException(status_code=400, detail="Aucune élection en cours")
    
    return {
        "total_votes": len(ballots),
        "remaining_votes": NUM_VOTERS - len(ballots),
        "is_complete": len(ballots) >= NUM_VOTERS
    }

@app.post("/vote")
async def submit_vote(
    vote: VoteRequest,
    current_user: dict = Depends(get_current_user)
):
    try:
        # Récupère l'élection
        election = db.get_election(vote.election_id)
        if not election:
            raise HTTPException(status_code=404, detail="Élection non trouvée")
        
        # Récupère les candidats pour connaître leur nombre
        candidates = db.get_candidates(vote.election_id)
        
        # Crée le système de vote avec les paramètres de l'élection
        voting_system = VotingSystem(
            use_ec=election["use_ec"],
            num_candidates=len(candidates)
        )
        
        # Assigne les clés de l'élection
        voting_system.priv_key = election["private_key"]
        voting_system.pub_key = election["public_key"]
        
        # Crée et chiffre le vote
        vote_list = voting_system.create_vote(vote.candidate)
        ballot = voting_system.encrypt_vote(vote_list, current_user["id"])
        
        # Convertit la signature en format hexadécimal si nécessaire
        if isinstance(ballot.signature, tuple):
            ballot.signature = tuple(hex(s)[2:] for s in ballot.signature)  # Enlève le préfixe '0x'
        
        # Stocke le bulletin
        success = db.store_ballot(vote.election_id, ballot)
        
        if not success:
            raise HTTPException(
                status_code=400,
                detail="Vous avez déjà voté pour cette élection"
            )
        
        return {"message": "Vote enregistré avec succès"}
        
    except Exception as e:
        print(f"Erreur lors du vote : {str(e)}")
        print(f"Type d'erreur : {type(e)}")
        import traceback
        print("Traceback complet :")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/results")
async def get_results(
    current_user: dict = Depends(get_current_admin)
):
    """Calcule et retourne les résultats de l'élection"""
    if not voting_system:
        raise HTTPException(status_code=400, detail="Aucune élection en cours")
    
    if len(ballots) < NUM_VOTERS:
        raise HTTPException(status_code=400, 
                          detail=f"Élection en cours. {NUM_VOTERS - len(ballots)} votes manquants")
    
    try:
        # Combine et déchiffre les votes
        combined = voting_system.combine_encrypted_votes(ballots)
        results = voting_system.decrypt_result(combined)
        
        return ElectionResults(
            results=results,
            total_votes=sum(results)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/register")
async def register(user: UserCreate):
    """Enregistre un nouvel utilisateur"""
    # Vérifie le code d'invitation
    if not db.verify_invitation_code(user.invitation_code):
        raise HTTPException(
            status_code=400, 
            detail="Code d'invitation invalide ou déjà utilisé"
        )
    
    # Crée l'utilisateur
    if db.create_user(user.username, user.password):
        # Récupère l'ID du nouvel utilisateur
        new_user = db.get_user(user.username)
        # Marque le code comme utilisé
        db.use_invitation_code(user.invitation_code, new_user["id"])
        return {"message": "Utilisateur créé avec succès"}
    
    raise HTTPException(status_code=400, detail="Nom d'utilisateur déjà pris")

@app.post("/auth/login")
async def login(user: UserLogin):
    """Connecte un utilisateur"""
    if not db.verify_password(user.username, user.password):
        raise HTTPException(status_code=401, detail="Nom d'utilisateur ou mot de passe incorrect")
    
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=30)  # ACCESS_TOKEN_EXPIRE_MINUTES
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/generate-invitation", response_model=InvitationCodeResponse)
async def generate_invitation(current_user: dict = Depends(get_current_admin)):
    """Génère un nouveau code d'invitation (admin uniquement)"""
    code = db.generate_invitation_code(current_user["id"])
    return {"code": code}

@app.get("/elections")
async def get_elections(current_user: dict = Depends(get_current_user)):
    """Récupère la liste des élections"""
    return db.get_elections(current_user["id"])

@app.get("/election/{election_id}/candidates")
async def get_candidates(
    election_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Récupère la liste des candidats pour une élection"""
    return db.get_candidates(election_id)

@app.get("/admin/elections")
async def get_admin_elections(current_user: dict = Depends(get_current_admin)):
    """Récupère toutes les élections (vue admin)"""
    return db.get_all_elections()

@app.post("/election/{election_id}/close")
async def close_election(
    election_id: int,
    current_user: dict = Depends(get_current_admin)
):
    """Ferme une élection"""
    if db.close_election(election_id):
        return {"message": "Élection fermée avec succès"}
    raise HTTPException(status_code=404, detail="Élection non trouvée")

@app.get("/election/{election_id}/results")
async def get_election_results(
    election_id: int,
    current_user: dict = Depends(get_current_admin)
):
    """Calcule et retourne les résultats d'une élection"""
    try:
        print(f"Récupération des résultats pour l'élection {election_id}")
        
        # Récupère l'élection et ses bulletins
        election = db.get_election(election_id)
        if not election:
            raise HTTPException(
                status_code=404, 
                detail=f"L'élection avec l'ID {election_id} n'existe pas"
            )
        
        print(f"Élection trouvée : {election}")
        
        if election["status"] != "completed":
            raise HTTPException(status_code=400, detail="L'élection n'est pas terminée")
            
        ballots = db.get_ballots(election_id)
        print(f"Bulletins trouvés : {ballots}")
        
        candidates = db.get_candidates(election_id)
        print(f"Candidats trouvés : {candidates}")
        
        # Crée une instance de VotingSystem avec les bonnes clés
        voting_system = VotingSystem(
            use_ec=election["use_ec"],
            num_candidates=len(candidates)
        )
        
        # Assigne les clés de l'élection
        print("Clés de l'élection :")
        print(f"- Privée : {election['private_key']}")
        print(f"- Publique : {election['public_key']}")
        
        voting_system.priv_key = election["private_key"]
        voting_system.pub_key = election["public_key"]
        
        # Combine et déchiffre les votes
        if not ballots:
            print("Aucun bulletin trouvé")
            return {
                "candidates": candidates,
                "results": [0] * len(candidates),
                "total_votes": 0
            }
            
        try:
            print("Combinaison des votes chiffrés...")
            combined = voting_system.combine_encrypted_votes(ballots)
            print(f"Votes combinés : {combined}")
            
            print("Déchiffrement des résultats...")
            results = voting_system.decrypt_result(combined)
            print(f"Résultats déchiffrés : {results}")
            
            return {
                "candidates": candidates,
                "results": results,
                "total_votes": sum(results)
            }
        except Exception as e:
            print(f"Erreur lors du déchiffrement : {str(e)}")
            print(f"Type d'erreur : {type(e)}")
            import traceback
            print("Traceback complet :")
            print(traceback.format_exc())
            raise HTTPException(
                status_code=500, 
                detail=f"Erreur lors du déchiffrement : {str(e)}"
            )
        
    except Exception as e:
        print(f"Erreur : {str(e)}")
        print(f"Type d'erreur : {type(e)}")
        import traceback
        print("Traceback complet :")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    reset_database()  # Décommentez cette ligne une fois pour réinitialiser la base de données
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True) 