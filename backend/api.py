from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict
import uvicorn
from config import NUM_VOTERS, NUM_CANDIDATES
from voting import VotingSystem, Ballot
from auth import get_current_user, get_current_admin, create_access_token
from datetime import timedelta
from database import ElectionDatabase
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
    status: str
    created_at: str
    total_votes: int

class CandidateInfo(BaseModel):
    id: int
    name: str

@app.post("/election/init")
async def initialize_election(
    config: ElectionConfig,
    current_user: dict = Depends(get_current_admin)
):
    """Initialise une nouvelle élection"""
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
            use_ec=config.use_ec,
            public_key=voting_system.pub_key,
            private_key=voting_system.priv_key,
            candidates=[c.name for c in config.candidates]
        )
        return {
            "message": f"Élection initialisée avec {'EC-ElGamal' if config.use_ec else 'ElGamal'}",
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
async def cast_vote(
    vote_request: VoteRequest,
    current_user: dict = Depends(get_current_user)
):
    """Enregistre un nouveau vote"""
    try:
        # Récupère l'élection
        election = db.get_election(vote_request.election_id)
        if not election:
            raise HTTPException(status_code=404, detail="Élection non trouvée")
            
        # Crée une instance de VotingSystem avec les bonnes clés
        voting_system = VotingSystem(
            use_ec=election["use_ec"],
            num_candidates=len(db.get_candidates(vote_request.election_id))
        )
        
        # Crée et chiffre le vote
        vote = voting_system.create_vote(vote_request.candidate)
        ballot = voting_system.encrypt_vote(vote, current_user["id"])
        
        # Stocke le bulletin
        if not db.store_ballot(vote_request.election_id, ballot):
            raise HTTPException(status_code=400, detail="Vous avez déjà voté pour cette élection")
        
        return {"message": "Vote enregistré avec succès"}
        
    except Exception as e:
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

@app.get("/elections", response_model=List[ElectionInfo])
async def get_elections(current_user: dict = Depends(get_current_user)):
    """Récupère la liste des élections"""
    return db.get_elections()

@app.get("/election/{election_id}/candidates")
async def get_candidates(
    election_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Récupère la liste des candidats pour une élection"""
    return db.get_candidates(election_id)

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True) 