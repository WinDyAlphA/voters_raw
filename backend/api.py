from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict
import uvicorn
from voting import VotingSystem, Ballot, NUM_VOTERS, NUM_CANDIDATES
from auth import get_current_user, get_current_admin, create_access_token
from datetime import timedelta
from database import ElectionDatabase

app = FastAPI(title="Système de Vote Cryptographique")

# Initialisation de la base de données
db = ElectionDatabase()

# Stockage en mémoire pour notre démo
voting_system: VotingSystem = None
ballots: List[Ballot] = []

class VoteRequest(BaseModel):
    voter_id: int
    candidate: int

class ElectionConfig(BaseModel):
    use_ec: bool = True

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

@app.post("/election/init")
async def initialize_election(
    config: ElectionConfig,
    current_user: dict = Depends(get_current_admin)
):
    """Initialise une nouvelle élection"""
    global voting_system, ballots
    
    try:
        voting_system = VotingSystem(use_ec=config.use_ec)
        ballots = []
        return {
            "message": f"Élection initialisée avec {'EC-ElGamal' if config.use_ec else 'ElGamal'}",
            "num_voters": NUM_VOTERS,
            "num_candidates": NUM_CANDIDATES
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
    if not voting_system:
        raise HTTPException(status_code=400, detail="Aucune élection en cours")
    
    if vote_request.voter_id >= NUM_VOTERS:
        raise HTTPException(status_code=400, detail="ID de votant invalide")
        
    if vote_request.candidate >= NUM_CANDIDATES:
        raise HTTPException(status_code=400, detail="ID de candidat invalide")
    
    # Vérifie si le votant a déjà voté
    if any(b.voter_id == vote_request.voter_id for b in ballots):
        raise HTTPException(status_code=400, detail="Ce votant a déjà voté")
    
    try:
        # Crée et chiffre le vote
        vote = voting_system.create_vote(vote_request.candidate)
        ballot = voting_system.encrypt_vote(vote, vote_request.voter_id)
        ballots.append(ballot)
        
        return {
            "message": "Vote enregistré avec succès",
            "total_votes": len(ballots)
        }
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

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True) 