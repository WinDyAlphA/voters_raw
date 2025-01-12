from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
from database import ElectionDatabase

# Configuration
SECRET_KEY = "votre_clé_secrète_très_longue_et_aléatoire"  # À changer en production !
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()
db = ElectionDatabase()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Crée un token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    # Récupère les informations de l'utilisateur
    user = db.get_user(data["sub"])
    to_encode.update({
        "exp": expire,
        "is_admin": user["is_admin"]  # Ajoute is_admin au token
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Vérifie le token JWT et retourne l'utilisateur"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token invalide")
        user = db.get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="Utilisateur non trouvé")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")

def get_current_admin(current_user: dict = Depends(get_current_user)):
    """Vérifie que l'utilisateur est admin"""
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Droits administrateur requis")
    return current_user 