# vulnerable_api.py - API para testing de vulnerabilidades de seguridad
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import hashlib
import base64
import uvicorn
from contextlib import asynccontextmanager

# Configuración JWT (VULNERABLE - clave débil)
SECRET_KEY = "123456"  # ⚠️ VULNERABLE: Clave muy débil
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Modelos
class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    email: str
    role: str = "user"

class User(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime
    is_active: bool = True
    password_hash: Optional[str] = None  # Campo para almacenar hash de contraseña

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user_info: dict

class AdminAction(BaseModel):
    action: str
    target_user_id: Optional[int] = None
    data: Optional[dict] = None

# Base de datos simulada
users_db = []
admin_logs = []
sensitive_data = []
next_user_id = 1

def get_next_user_id():
    global next_user_id
    current = next_user_id
    next_user_id += 1
    return current

# Funciones de utilidad
def hash_password(password: str) -> str:
    # ⚠️ VULNERABLE: MD5 es inseguro
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        # ⚠️ VULNERABLE: No verificación de expiración en algunos casos
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        return payload
    except jwt.InvalidTokenError:
        return None

def find_user_by_username(username: str):
    for user in users_db:
        if user.username == username:
            return user
    return None

def find_user_by_id(user_id: int):
    for user in users_db:
        if user.id == user_id:
            return user
    return None

# Configuración de datos iniciales
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Crear usuarios de prueba
    admin_user = User(
        id=get_next_user_id(),
        username="admin",
        email="admin@test.com",
        role="admin",
        created_at=datetime.now(),
        password_hash=hash_password("admin123")
    )
    users_db.append(admin_user)
    
    regular_user = User(
        id=get_next_user_id(),
        username="user1",
        email="user1@test.com",
        role="user",
        created_at=datetime.now(),
        password_hash=hash_password("password123")
    )
    users_db.append(regular_user)
    
    moderator_user = User(
        id=get_next_user_id(),
        username="moderator",
        email="mod@test.com",
        role="moderator",
        created_at=datetime.now(),
        password_hash=hash_password("mod123")
    )
    users_db.append(moderator_user)
    
    # Datos sensibles de ejemplo
    sensitive_data.extend([
        {"id": 1, "type": "credit_card", "data": "4532-1234-5678-9012", "owner_id": 2},
        {"id": 2, "type": "ssn", "data": "123-45-6789", "owner_id": 2},
        {"id": 3, "type": "medical", "data": "Patient has diabetes", "owner_id": 3}
    ])
    
    yield
    pass

app = FastAPI(
    title="API Vulnerable para Testing de Seguridad",
    description="API con vulnerabilidades intencionadas para pruebas de penetración",
    version="1.0.0",
    lifespan=lifespan
)

security = HTTPBearer()

# ================================
# ENDPOINTS DE AUTENTICACIÓN
# ================================

@app.post("/register", response_model=dict)
async def register(user_data: UserRegister):
    """
    Registro de usuario
    VULNERABILIDAD: No validación de role - puedes registrarte como admin
    """
    if find_user_by_username(user_data.username):
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    
    # ⚠️ VULNERABLE: Acepta cualquier role sin validación
    new_user = User(
        id=get_next_user_id(),
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,  # Sin validación!
        created_at=datetime.now(),
        password_hash=hash_password(user_data.password)
    )
    users_db.append(new_user)
    
    return {"message": "Usuario creado exitosamente", "user_id": new_user.id}

@app.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """Login y generación de token JWT"""
    user = find_user_by_username(credentials.username)
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario desactivado")
    
    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "iat": datetime.utcnow()
    }
    
    access_token = create_access_token(token_data)
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_info={
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "email": user.email
        }
    )

# ================================
# MIDDLEWARE DE AUTENTICACIÓN
# ================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Obtener usuario actual del token"""
    token = credentials.credentials
    payload = decode_token(token)
    
    if payload is None:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    username = payload.get("sub")
    user = find_user_by_username(username)
    
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    return user

async def get_current_user_weak(authorization: str = Header(None)):
    """
    ⚠️ VULNERABLE: Autenticación débil - acepta múltiples formatos
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Token requerido")
    
    # ⚠️ VULNERABLE: Acepta diferentes formatos de autorización
    token = None
    if authorization.startswith("Bearer "):
        token = authorization[7:]
    elif authorization.startswith("Token "):
        token = authorization[6:]
    else:
        token = authorization  # Acepta token directo
    
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    username = payload.get("sub")
    user = find_user_by_username(username)
    
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    return user

# ================================
# ENDPOINTS VULNERABLES
# ================================

@app.get("/")
async def root():
    return {
        "message": "API Vulnerable para Testing de Seguridad",
        "docs": "/docs",
        "endpoints": {
            "auth": ["/register", "/login"],
            "user": ["/profile", "/users", "/users/{id}"],
            "admin": ["/admin/users", "/admin/logs", "/admin/actions"],
            "vulnerable": ["/debug", "/internal", "/sensitive-data"]
        },
        "test_users": {
            "admin": "admin/admin123",
            "user": "user1/password123",
            "moderator": "moderator/mod123"
        }
    }

@app.get("/profile", response_model=User)
async def get_profile(current_user: User = Depends(get_current_user)):
    """Obtener perfil del usuario actual"""
    return current_user

@app.get("/users", response_model=List[User])
async def get_users(current_user: User = Depends(get_current_user)):
    """
    ⚠️ VULNERABLE: No control de acceso - cualquier usuario puede ver todos los usuarios
    """
    return users_db

@app.get("/users/{user_id}")
async def get_user_by_id(user_id: int, current_user: User = Depends(get_current_user_weak)):
    """
    ⚠️ VULNERABLE: IDOR - Insecure Direct Object Reference
    """
    user = find_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # ⚠️ Sin verificación si el usuario puede acceder a esta información
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at,
        "password_hash": user.password_hash  # ⚠️ VULNERABLE: Expone hash de contraseña
    }

@app.get("/admin/users")
async def admin_get_users(current_user: User = Depends(get_current_user)):
    """
    ⚠️ VULNERABLE: Control de acceso débil
    """
    # ⚠️ Solo verifica si existe usuario, no si es admin
    if not current_user:
        raise HTTPException(status_code=401, detail="No autorizado")
    
    # Debería verificar: if current_user.role != "admin"
    return {
        "users": users_db,
        "total": len(users_db),
        "admin_info": "Acceso desde usuario: " + current_user.username
    }

@app.post("/admin/actions")
async def admin_actions(action: AdminAction, current_user: User = Depends(get_current_user)):
    """
    ⚠️ VULNERABLE: Escalación de privilegios
    """
    # ⚠️ Control de acceso insuficiente
    if current_user.role not in ["admin", "moderator"]:
        # Pero moderator puede hacer acciones de admin
        pass
    
    log_entry = {
        "timestamp": datetime.now(),
        "user": current_user.username,
        "action": action.action,
        "target": action.target_user_id,
        "data": action.data
    }
    admin_logs.append(log_entry)
    
    # ⚠️ VULNERABLE: Permite acciones peligrosas sin validación
    if action.action == "delete_user" and action.target_user_id:
        users_db[:] = [u for u in users_db if u.id != action.target_user_id]
        return {"message": f"Usuario {action.target_user_id} eliminado"}
    
    elif action.action == "promote_user" and action.target_user_id:
        target_user = find_user_by_id(action.target_user_id)
        if target_user:
            target_user.role = "admin"
            return {"message": f"Usuario {action.target_user_id} promovido a admin"}
    
    return {"message": "Acción ejecutada", "log_id": len(admin_logs)}

@app.get("/debug")
async def debug_endpoint(token: str = None):
    """
    ⚠️ VULNERABLE: Debug endpoint que expone información sensible
    """
    debug_info = {
        "jwt_secret": SECRET_KEY,  # ⚠️ Expone la clave JWT
        "users_count": len(users_db),
        "algorithm": ALGORITHM,
        "server_time": datetime.now(),
        "environment": "production"  # Mentira, pero simula exposición
    }
    
    if token:
        # ⚠️ VULNERABLE: Decodifica token sin validación
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            debug_info["decoded_token"] = decoded
        except:
            debug_info["token_error"] = "Token inválido"
    
    return debug_info

@app.get("/internal")
async def internal_endpoint(request: Request):
    """
    ⚠️ VULNERABLE: Endpoint interno accesible públicamente
    """
    return {
        "internal_data": "Información confidencial del sistema",
        "database_config": {
            "host": "internal-db.company.com",
            "user": "admin",
            "password": "super_secret_123"  # ⚠️ Expone credenciales
        },
        "api_keys": {
            "payment_gateway": "sk_live_1234567890",
            "external_service": "key_abcdef123456"
        },
        "client_ip": request.client.host,
        "headers": dict(request.headers)
    }

@app.get("/sensitive-data/{data_id}")
async def get_sensitive_data(data_id: int, current_user: User = Depends(get_current_user_weak)):
    """
    ⚠️ VULNERABLE: IDOR en datos sensibles + falta de autorización
    """
    for data in sensitive_data:
        if data["id"] == data_id:
            # ⚠️ No verifica si el usuario puede acceder a estos datos
            return {
                "id": data["id"],
                "type": data["type"],
                "data": data["data"],
                "owner_id": data["owner_id"],
                "accessed_by": current_user.username
            }
    
    raise HTTPException(status_code=404, detail="Datos no encontrados")

@app.get("/token-info")
async def token_info(authorization: str = Header(None)):
    """
    ⚠️ VULNERABLE: Endpoint que procesa tokens sin validación adecuada
    """
    if not authorization:
        return {"message": "No token provided"}
    
    # ⚠️ VULNERABLE: Acepta múltiples formatos y procesa tokens inválidos
    token = authorization.replace("Bearer ", "").replace("Token ", "")
    
    try:
        # Decodifica sin verificar expiración
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        
        # ⚠️ Expone información del token
        return {
            "valid": True,
            "payload": payload,
            "is_expired": payload.get("exp", 0) < datetime.utcnow().timestamp(),
            "user_id": payload.get("user_id"),
            "role": payload.get("role")
        }
    except jwt.InvalidSignatureError:
        return {"valid": False, "error": "Invalid signature", "token": token[:20] + "..."}
    except Exception as e:
        return {"valid": False, "error": str(e), "token": token[:20] + "..."}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "users": len(users_db),
        "version": "1.0.0-vulnerable"
    }

if __name__ == "__main__":
    print("🚨 ADVERTENCIA: Esta API contiene vulnerabilidades intencionadas")
    print("   Solo para uso en entornos de testing de seguridad")
    print("📖 Documentación: http://127.0.0.1:8000/docs")
    print("🔧 Endpoints vulnerables listos para testing")
    uvicorn.run(app, host="127.0.0.1", port=8000)
