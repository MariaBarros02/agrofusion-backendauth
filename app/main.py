from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth
from app.routes import external_projects


# Inicialización de la aplicación FastAPI
app = FastAPI(
    title="API Inmero - Backend Authentication Agrofusion",
    version="1.0.0"
)

# -----------------------------
# Configuración de CORS
# -----------------------------
# Define los orígenes permitidos para consumir la API
# Usado principalmente por el frontend
origins = [
    "http://localhost:5173",   # Frontend local (Vite)
    "http://localhost:3000",   # Frontend alternativo
    "http://127.0.0.1:5173",   # Backend / frontend local
]

# Middleware de CORS
# Permite solicitudes cross-origin desde los orígenes definidos
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],   # Permite todos los métodos HTTP
    allow_headers=["*"],   # Permite todos los headers
)

# -----------------------------
# Registro de rutas
# -----------------------------
# Incluye el router de autenticación
app.include_router(auth.router)
app.include_router(external_projects.router)
