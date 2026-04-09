from fastapi import FastAPI
from slowapi.middleware import SlowAPIMiddleware
from .core.rate_limiter import limiter
from .api.routes import auth, scan, github
from .db.session import init_db

app = FastAPI(
    title="SourceGuard Production API",
    description="Professional secret detection platform backend with JWT auth and GitHub integration.",
    version="1.0.0"
)

# Apply Rate Limiting
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Initialize Database (SQLite for dev, auto-switches to PG for prod)
@app.on_event("startup")
def on_startup():
    init_db()

# Include Routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(github.router)

@app.get("/")
def read_root():
    return {
        "service": "SourceGuard Production API",
        "status": "online",
        "documentation": "/docs"
    }
