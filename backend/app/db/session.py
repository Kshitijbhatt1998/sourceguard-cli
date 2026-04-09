from sqlmodel import create_engine, Session, SQLModel
from ..core.config import settings

# Engine configuration (dev: sqlite, prod: postgresql)
engine = create_engine(settings.DATABASE_URL, echo=False)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
        
def get_sync_session():
    """Context manager for synchronous sessions where 'Depends' cannot be used."""
    return Session(engine)
