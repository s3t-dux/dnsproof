from sqlmodel import SQLModel, create_engine
from config import DB_PATH

engine = create_engine(f"sqlite:///{DB_PATH}")

def init_db():
    print(f"[DEBUG] Using DB at: {DB_PATH}")
    SQLModel.metadata.create_all(engine)
