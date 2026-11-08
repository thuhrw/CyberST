from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .simulation import run

app = FastAPI()


class Req(BaseModel):
    message: str = "Meet at 10:00"
    attack: str = "none"
    defense: bool = False


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.post("/api/simulate")
def simulate(r: Req):
    return run(r.message, r.attack, r.defense)
