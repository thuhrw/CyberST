from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StrictBool
from typing import Literal

from .simulation import run

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")


class Req(BaseModel):
    message: str = "Meet at 10:00"
    attack: Literal["none", "key_replace", "tamper", "replay"] = "none"
    defense: StrictBool = False


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.post("/api/simulate")
def simulate(r: Req):
    return run(r.message, r.attack, r.defense)
