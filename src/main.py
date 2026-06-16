from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from utility.setting import settings

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.DOMAIN_HOST],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"status": True}
