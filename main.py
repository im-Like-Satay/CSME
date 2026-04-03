from fastapi import FastAPI

from until.response import response

app = FastAPI()


@app.get("/")
async def root():
    return response(200, "ok", {"helo": "wrd"})
