from typing import Any

from pydantic import BaseModel

# status code tidak bisa di diclare dengan ini
class ResponseScema(BaseModel):
    msg: str = "success"
    data: Any = None


def response(
    msg: str = "success", data: Any = None
) -> ResponseScema:
    return ResponseScema(data=data, msg=msg)