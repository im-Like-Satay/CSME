from typing import Any

from pydantic import BaseModel


class ResponseScema(BaseModel):
    status_code: int = 200
    msg: str = "success"
    data: Any = None


def response(
    status_code: int = 200, msg: str = "success", data: Any = None
) -> ResponseScema:
    return ResponseScema(status_code=status_code, data=data, msg=msg)
