from typing import Any, Dict
from pydantic import BaseModel


class BaseResponse(BaseModel):
    success: bool
    message: str
    data: Any = None

    class Config:
        orm_mode = True


def success_response(message: str, data: Dict = None):
    return BaseResponse(success=True, message=message, data=data)


def error_response(message: str, status_code: int = 400):
    return BaseResponse(success=False, message=message), status_code
