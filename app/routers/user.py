from fastapi import APIRouter, Depends
from bson.objectid import ObjectId
from app.Serializers.userSerializers import userResponseEntity
from app.auth.auth_bearer import JWTBearer
from app.utils.jwt import get_current_user
from app.utils.response import success_response

from app.database import User
from .. import schemas, oauth2


router = APIRouter()
@router.get("/me")
async def dashboard(current_user: dict = Depends(get_current_user)):
    return success_response("Dashboard data retrieved successfully", data=current_user)

# @router.get('/me', response_model=schemas.UserResponse, dependencies=[Depends(JWTBearer())])
# @router.get('/me')
# def get_me(credentials: str = Depends(JWTBearer())):
#     print(credentials)
#     return {"status": "success"}
# def get_me(user_id: str = Depends(JWTBearer())):
#     user = userResponseEntity(User.find_one({'_id': ObjectId(str(user_id))}))
#     return {"status": "success", "user": user}
