from datetime import datetime, timedelta
from bson.objectid import ObjectId
from fastapi import APIRouter, Response, status, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app import oauth2
from app.database import User
from app.Serializers.userSerializers import userEntity, userResponseEntity
from .. import schemas, utils
# from app.oauth2 import AuthJWT
from ..config import settings
from app.utils.password import verify_password, get_password_hash
from app.utils.response import success_response, error_response
from app.utils.jwt import create_access_token
from ..auth.auth_handler import sign_jwt

router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


@router.post('/register', status_code=status.HTTP_201_CREATED, response_model=schemas.UserResponse)
async def create_user(payload: schemas.CreateUserSchema):
    # Check if the user exists already
    user = User.find_one({'email': payload.email.lower()})
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Account already exist')
    if payload.password != payload.passwordConfirm:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Passwords do not match')

    # hash the password
    payload.password = utils.hash_password(payload.password)
    del payload.passwordConfirm
    payload.role = 'user'
    payload.verified = True
    payload.email = payload.email.lower()
    payload.created_at = datetime.utcnow()
    payload.updated_at = payload.created_at
    result = User.insert_one(payload.dict())
    new_user = userResponseEntity(User.find_one({'_id': result.inserted_id}))
    return {"status": "Success", "user": new_user}


@router.post('/login')
def login(payload: schemas.LoginUserSchema, response: Response):
    db_user = User.find_one({'email': payload.email.lower()})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')
    user = userEntity(db_user)
    # check if the password is valid
    if not verify_password(payload.password, user['password']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')
    access_token_expires = timedelta(minutes=400)
    access_token = create_access_token(data={"sub": user['email']}, expires_delta=access_token_expires)
    return success_response("Login Successful", {"access_token": access_token})


@router.post("/token")
async def authenticate_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db_user = User.find_one({'email': form_data.username.lower()})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')
    user = userEntity(db_user)
    # check if the password is valid
    if not verify_password(form_data.password, user['password']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')
    access_token_expires = timedelta(minutes=400)
    access_token = create_access_token(data={"sub": user['email']}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
# @router.post("/token")
# async def authenticate_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = User.find_one({'email': form_data.email.lower()})
#     if not user or not user.check_password(form_data.password):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
#     access_token_expires = timedelta(minutes=400)
#     access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
#     return {"access_token": access_token, "token_type": "bearer"}
# @router.post('/token')
# async def authenticate_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = User.query(User).filter(User.username == form_data.username).first()
# if not user or not user.check_password(form_data.password):
#     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
# access_token_expires = timedelta(minutes=400)
# access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
# return {"access_token": access_token, "token_type": "bearer"}

# token = sign_jwt(user['id'])
#
# return {"status": "success", "access_token": token["access_token"]}

#
#     # create access token
#     access_token = Authorize.create_access_token(subject=str(user['id']),
#                                                  expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN))
#
#     # create refresh token
#     refresh_token = Authorize.create_refresh_token(subject=str(user['id']),
#                                                    expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN))
#
#     # store refresh and access tokens in cookie
#     response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60, ACCESS_TOKEN_EXPIRES_IN * 60, '/',
#                         None, False, True, 'lax')
#
#     response.set_cookie('refresh_token', refresh_token,
#                         REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
#     response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
#                         ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
#
#     # send both access
#     return {'status': 'success', 'access_token': access_token}
#
# @router.get('/refresh')
# def refresh_token(response: Response, Authorize: AuthJWT = Depends()):
#     try:
#         Authorize.jwt_refresh_token_required()
#         user_id = Authorize.get_jwt_subject()
#         if not user_id:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not access refresh token')
#         user = userEntity(User.find_one({'_id': ObjectId(str(user_id))}))
#         if not user:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='The user belonging to this token does not exists any longer')
#         access_token = Authorize.create_access_token(
#             subject=str(user['id']), expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
#         )
#     except Exception as e:
#         error = e.__class__.__name__
#         if error == 'MissingTokenError':
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Please provide refresh token')
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
#
#     response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
#                         ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
#     response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
#                         ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')
#     return {'access_token': access_token}
#
# @router.get('/logout', status_code=status.HTTP_200_OK)
# def logout(response: Response, Authorize: AuthJWT = Depends(), user_id: str = Depends(oauth2.require_user)):
#     Authorize.unset_jwt_cookies()
#     response.set_cookie('logged_in', '', -1)
#
#     return {'status': 'success'}
