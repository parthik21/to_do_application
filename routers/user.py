import sys

from starlette.responses import RedirectResponse

sys.path.append("..")

from fastapi import Depends, status, APIRouter, Request, Form
import models
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from .auth import get_current_user

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "KlgH6AzYDeZeGwD288to79I3vTHT8wp7"
ALGORITHM = "HS256"

router = APIRouter(
    prefix="/user",
    tags=["User"],
    responses={404: {"description": "Not found"}}
)

models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()



def get_password_hash(password):
    return bcrypt_context.hash(password)


@router.get("/profile", response_class=HTMLResponse)
async def user_profile(request: Request,
                       db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    user_data = db.query(models.Users).filter(models.Users.id == user.get('id')).first()

    user_dict = {'username': user_data.username,
                 'firstname': user_data.first_name,
                 'lastname': user_data.last_name,
                 'email': user_data.email}

    return templates.TemplateResponse('profile.html', {'request': request, "user": user_dict})


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse('change-password.html', {'request': request, "user": user})


@router.post("/change-password", response_class=HTMLResponse)
async def change_password(request: Request,
                          old_password: str = Form(...),
                          new_password: str = Form(...),
                          new_password2: str = Form(...),
                          db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    if new_password != new_password2:
        msg = "Enter same new passwords"
        return templates.TemplateResponse("change-password.html", {"request": request, "msg": msg})

    user_model = db.query(models.Users).filter(models.Users.id == user.get("id")).first()

    if not bcrypt_context.verify(old_password, user_model.hashed_password):
        msg = "Incorrect old password"
        return templates.TemplateResponse("change-password.html", {"request": request, "msg": msg})

    hash_new_password = get_password_hash(new_password)
    user_model.hashed_password = hash_new_password

    db.add(user_model)
    db.commit()

    msg = "Password has been re-set successfully"
    return RedirectResponse(url="/user/profile", status_code=status.HTTP_302_FOUND)
