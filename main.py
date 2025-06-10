from fastapi import FastAPI,Depends,HTTPException,status
from database import Base,engine,SessionLocal
from sqlalchemy.orm import Session
from Schemas import User,Admin,EmailModel, SignUpEmailModel, UserResponseModel,AdminUpdateModel, AdminResponseModel, UserLoginModel,UserUpdateModel
from models import UserModel,AdminModel
from auth import hashed_password,verify_password,create_admin_token,create_user_token,decode_user_token,decode_admin_token
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from mail import create_message,mail
from config import settings
from auth import create_user_safe_url_token,decode_user_safe_url_token,create_admin_safe_url_token,decode_admin_safe_url_token

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_user_bearer = OAuth2PasswordBearer(tokenUrl="/userlogin")
oauth2_admin_bearer = OAuth2PasswordBearer(tokenUrl="/adminlogin")

@app.post("/sent_email",tags=["Email Notification"])
async def send_mail(emails: EmailModel):
    emails = emails.addresses
    html = "<h1>There is an Server Issue at this time please sign up / log in later</h1>"
    message = create_message(recipients=emails,subject="Welcome",body=html)
    await mail.send_message(message)
    return {"Message":"email sent successfully"}

@app.post("/usersignup",tags=["User Login/Sign Up"])
async def Create_user(user : User,db: Session = Depends(get_db)):
    
    existing_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail="User Already Exist")
    else:
        token_data = {"email":user.email,"username":user.username,"hashed_password":hashed_password(user.password)}
        token = create_user_safe_url_token(token_data)
        link = f"http://{settings.DOMAIN}/verify_user/{token}"
        html_message = f"""
           <h3>Hello {user.username}!</h3>
           <p>Thanks for signing up. Please verify your email address by clicking the link below:</p>
           <a href="{link}">verify link</a>
           """
        message = create_message(recipients=[user.email],subject="Verify Your Email",body=html_message)
        await mail.send_message(message,template_name="verify_email.html")
        return {"message":"Verification Link Sent Successfully!"}

@app.get("/verify_user/{token}",tags=["User Login/Sign Up"])
async def verify_email(token:str,db:Session = Depends(get_db)):
    try:
        token_data = decode_user_safe_url_token(token)
        email = token_data["email"]
        username = token_data["username"]
        hashed_password = token_data["hashed_password"]
    
    except Exception:
        raise HTTPException(status_code=400,detail="Invalid or expired token")
    
    existing_user = db.query(UserModel).filter(UserModel.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400,detail="User already verified")
    
    new_user = UserModel(email = email,username=username,password=hashed_password,is_verified=True)
    db.add(new_user)
    db.commit()
    return {"Message":"Email verified Successful. Account Created"}


@app.post("/userlogin",tags=["User Login/Sign Up"])
def user_login(form_data:OAuth2PasswordRequestForm=Depends(),db: Session = Depends(get_db)):
    user_name = db.query(UserModel).filter(UserModel.username == form_data.username).first()
    if user_name:
        verify = verify_password(form_data.password , user_name.password)
        if verify:
           token = create_user_token({'sub':user_name.username})
           return {"access_token":token,"token_type":"bearer"}
        else: 
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid credentials")
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User Not Found")
   
    
def get_user(token: str = Depends(oauth2_user_bearer),db: Session = Depends(get_db)):
    data = decode_user_token(token)
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Token")
    else:
        username= data["sub"]
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="User not Found")
        return user
      
@app.post("/adminsignup",tags=["Admin Login/SignUp"])
async def create_admin(ad : Admin,db: Session = Depends(get_db)):
    existing_admin = db.query(AdminModel).filter(AdminModel.email == ad.email).first()
    if existing_admin:
        raise HTTPException(status_code=409,detail="Admin already exist")
    else:
        token_data = {"admin_name":ad.admin_name,"email":ad.email,"password":hashed_password(ad.password)}
        token = create_admin_safe_url_token(token_data)
        link = f"http://{settings.DOMAIN}/verify_admin/{token}"
        html_message = f"""
        <h3> Hey {ad.admin_name}!</h3>
        <p> Please follow the link to verify your details</p>
        <a href="{link}">Verify Link</a>
        """
        message = create_message(recipients=[ad.email],subject="Sign up Verification",body=html_message)
        await mail.send_message(message,template_name="verify_email.html")
        return {"Message":"Verification link sent Successfully"}
    
@app.get("/verify_admin/{token}",tags=["Admin Login/SignUp"])
async def verify_mail(token:str,db:Session=Depends(get_db)):
    try:
        token_data = decode_admin_safe_url_token(token)
        admin_name = token_data["admin_name"]
        email = token_data["email"]
        password = token_data["password"]

    except Exception:
        raise HTTPException(status_code=400,detail="Invalid or Token Expired!")
    
    existing_admin = db.query(AdminModel).filter(AdminModel.email == email).first()
    if existing_admin:
        raise HTTPException(status_code=400,detail="Admin Already Exists!")
    else:
        new_admin = AdminModel(admin_name = admin_name,email=email,password = password,is_verified = True)
        db.add(new_admin)
        db.commit()
        return {"Message": "Email Verified successfully, Admin Account Created"}

@app.post("/adminlogin",tags=["Admin Login/SignUp"])
def admin_login(form_data : OAuth2PasswordRequestForm = Depends(),db: Session = Depends(get_db)):
    admin_name = db.query(AdminModel).filter(AdminModel.admin_name == form_data.username).first()
    if admin_name:
        verify = verify_password(form_data.password,admin_name.password)
        if verify:
            token = create_admin_token({"sub":admin_name.admin_name})
            return {"access_token":token,"token_type":"bearer"}
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid Credentials")
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail= "Admin not found")

    
def get_admin(token: str = Depends(oauth2_admin_bearer),db:Session = Depends(get_db)):
    data = decode_admin_token(token)
    if not data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Token")
    else:
        return data['sub']
    
@app.put("/userupdate/{username}",response_model=UserResponseModel,tags=["Admin Things"])
def update_user(username:str,data: UserUpdateModel,admin: AdminModel= Depends(get_admin),db: Session = Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name == admin).first()
    if admin:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="User not Found")
        if data.username is not None:
            user.username = data.username
        if data.email is not None:
            user.email = data.email
        if data.password is not None:
            user.password = data.password
        if data.salary is not None:
            user.salary = data.salary
        db.commit()
        db.refresh(user)
        return user
    
@app.put("/adminupdate/{admin_name}",response_model=AdminResponseModel,tags=["Admin Things"])
def update_admin(admin_name:str,data:AdminUpdateModel,admin: AdminModel= Depends(get_admin),db:Session = Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name == admin_name).first()
    if admin:
        if data.admin_name is not None:
            admin.admin_name = data.admin_name
        if data.email is not None:
            admin.email = data.email
        if data.password is not None:
            admin.password = data.password
        if data.salary is not None:
            admin.salary = data.salary
        db.commit()
        db.refresh(admin)
        return admin

@app.get("/All_users",tags=["User Things"])
def view_all_users(db:Session = Depends(get_db)):
    all_users = db.query(UserModel).all()
    return all_users

@app.get("/user_by_id/{id}",tags=["User Things"],response_model=UserResponseModel)
def view_user_by_id(id: int, db: Session=Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.id == id).first()
    return user

@app.get("/user_by_name/{name}",tags=["User Things"],response_model=UserResponseModel)
def view_user_by_name(name: str, db: Session=Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == name).first()
    return user

@app.get("/all_Admins",tags=["Admin Things"])
def view_admins(db: Session=Depends(get_db)):
    admins = db.query(AdminModel).all()
    return admins

@app.get("/admin_by_name/{name}",tags=["Admin Things"],response_model=AdminResponseModel)
def view_admin_by_name(name: str, db: Session=Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name == name).first()
    return admin

@app.get("/admin_by_id/{id}",tags=["Admin Things"],response_model=AdminResponseModel)
def view_user_by_id(id: int, db: Session=Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.id == id).first()
    return admin

@app.delete("/delete_user/{id}",tags=["Admin Things"])
def delete_user_by_id(id:int,admin:AdminModel=Depends(get_admin),db:Session=Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name== admin).first()
    if admin:
        user = db.query(UserModel).filter(UserModel.id == id).first()
        if user:
            db.delete(user)
            db.commit()
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="User Not Found")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Admin not Found")
    
@app.delete("/delete_user_by_name/{name}",tags=["Admin Things"])
def delete_user_by_name(name:str,admin:AdminModel=Depends(get_admin),db:Session=Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name== admin).first()
    if admin:
        user = db.query(UserModel).filter(UserModel.username == name).first()
        if user:
            db.delete(user)
            db.commit()
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="User Not Found")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Admin not Found")
    

@app.delete("/delete_admin_by_id/{id}",tags=["Admin Things"])
def delete_admin_by_id(id:int,admin:AdminModel = Depends(get_admin),db:Session = Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name == admin).first()
    if admin:
        admin_id = db.query(AdminModel).filter(AdminModel.id == id).first()
        if admin_id:
            db.delete(admin_id)
            db.commit()
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Admin Id not found")
        
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Admin Not Found")
    

@app.delete("/delete_admin_by_name/{name}",tags=["Admin Things"])
def delete_admin_by_id(name:str,admin:AdminModel = Depends(get_admin),db:Session = Depends(get_db)):
    admin = db.query(AdminModel).filter(AdminModel.admin_name == admin).first()
    if admin:
        admin_name = db.query(AdminModel).filter(AdminModel.admin_name == name).first()
        if admin_name:
            db.delete(admin_name)
            db.commit()
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Admin name not found")
        
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="Admin Not Found")    