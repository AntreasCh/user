from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import sqlite3
from fastapi.middleware.cors import CORSMiddleware
# Database Connection
conn = sqlite3.connect('user.db')

# Security Configuration
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI App Instance
app = FastAPI()
# Add the following code before the endpoints are defined
origins = ["*"]  # Replace this with the list of allowed origins

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# OAuth2 Scheme Configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User Class
class User:
    def __init__(self, id, username, password, email, full_name):
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.full_name = full_name

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

# Helper Functions
def get_user_by_username(username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM user WHERE username=?", (username,))
    user = cur.fetchone()
    if user:
        return User(user[0], user[1], user[2], user[3], user[4])

def authenticate_user(username, password):
    user = get_user_by_username(username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Routes

@app.get("/user/{username}")
async def get_user_details(username: str):
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "username": user.username, "email": user.email, "full_name": user.full_name}

@app.post("/register")
async def register(user: dict):
    username = user.get("username")
    password = user.get("password")
    email = user.get("email")
    full_name = user.get("full_name")

    if not username or not password or not email or not full_name:
        raise HTTPException(status_code=401, detail="All fields are required")

    cur = conn.cursor()
    cur.execute("SELECT * FROM user WHERE username=?", (username,))
    existing_user = cur.fetchone()
    if existing_user:
        raise HTTPException(status_code=402, detail="Username already exists")

    password = pwd_context.hash(password)
    cur.execute("INSERT INTO user (username, password, email, full_name) VALUES (?, ?, ?, ?)", (username, password, email, full_name))
    conn.commit()
    return {"message": "User created successfully"}


@app.post("/token")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = get_user_by_username(username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        return {"id": user.id, "username": user.username, "email": user.email, "full_name": user.full_name}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please log in again.")
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(status_code=401, detail="Could not validate credentials. Please log in again.")


