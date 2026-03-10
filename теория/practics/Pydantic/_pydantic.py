from fastapi import FastAPI
import uvicorn
from pydantic import BaseModel, Field, ConfigDict, EmailStr

app = FastAPI()

users = []

data = {
        "email": "abc@mail.com",
        "bio": None,
        "age": 15
}

class UserSchema(BaseModel):
    email: EmailStr 
    bio: str | None = Field(max_length=10)
    
class UserAgeSchema(UserSchema):
    age: int = Field(ge=12, le=120)
    model_config = ConfigDict(extra="forbid")
    
@app.post("/users")
def add_user(user: UserAgeSchema):
    users.append(user)
    return {"success": True, "message": "Пользователь добавлен"}

@app.get("/users")
def get_users() -> list[UserAgeSchema]: # Пример возвращаемых данных в Swagger
    return users

# user = UserAgeSchema(**data)
# print(repr(user))

if __name__ == "__main__":
    uvicorn.run("_pydantic:app", host="127.0.0.1", port=8000, reload=True)

