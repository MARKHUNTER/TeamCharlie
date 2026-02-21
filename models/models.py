from pydantic import BaseModel

class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None


class ContentUpload(BaseModel):
    title: str
    body: str
    content_type: Optional[str] = "lesson"
    metadata: Optional[dict] = None


class ContentSearch(BaseModel):
    query: str
    limit: Optional[int] = 5
