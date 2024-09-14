from django.contrib.auth.models import User
from ninja import Router
from ninja.security import HttpBearer
from rest_framework_simplejwt.tokens import RefreshToken
from ninja.errors import HttpError
from authentication.schema import LoginSchema, RegisterSchema

router = Router()

class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        try:
            return RefreshToken(token).check_blacklist()
        except Exception as e:
            raise HttpError(401, "Invalid token")
        
@router.post("/login")
def login(request, data: LoginSchema):
    try:  
        user = User.objects.get(username=data.phone_number)
        if not user.check_password(data.password):  # Use the built-in method
            raise HttpError(404, "User not found")
        
        refresh = RefreshToken.for_user(user)
        return {
            'message': "Login successful",
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    except User.DoesNotExist:
        raise HttpError(404, "User not found")
    
@router.post("/register")
def register(request, data: RegisterSchema):
    if User.objects.filter(username=data.phone_number).exists():
        raise HttpError(400, "User already exists")
    
    user = User.objects.create_user(
        username=data.phone_number,
        password=data.password,
        first_name=data.first_name,
        last_name=data.last_name
    )
    refresh = RefreshToken.for_user(user)

    return {
        "message": "User created successfully",
        "refresh": str(refresh),
        "access": str(refresh.access_token)
    }

@router.get("/protected", auth=JWTAuth())
def protected_route(request):
    return {"message": "You are authenticated"}