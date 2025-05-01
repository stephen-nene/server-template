from django.shortcuts import render
from .models import User
from .serializers import *
from django.views import View
from django.http import JsonResponse

from rest_framework import status, viewsets

from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from rest_framework_simplejwt.views import TokenObtainPairView,TokenVerifyView,TokenRefreshView,TokenBlacklistView
# from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from rest_framework_simplejwt.settings import api_settings

# from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import RetrieveAPIView


from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

import jwt
import requests
import time
from django.contrib.auth import get_user_model


from django.conf import settings

# Create your views here.

class FunnyAPIView(APIView):
    """
    A view that provides various types of funny content.
    """
    permission_classes = [AllowAny]
    def get_chuck_norris_joke(self):
        """Fetch a random Chuck Norris joke."""
        try:
            response = requests.get("https://api.chucknorris.io/jokes/random", timeout=5)
            response.raise_for_status()  # Raise an error for bad status codes
            return response.json().get("value", "Chuck Norris is too powerful to joke about.")
        except (requests.RequestException, ValueError):
            return "Chuck Norris once roundhouse kicked a server, and it's still down."

    def get_dad_joke(self):
        """Fetch a random dad joke."""
        try:
            headers = {"Accept": "application/json"}
            response = requests.get("https://icanhazdadjoke.com/", headers=headers, timeout=5)
            response.raise_for_status()
            return response.json().get("joke", "Why don't skeletons fight each other? They don't have the guts.")
        except (requests.RequestException, ValueError):
            return "I'm reading a book on anti-gravity. It's impossible to put down!"

    def get_random_meme(self):
        """Fetch a random meme image."""
        try:
            response = requests.get("https://some-random-api.com/meme", timeout=5)
            response.raise_for_status()
            return response.json().get("image", "https://i.imgur.com/funny-meme.jpg")
        except (requests.RequestException, ValueError):
            return "https://i.imgur.com/fallback-meme.jpg"

    def get_programming_joke(self):
        """Fetch a random programming joke."""
        try:
            response = requests.get("https://official-joke-api.appspot.com/jokes/programming/random", timeout=5)
            response.raise_for_status()
            if response.json():
                return response.json()[0]
            return {"setup": "Why do programmers prefer dark mode?", "punchline": "Because light attracts bugs."}
        except (requests.RequestException, ValueError):
            return {"setup": "Why do programmers hate nature?", "punchline": "It has too many bugs."}

    def get_inspirational_quote(self):
        """Fetch a random inspirational quote."""
        try:
            response = requests.get("https://api.quotable.io/random", timeout=5)
            response.raise_for_status()
            return {
                "quote": response.json().get("content", "Stay hungry, stay foolish."),
                "author": response.json().get("author", "Steve Jobs"),
            }
        except (requests.RequestException, ValueError):
            return {
                "quote": "When something is important enough, you do it even if the odds are not in your favor.",
                "author": "Elon Musk",
            }

    """
    A fun API to return different kinds of funny content.
    """

    @swagger_auto_schema(
        operation_summary="Get a random funny content",
        operation_description="""
        Returns a funny or inspirational piece of content based on the `type` query parameter.

        Supported types:
        - `chuck_norris` → Chuck Norris joke
        - `dad_joke` → Dad joke
        - `meme` → Meme image
        - `programming_joke` → Programming joke
        - `inspirational_quote` → Inspirational quote
        """,
        manual_parameters=[
            openapi.Parameter(
                'type',
                openapi.IN_QUERY,
                description="Type of funny content to fetch",
                type=openapi.TYPE_STRING,
                enum=[
                    'chuck_norris',
                    'dad_joke',
                    'meme',
                    'programming_joke',
                    'inspirational_quote'
                ],
                default='chuck_norris',
                required=False
            )
        ],
        responses={
            200: openapi.Response(description="Funny content retrieved successfully"),
            400: "Invalid content type",
            500: "Server error fetching content"
        },
        tags=["Fun"]
    )
    def get(self, request):
        content_type = request.GET.get("type", "chuck_norris")

        content = {}
        try:
            if content_type == "chuck_norris":
                res = requests.get("https://api.chucknorris.io/jokes/random", timeout=5)
                res.raise_for_status()
                content = {"chuck_norris_joke": res.json().get("value")}
            elif content_type == "dad_joke":
                headers = {"Accept": "application/json"}
                res = requests.get("https://icanhazdadjoke.com/", headers=headers, timeout=5)
                res.raise_for_status()
                content = {"dad_joke": res.json().get("joke")}
            elif content_type == "meme":
                res = requests.get("https://some-random-api.com/meme", timeout=5)
                res.raise_for_status()
                content = {"meme": res.json().get("image")}
            elif content_type == "programming_joke":
                res = requests.get("https://official-joke-api.appspot.com/jokes/programming/random", timeout=5)
                res.raise_for_status()
                joke = res.json()[0] if res.json() else {}
                content = {"programming_joke": joke}
            elif content_type == "inspirational_quote":
                res = requests.get("https://api.quotable.io/random", timeout=5)
                res.raise_for_status()
                quote_data = res.json()
                content = {
                    "inspirational_quote": {
                        "quote": quote_data.get("content"),
                        "author": quote_data.get("author")
                    }
                }
            else:
                return Response({
                    "error": "Invalid content type.",
                    "supported_types": [
                        "chuck_norris", "dad_joke", "meme", "programming_joke", "inspirational_quote"
                    ]
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "status": "100% 🔥 Ready to roll!",
            # "message": "Welcome to the ultimate API of chaos!",
            **content,
            "DIY":"url/?type=chuck_norris"
        })


class CustomTokenRefreshView(TokenRefreshView):
    @swagger_auto_schema(
        operation_summary="Refresh a JWT token",
        operation_description="Returns a new JWT token pair using the refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description="Refresh token"),
            }
        ),
        responses={
            200: openapi.Response(
                description="New token pair",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access_token': openapi.Schema(type=openapi.TYPE_STRING, description="New access token"),
                        'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description="New refresh token"),
                    }
                )
            )
        },
        tags=["Auth"]
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
class CustomeTokenBlacklistView(TokenBlacklistView):
    """
    Custom view to handle token blacklisting.
    """
    @swagger_auto_schema(
        operation_summary="Blacklist a JWT token",
        operation_description="Blacklists the provided refresh token.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description="Refresh token"),
            }
        ),
        responses={
            205: "Token blacklisted successfully",
            400: "Invalid token or already blacklisted"
        },
        tags=["Auth"]
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
# Login
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Extends TokenObtainPairView to also return user data along with the token.
    """
    @swagger_auto_schema(
        operation_summary="Obtain a JWT token pair",
        operation_description="Returns a JWT token pair along with the user information.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description="Username"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="Password"),
            }        
        ),
        responses={
            200: openapi.Response(
                description="Token pair and user information",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access_token': openapi.Schema(type=openapi.TYPE_STRING, description="Access token"),
                        'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description="Refresh token"),
                        'user_info': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="User ID"),
                                'username': openapi.Schema(type=openapi.TYPE_STRING, description="Username"),
                                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email"),
                            }
                        )
                    }
                )
            )
        },
        tags=["Auth"]
        
        
    )
    def post(self, request, *args, **kwargs):
        # First, call the original post method to get the token
        response = super().post(request, *args, **kwargs)
        
        # After obtaining the token, get the user information
        user = request.user
        user_data = UserSerializer(user).data  # Serialize the user data
        
        # Return the token along with user info
        return Response({
            'access_token': response.data['access'],
            'refresh_token': response.data['refresh'],
            'user_info': user_data
        }, status=status.HTTP_200_OK)
    
class MeView(APIView):
    """
    View to get the current user's information.
    """
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_summary="Get current user information",
        operation_description="Returns the information of the currently authenticated user.",
        responses={
            200: openapi.Response(
                description="User information",
                schema=UserSerializer()
            ),
            401: "Unauthorized"
        },
        tags=["Auth"]
    )
    def get(self, request):
        user = request.user
        if user.is_authenticated:
            user_data = UserSerializer(user).data
            return Response(user_data, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

class UserCreateView(APIView):
    # will have a create an get. get will be used to actiavte a user account using the token
    # create will be used to create a new user
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_summary="Create a new user",
        operation_description="Creates a new user with the provided information.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description="Username"),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Email"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="Password"),
                
            }
        ),
        responses={
            201: openapi.Response(
                description="User created successfully",
                schema=UserSerializer()
            ),
            400: "Invalid data"
            
        },
        tags=["Auth",'users']
    )
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            # send a welcome email here
            # send_activation_email(user)
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    # will get a token in the url to activate the user account related with it
    
    @swagger_auto_schema(
        operation_summary="Activate a user account",
        operation_description="Activates the user account associated with the provided token.",
        manual_parameters=[
            openapi.Parameter(
                'token',
                openapi.IN_QUERY,
                description="Activation token",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="User account activated successfully",
                schema=UserSerializer()
            ),
            400: "Invalid token",
            404: "User not found"
        } ,       
        tags=["Auth"]
    )
    
    def get(self,request):        
        token = request.query_params.get('token')
        try:
            payload  = jwt.decode(token, settings.SECRET_KEY, algorithms=[api_settings.ALGORITHM])

            user_id = payload.get('user_id')
            if user_id is None:
                return Response({"detail": "Invalid token payload."}, status=status.HTTP_400_BAD_REQUEST)
            user = User.objects.get(id=user_id)
            if not user.is_active:
                user.is_active = True
                user.email_verified = True
                user.save()
                return Response(UserSerializer(user).data, status=status.HTTP_200_OK)
            return Response({"detail": "User is already active."}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({"detail": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError as e:
            return Response({"detail": "Invalid token.", "info":str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserProfileView(RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_summary="Get user profile",
        operation_description="Returns the profile information of the specified user.",
        responses={
            200: openapi.Response(
                description="User profile information",
                schema=UserSerializer()
            ),
            404: "User not found",
            401: "Unauthorized"
        },
        tags=["Auth"]
    )

    def get_object(self):
        return self.request.user
       
class TokenVerifyViewExtended(TokenVerifyView):
    """
    Extends TokenVerifyView to also return user data along with the token's validity.
    """

    def post(self, request, *args, **kwargs):
        token = request.data.get("token")
        if not token:
            return Response({"detail": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode the JWT token
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

            # Check if token is expired or invalid
            if 'exp' in decoded_token and decoded_token['exp'] < int(time.time()):
                raise TokenError("Token has expired.")

            # Fetch the user using the user id from the decoded token
            user_id = decoded_token.get('user_id')  # Assuming 'user_id' is stored in the token
            if not user_id:
                raise TokenError("No user data in token.")
            
            # Retrieve the user instance
            User = get_user_model()
            user = User.objects.get(id=user_id)

            # Call the original TokenVerifyView post method
            response = super().post(request, *args, **kwargs)

            # Return the response with user data and token validity
            response.data['valid'] = True
            response.data['user'] = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
            return response

        except jwt.ExpiredSignatureError:
            return Response({"detail": "Token has expired."}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.DecodeError:
            return Response({"detail": "Token is invalid."}, status=status.HTTP_401_UNAUTHORIZED)
        except TokenError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)





class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.

    * `list`: Returns a list of all users.
    * `retrieve`: Returns the specified user.
    * `create`: Creates a new user.
    * `update`: Updates the specified user.
    * `destroy`: Deletes the specified user.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    # -------------------------
    # 🟩 LIST
    # -------------------------
    @swagger_auto_schema(
        operation_summary="List all users.",
        responses={200: UserSerializer(many=True)},
        tags=["users"]
    )
    def list(self, request, *args, **kwargs):
        """
        List all users.
        """
        return super().list(request, *args, **kwargs)

    # -------------------------
    # 🟩 RETRIEVE
    # -------------------------
    @swagger_auto_schema(
        operation_summary="Retrieve a user.",
        responses={200: UserSerializer()},
        tags=["users"]
    )
    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific user by ID.
        """
        return super().retrieve(request, *args, **kwargs)

    # -------------------------
    # 🟩 CREATE
    # -------------------------
    @swagger_auto_schema(
        operation_summary="Create a new user.",
        responses={201: UserSerializer()},
        tags=["users"]
    )
    def create(self, request, *args, **kwargs):
        """
        Create a new user.
        """
        return super().create(request, *args, **kwargs)

    # -------------------------
    # 🟩 UPDATE
    # -------------------------
    @swagger_auto_schema(
        operation_summary="Update a user.",
        responses={200: UserSerializer()},
        tags=["users"]
    )
    def update(self, request, *args, **kwargs):
        """
        Fully update a user.
        """
        return super().update(request, *args, **kwargs)

    # -------------------------
    # 🟫 PARTIAL UPDATE (PATCH)
    # -------------------------
    @swagger_auto_schema(
        operation_summary="Partially update a user.",
        responses={200: UserSerializer()},
        tags=["users"]
    )
    def partial_update(self, request, *args, **kwargs):
        """
        Partially update a user.
        """
        return super().partial_update(request, *args, **kwargs)

    # -------------------------
    # 🟩 DESTROY
    # -------------------------
    @swagger_auto_schema(
        operation_summary="Delete a user.",
        responses={204: "No content"},
        tags=["users"]
    )
    def destroy(self, request, *args, **kwargs):
        """
        Delete a user.
        """
        return super().destroy(request, *args, **kwargs)
