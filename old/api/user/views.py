from django.shortcuts import render
from .models import User
from ....profiles.serializers import *

from rest_framework import status, viewsets

from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from rest_framework_simplejwt.views import TokenObtainPairView,TokenVerifyView
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
# from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response


from drf_yasg.utils import swagger_auto_schema

import jwt
import time
from django.contrib.auth import get_user_model


from django.conf import settings


# Create your views here.


class CustomTokenObtainPairView(TokenObtainPairView):
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
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[api_settings.JWT_ALGORITHM])

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
