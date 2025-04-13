from django.db import models
from django.contrib.auth.models import User,AbstractBaseUser
# Create your models here.


class User(AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True)
    status = models.CharField(max_length=255, default='active')
