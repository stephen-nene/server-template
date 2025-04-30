from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


# Emuns

class UserStatus(models.TextChoices):
    ACTIVE = 'active'
    INACTIVE = 'inactive'
    PENDING = 'pending'
    SUSPENDED = 'suspended'
    DELETED = 'deleted'
    

class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        
        
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            email=self.normalize_email(email),
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_staff', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, TimeStampedModel):
    email = models.EmailField(max_length=255, unique=True)
    status= models.CharField(max_length=20, choices=UserStatus.choices, default=UserStatus.INACTIVE)
    
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin