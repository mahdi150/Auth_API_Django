from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser,BaseUserManager



class ClientManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, username=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, name, password, **extra_fields)


class Client(AbstractUser):
    name = models.CharField(max_length=20)
    email = models.EmailField(max_length=20, unique=True)
    objects = ClientManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']





