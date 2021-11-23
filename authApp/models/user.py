from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.hashers import make_password

class UserManager(BaseUserManager):
    def create_user(self, username, password=None):
        """
        Creates and saves a user with the given username and password.
        """
        if not username:
            raise ValueError('Users must have an username')
        user = self.model(username=username)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password):
        """
        Creates and saves a superuser with the given username and password.
        """
        user = self.create_user(
            username=username,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True)
    nameCompany = models.CharField('Nombre de la tienda', max_length = 40)
    position = models.CharField('Cargo', max_length = 40)
    email = models.EmailField('Email del trabajo', max_length = 100, unique=True)
    username = models.CharField('Nombre de Usuario', max_length = 15, unique=True)
    firstName = models.CharField('Nombre', max_length = 40)
    lastName = models.CharField('Apellido', max_length = 40)
    password = models.CharField('Contraseña', max_length = 256)
      
      
    def save(self, **kwargs):
        some_salt = 'mMUj0DrIK6vgtdIYepkIxN' 
        self.password = make_password(self.password, some_salt)
        super().save(**kwargs)

    objects = UserManager()
    USERNAME_FIELD = 'username'
