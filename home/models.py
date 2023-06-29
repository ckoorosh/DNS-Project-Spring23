from django.db import models
import hashlib
import secrets


class User(models.Model):
    name = models.CharField(max_length=200)
    username = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=200)
    salt = models.CharField(max_length=200)
    public_key = models.TextField()
    pk_identifier = models.CharField(max_length=200)

    def set_pk_identifier(self):
        self.pk_identifier = hashlib.sha256(self.public_key.encode()).hexdigest()

    def set_password(self, password):
        self.salt = secrets.token_urlsafe(16)
        self.password = hashlib.sha256(password.encode() + self.salt.encode()).hexdigest()


class UserPublicKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    public_key = models.TextField()


class GroupChat(models.Model):
    name = models.CharField(max_length=200)


class GroupChatUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(GroupChat, on_delete=models.CASCADE)
    role = models.CharField(max_length=200)


class QueueMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=200)
    timestamp = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=200)
