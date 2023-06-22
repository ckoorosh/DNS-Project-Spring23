from django.db import models


class User(models.Model):
    name = models.CharField(max_length=200)
    username = models.CharField(max_length=200, unique=True)
    password = models.CharField(max_length=200)
    salt = models.CharField(max_length=200)
    public_key = models.TextField()
    pk_identifier = models.CharField(max_length=200)

    def set_pk_identifier(self):
        # sha256 of public key
        self.pk_identifier = "todo"

    def set_password(self, password):
        self.salt = "todo"
        self.password = "todo"


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
