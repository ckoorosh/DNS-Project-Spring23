from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from home import views

urlpatterns = [
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),
    path('send_chat_message/', views.send_chat_message, name='send_chat_message'),
]