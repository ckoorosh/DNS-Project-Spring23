from django.urls import path

from security import views

urlpatterns = [
    path('get_rsa_pub/', views.get_rsa_pub, name='get_rsa_pub'),
]
