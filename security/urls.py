from django.urls import path

from security import views

urlpatterns = [
    path('get_rsa_pub/', views.get_rsa_pub, name='get_rsa_pub'),
    path('create_session/', views.create_session, name='create_session'),
    path('user_bundle_key/', views.get_key_bundle, name='get_key_bundle'),
    path('send_x3dh/', views.send_x3dh, name='send_x3dh'),
    path('send_message/', views.send_message, name='send_message'),

]
