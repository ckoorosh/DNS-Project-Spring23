from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from home import views

urlpatterns = [
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),
    path('send_chat_message/', views.send_chat_message, name='send_chat_message'),
    path('send_group_message/', views.send_group_message, name='send_group_message'),
    path('create_group/', views.create_group, name='create_group'),
    path('show_group_chats/', views.show_group_chats, name='show_group_chats'),
    path('add_member_to_group/', views.add_member_to_group, name='add_member_to_group'),
    path('remove_member_from_group/', views.remove_member_from_group, name='remove_member_from_group'),
    path('make_member_admin/', views.make_member_admin, name='make_member_admin'),
    path('view_online_users/', views.view_online_users, name='view_online_users'),
    path('send_public_keys/', views.send_public_keys, name='send_public_keys'),
    path('get_members/', views.get_members, name='get_members')
]