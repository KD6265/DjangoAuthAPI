
from django.contrib import admin
from django.urls import path,include
from account.views import UserRegistrationView,UserLoginView,UserProfileView,UserChangePasswordView,UserRestPasswordEmailView,UserSetRestPasswordView

urlpatterns = [
    path('registration/',UserRegistrationView.as_view(),name='registration'),
    path('login/',UserLoginView.as_view(),name='login'),    
    path('profile/',UserProfileView.as_view(),name='profile'), 
    path('changepassword/',UserChangePasswordView.as_view(),name='changepassword'),
    path('resetpasswordsend/',UserRestPasswordEmailView.as_view(),name='resetpasswordsend'),
    path('resetpasswords/<uid>/<token>/',UserSetRestPasswordView.as_view(),name='resetpasswords'),
]
