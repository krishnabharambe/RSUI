from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('validatePhone/', views.ValidatePhoneSendOTP, name="validatePhone"),
    path('ValidatePhoneForgot/', views.ValidatePhoneForgot,
         name="ValidatePhoneForgot"),
    path('validateOtp/<phone>', views.ValidatePhoneOTP, name="validateOtp"),
    path('ForgotValidateOTP/<phone>',
         views.ForgotValidateOTP, name="ForgotValidateOTP"),
    path('register/<phone>', views.Register, name="Register"),
    path('ForgetPasswordChange/<phone>/<otp>',
         views.ForgetPasswordChange, name="ForgetPasswordChange"),
    path('login/', views.Login, name="login"),
    path('logout/', views.logout_user, name="logout"),
    path('hostservice/<MSID>', views.hostservice, name="hostservice"),
    path('bookService/<subSID>', views.bookService, name="bookService"),


    path('adminurl/', views.adminIndex, name="adminIndex"),
    path('adminurl/services', views.adminServices, name="adminServices"),
    path('adminurl/services/<id>/edit/',
         views.mainServiceEdit, name="mainServiceEdit"),
    path('adminurl/services/<id>/delete/',
         views.mainServiceDelete, name="mainServiceDelete"),

    path('adminurl/service/<id>/', views.adminSubService, name="adminSubService"),
    path('adminurl/service/<id>/add/', views.addSubservice, name="addSubservice"),
    path('adminurl/service/<id>/<sid>/edit/',
         views.editSubservice, name="editSubservice"),
    path('adminurl/service/<id>/<sid>/delete/',
         views.deleteSubservice, name="deleteSubservice"),

    path('adminurl/requests', views.adminRequests, name="adminRequests"),






]
