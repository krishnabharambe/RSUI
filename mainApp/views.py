from django.http import request
from django.shortcuts import redirect, render, HttpResponse
from .models import M_Services, M_SubServices, PhoneOTP, User, RServices, RServices
from django.shortcuts import get_object_or_404
from random import randint
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.db.models import Q


def adminRequests(request):
    newRequests = RServices.objects.filter(status="new")
    return render(request, 'adminPanel/Srequests/requests.html', {'newRequests': newRequests})


def deleteSubservice(request, id, sid):
    mainService = M_Services.objects.get(id=id)
    subservice = M_SubServices.objects.get(id=sid)
    if request.method == "POST":
        subService = subservice
        subService.delete()
        return redirect("adminSubService", id=id)
    else:
        return render(request, "adminPanel/service/DeleteSubservice.html", {"mainService": mainService, 'subservice': subservice})


def editSubservice(request, id, sid):
    mainService = M_Services.objects.get(id=id)
    subservice = M_SubServices.objects.get(id=sid)
    if request.method == "POST":
        subService = subservice
        subService.title = request.POST['title']
        subService.MainService = mainService
        subService.description = request.POST['description']
        subService.shortdescription = request.POST['shortdescription']

        if "status" in request.POST:
            subService.status = request.POST['status']

        if "icon" in request.FILES:
            subService.icon = request.FILES['icon']

        subService.save()
        return redirect("adminSubService", id=id)
    else:
        return render(request, "adminPanel/service/EditSubservice.html", {"mainService": mainService, 'subservice': subservice})


def addSubservice(request, id):
    mainService = M_Services.objects.get(id=id)

    if request.method == "POST":
        subService = M_SubServices()
        subService.title = request.POST['title']
        subService.MainService = mainService
        subService.description = request.POST['description']
        subService.shortdescription = request.POST['shortdescription']
        subService.status = request.POST['status']
        subService.icon = request.FILES['icon']
        subService.banner = request.FILES['banner']
        subService.save()
        return redirect("adminSubService", id=id)
    else:
        return render(request, "adminPanel/service/service.html", {"mainService": mainService})


def adminSubService(request, id):
    mainService = M_Services.objects.get(id=id)
    subservice = M_SubServices.objects.filter(MainService=mainService)
    return render(request, "adminPanel/service/service.html", {"mainService": mainService, "subservice": subservice})


def mainServiceDelete(request, id):
    mainService = M_Services.objects.get(id=id)
    if request.method == "POST":
        mainService = mainService
        mainService.delete()
        return redirect('adminServices')
    else:
        return render(request, "adminPanel/service/mainService/mainServiceDelete.html", {'mainService': mainService})


def mainServiceEdit(request, id):
    mainService = M_Services.objects.get(id=id)
    if request.method == "POST":
        service = mainService
        service.title = request.POST['title']
        service.description = request.POST['description']
        service.shortdescription = request.POST['shortdescription']
        if 'status' in request.POST:
            service.status = request.POST['status']
        if 'icon' in request.FILES:
            service.icon = request.FILES['icon']
        if 'banner' in request.FILES:
            service.banner = request.FILES['banner']
        service.save()
        return redirect('adminServices')
    else:
        return render(request, "adminPanel/service/mainService/mainServiceEdit.html", {'mainService': mainService})


def adminServices(request):
    tempData = M_Services.objects.all()
    if request.method == "POST":
        service = M_Services()
        service.title = request.POST['title']
        service.description = request.POST['description']
        service.shortdescription = request.POST['shortdescription']
        service.status = request.POST['status']
        service.icon = request.FILES['icon']
        service.banner = request.FILES['banner']
        service.save()
        return redirect('adminServices')
    else:
        return render(request, "adminPanel/MainServices.html", {'tempData': tempData})


def adminIndex(request):
    tempData = M_Services.objects.all()
    return render(request, "adminPanel/index.html", {'tempData': tempData})


def index(request):
    tempData = M_Services.objects.all()
    return render(request, "mainApp/index.html", {'tempData': tempData})


@login_required(login_url='/login/')
def bookService(request, subSID):
    subService = M_SubServices.objects.get(pk=subSID)
    user = request.user
    print(user)
    if request.method == 'POST':
        rservice = RServices()
        rservice.MainService = subService
        rservice.user = user
        rservice.phone = request.POST['phone']
        rservice.address = request.POST['address']
        rservice.location = "locaton"
        rservice.ServiceDate = request.POST['ServiceDate']
        rservice.time = request.POST['time']
        rservice.status = "new"
        rservice.save()
        return HttpResponse("Thank You")
    else:
        return render(request, 'services/bookservice.html', {'subService': subService, "authUser": user})


def hostservice(request, MSID):
    hostService = M_Services.objects.get(pk=MSID)
    subService = M_SubServices.objects.filter(MainService=hostService)
    print(subService)
    return render(request, 'services/SubServices.html', {'hostservice': hostService, 'subService': subService})


def logout_user(request):
    logout(request)
    # messages.success(request, ('You Have Been Logged Out...'))
    return redirect('index')


def ForgetPasswordChange(request, phone, otp):
    '''
    if forgot_logged is valid and account exists then only pass otp, phone and password to reset the password. All three should match.APIView
    '''

    if request.method == "POST":
        phone = phone
        otp = otp
        password = request.POST['password']

        if phone and otp and password:
            old = PhoneOTP.objects.filter(
                Q(phone__iexact=phone) & Q(otp__iexact=otp))
            if old.exists():
                old = old.first()
                if old.forgot_logged:
                    post_data = {
                        'phone': phone,
                        'password': password
                    }
                    user_obj = get_object_or_404(User, phone__iexact=phone)
                    # serializer = ForgetPasswordSerializer(data=post_data)
                    # serializer.is_valid(raise_exception=True)
                    if user_obj:
                        user_obj.set_password(password)
                        user_obj.active = True
                        user_obj.save()
                        old.delete()
                        messages.success(
                            request, ('Password changed successfully. Please Login'))
                        return redirect('login')

                else:
                    messages.error(
                        request, ('OTP Verification failed. Please try again in previous step'))
                    return redirect('ValidatePhoneForgot')

            else:
                messages.error(
                    request, ('Phone and otp are not matching or a new phone has entered. Request a new otp in forgot password'))
                return redirect('ValidatePhoneForgot')
        else:
            messages.error(
                request, ('Post request have parameters mising.'))
            return redirect('ValidatePhoneForgot')
    else:
        return render(request, "Auth/ForgetPasswordChange.html", {'phone': phone, 'otp': otp})


def ForgotValidateOTP(request, phone):
    '''
    If you have received an otp, post a request with phone and that otp and you will be redirected to reset  the forgotted password
    '''

    if request.method == "POST":
        phone = phone
        otp_sent = request.POST['otp']

        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                if old.forgot == False:
                    messages.error(
                        request, ('This phone havenot send valid otp for forgot password. Request a new otp or contact help centre.'))
                    return redirect('ForgotValidateOTP', phone=phone)

                otp = old.otp
                if str(otp) == str(otp_sent):
                    old.forgot_logged = True
                    old.save()

                    messages.success(
                        request, ('OTP matched, kindly proceed to create new password'))
                    return redirect('ForgetPasswordChange', phone=phone, otp=otp)
                else:
                    messages.error(
                        request, ('OTP incorrect, please try again'))
                    return redirect('ForgotValidateOTP', phone=phone)

            else:
                messages.error(
                    request, ('Phone not recognised. Kindly request a new otp with this number'))
                return redirect('ForgotValidateOTP', phone=phone)

        else:
            messages.error(
                request, ('Either phone or otp was not recieved in Post request'))
            return redirect('ForgotValidateOTP', phone=phone)
    else:
        return render(request, "Auth/ForgotValidateOTP.html", {'phone': phone})


def ValidatePhoneForgot(request):
    '''
    Validate if account is there for a given phone number and then send otp for forgot password reset'''

    if request.method == "POST":
        phone_number = request.POST['phone']
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                otp = send_otp_forgot(phone)
                print(phone, otp)
                if otp:
                    otp = str(otp)
                    count = 0
                    old = PhoneOTP.objects.filter(phone__iexact=phone)
                    if old.exists():
                        old2 = old.first()
                        k = old2.count
                        count = old.first().count
                        old.update(count=count + 1)
                        old.update(otp=otp)
                        if k > 500:
                            messages.error(
                                request, ('Maximum otp limits reached. Kindly support our customer care or try with different number'))
                            return redirect('ValidatePhoneForgot')

                        messages.success(
                            request, ('OTP has been sent for password reset. Limits about to reach.'))
                        return redirect('ForgotValidateOTP', phone=phone_number)

                    else:
                        count = count + 1

                        PhoneOTP.objects.create(
                            phone=phone,
                            otp=otp,
                            count=count,
                            forgot=True,

                        )

                        messages.success(
                            request, ('OTP has been sent for password reset'))
                        return redirect('ForgotValidateOTP', phone=phone_number)

                else:
                    messages.error(
                        request, ('OTP sending error. Please try after some time.'))
                    return redirect('ValidatePhoneForgot')
            else:
                messages.error(
                    request, ('Phone number not recognised. Kindly try a new account for this number'))
                return redirect('ValidatePhoneForgot')
    else:
        return render(request, "Auth/ValidatePhoneForgot.html")


def Login(request):
    if request.method == "POST":
        phone = request.POST['phone']
        password = request.POST['password']

        if phone and password:
            if User.objects.filter(phone=phone).exists():
                user = authenticate(request, phone=phone, password=password)
                if user is not None:
                    login(request, user)
                    messages.success(request, ('You Have Been Logged In!'))
                    print("Login Success")
                    return redirect('index')

                else:
                    messages.error(
                        request, ('Error Logging In - Please Try Again...'))
                    return redirect('login')

    else:
        return render(request, "Auth/login.html")


def Register(request, phone):
    if request.method == "POST":
        phone = phone
        phone2 = request.POST['phone']
        password = request.POST['password']
        if phone and password:
            phone = str(phone)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                messages.error(
                    request, 'Phone Number already have account associated. Kindly try forgot password')
                return redirect('Register', phone=phone)
            else:
                old = PhoneOTP.objects.filter(phone__iexact=phone)
                if old.exists():
                    old = old.first()
                    if old.logged:
                        print("Registration - Creating users")
                        user = User.objects.create_user(phone, password)
                        user.save()
                        print("Registration - User Saved")
                        old.delete()

                        messages.success(
                            request, 'Congrts, user has been created successfully.')
                        return redirect('login')

                    else:
                        messages.error(
                            request, 'Your otp was not verified earlier. Please go back and verify otp')
                        return redirect('Register', phone=phone)
                else:
                    messages.error(
                        request, 'Phone number not recognised. Kindly request a new otp with this number')
                    return redirect('Register', phone=phone)

        else:
            messages.error(
                request, 'Either phone or password was not recieved in Post request')
            return redirect('Register', phone=phone)
    else:
        return render(request, "Auth/Register.html", {"phone": phone})


def ValidatePhoneOTP(request, phone):

    if request.method == "POST":
        phone = phone
        otp_sent = request.POST['otp']

        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact=phone)
            if old.exists():
                old = old.first()
                otp = old.otp
                if str(otp) == str(otp_sent):
                    old.logged = True
                    old.save()
                    messages.success(
                        request, 'OTP matched, kindly proceed to save password')
                    return redirect('Register', phone=phone)
                else:
                    messages.error(
                        request, 'OTP incorrect, please try again')
                    return redirect('validateOtp', phone=phone)
            else:
                messages.error(
                    request, 'Phone not recognised. Kindly request a new otp with this number')
                return redirect('validateOtp', phone=phone)

        else:
            messages.error(
                request, 'Either phone or otp was not recieved in Post request')
            return redirect('validateOtp', phone=phone)
    else:
        return render(request, "Auth/ValidateOtp.html", {"phone": phone})


def ValidatePhoneSendOTP(request):
    if request.method == "POST":
        phone_number = request.POST['phone']
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact=phone)
            if user.exists():
                return HttpResponse({'status': False, 'detail': 'Phone Number already exists'})
                # logic to send the otp and store the phone number and that otp in table.
            else:
                otp = send_otp(phone)
                print(phone, otp)
                if otp:
                    otp = str(otp)
                    count = 0
                    old = PhoneOTP.objects.filter(phone__iexact=phone)
                    if old.exists():
                        count = old.first().count
                        old.update(count=count + 1)
                        old.first().save()
                        old.update(otp=otp)
                    else:
                        count = count + 1
                        PhoneOTP.objects.create(
                            phone=phone,
                            otp=otp,
                            count=count
                        )
                        if count > 10:
                            messages.error(
                                request, 'Maximum otp limits reached. Kindly support our customer care or try with different number')
                            return redirect('validatePhone')

                else:
                    messages.error(
                        request, 'OTP sending error. Please try after some time.')
                    return redirect('validatePhone')

                messages.success(
                    request, 'Otp has been sent successfully.')
                return redirect('validateOtp', phone=phone)
        else:

            messages.error(
                request, 'I havent received any phone number. Please do a POST request.')
            return redirect('validatePhone')

    else:
        return render(request, "Auth/ValidatePhone.html")


def send_otp(phone):
    """
    This is an helper function to send otp to session stored phones or
    passed phone number as argument.
    """

    if phone:

        key = randint(1000, 9999)
        phone = str(phone)
        otp_key = str(key)

        # link = f'https://2factor.in/API/R1/?module=TRANS_SMS&apikey=fc9e5177-b3e7-11e8-a895-0200cd936042&to={phone}&from=wisfrg&templatename=wisfrags&var1={otp_key}'

        # result = requests.get(link, verify=False)

        return otp_key
    else:
        return False


def send_otp_forgot(phone):
    if phone:
        key = randint(1000, 9999)
        phone = str(phone)
        otp_key = str(key)
        user = get_object_or_404(User, phone__iexact=phone)
        if user.name:
            name = user.name
        else:
            name = phone

        # link = f'https://2factor.in/API/R1/?module=TRANS_SMS&apikey=fc9e5177-b3e7-11e8-a895-0200cd936042&to={phone}&from=wisfgs&templatename=Wisfrags&var1={name}&var2={otp_key}'

        # result = requests.get(link, verify=False)
        # print(result)

        return otp_key
    else:
        return False
