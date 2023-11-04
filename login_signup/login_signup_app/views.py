from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

# Create your views here.

def checkusername(username): # Special Character not allowed
    if username != '' and all(chr.isalnum() or chr.isspace() for chr in username):
        return True
    else:
        return False

def uniqueemail(email):  # Email Should be unique
    search_email = User.objects.filter(email=email)
    if search_email:
        return False
    else:
        return True

def checkemail(email):
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False

def checkpassword(password):  # Password format
    if password != '' :
        return True
    else:
        return False

def validate_registration(request,username,email,password):
    if checkusername(username)==False:
        messages.warning(request, "Username should contain only alphabets")
    elif checkemail(email)==False:
        messages.warning(request, "Enter a valid email address")
    elif uniqueemail(email)==False:
        messages.warning(request, "This Email is already Registered")
    elif checkpassword(password)==False:
        messages.warning(request, "Password can't be blank")
    else:
        return 1

def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        psw = request.POST.get('password')
        try:
            get_user_by_username =User.objects.get(username=username)
            if get_user_by_username:
                flag= check_password(psw, get_user_by_username.password)
                if flag:
                    request.session["uid"] = request.POST.get('username')
                    messages.success(request, "Login Successfully.")
                    return redirect('/index')
                error = 'Wrong password'
                messages.warning(request, "Wrong password")
                return render(request, "login.html", locals())
        except:
            error = 'User not Exists'
            messages.error(request, "User not Exists")
            return render(request, "login.html", locals())
    return render(request, "login.html", locals())


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        psw = request.POST.get('psw')
        repeat_psw= request.POST.get('psw_repeat')
        if validate_registration(request,username,email,psw) == 1:
            if psw == repeat_psw:
                password = make_password(psw)
                obj_user = User.objects.filter(username=username)
                if obj_user:
                    error = 'Username already exists'
                    messages.warning(request, "Username already exists")
                    return render(request, "register.html", locals())
                else:
                    newuser = User.objects.create(username=username, password = password, email=email)
                    newuser.save()
                    messages.success(request, "User Register Successfully.")
                    return redirect('/login')
            else:
                messages.warning(request, "Password and Confirm Password should be same")
        return render(request, "register.html", locals())
    return render(request, "register.html", locals())


def index(request):
    if request.session.has_key('uid'):
        return render(request, "index.html")
    else:
        return redirect('/login')

def logout(request):
    try:
        del request.session["uid"]
    except KeyError:
        pass
    return redirect("/login")


def forgot_password(request):
    return render(request, 'resetpassword.html')


def password_reset(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        psw = request.POST.get('new_psw')
        repeat_psw = request.POST.get('psw_repeat')
        try:
            get_user = User.objects.get(username=username)
            print("get", get_user)
            if get_user:
                if psw == repeat_psw:
                    password = make_password(psw)
                    User.objects.filter(pk=get_user.id).update(password=password)
                    messages.success(request, "Password reset Successfully.")
                    return render(request, 'password_reset.html')
                else:
                    messages.warning(request, "Password and Confirm Password should be same")
                    return render(request, "password_reset.html", locals())
        except:
            messages.warning(request, "User not exists")
            return render(request, 'password_reset.html')
    return render(request, 'password_reset.html')