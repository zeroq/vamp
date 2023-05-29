
from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib import messages

# Create your views here.

def accounts_login(request):
    context = {}
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse("home"))
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                #  add CDC as organization in case nothing is set
                #if not user.userextension.organization:
                #    org_obj = Organization.objects.get(name='CDC')
                #    user.userextension.organization = org_obj
                #    user.save()
                login(request, user)
                return HttpResponseRedirect(reverse('home'))
            else:
                messages.error(request, '%s: is not activated!' % (username))
        else:
            messages.error(request, 'Logon failed!')
        return HttpResponseRedirect(reverse("accounts:login"))
    return render(request, 'vamp_accounts/login.html', context)

@login_required
def accounts_logout(request):
    logout(request)
    messages.info(request, 'Successfully logged out.')
    return HttpResponseRedirect(reverse("accounts:login"))
