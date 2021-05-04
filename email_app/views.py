from django.views.generic import ListView, DetailView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.shortcuts import render, redirect, reverse
from .models import Mail
from Crypto.Cipher import AES
from django.contrib import messages

# Create your views here.
class ReceivedMailListView(LoginRequiredMixin, ListView):
    model = Mail
    template_name = 'email_app/home.html'
    context_object_name = 'mails'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(mails=Mail.objects.filter(send_to=self.request.user.email).filter(passcode='').order_by('-date'))
        return context


class SentMailListView(LoginRequiredMixin, ListView):
    model = Mail
    template_name = 'email_app/sent.html'
    context_object_name = 'mails'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(mails=Mail.objects.filter(send_from=self.request.user.email).filter(passcode='').order_by('-date'))
        return context


class SecretMailListView(LoginRequiredMixin, ListView):
    model = Mail
    template_name = 'email_app/secret.html'
    context_object_name = 'mails'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        mails = (
            Mail.objects.filter(send_to=self.request.user.email).exclude(passcode='') |
            Mail.objects.filter(send_from=self.request.user.email).exclude(passcode='')
        )
        mails = Mail.objects.filter(id__in=mails.values('id')).order_by('-date')
        context.update(mails=mails)
        return context

class MailDetailView(LoginRequiredMixin, DetailView):
    model = Mail


class PasscodeDetailView(LoginRequiredMixin, DetailView):
    model = Mail
    template_name = 'email_app/passcode_detail.html'

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()

        if type(eval(self.object.message)) is bytes:
            self.object.message = ''

        if 'message' in request.session:
            self.object.message = request.session['message']
            request.session['message'] = ''

        if 'error' in request.session:
            self.object.error = request.session['error']
            request.session['error'] = ''
            
        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        passcode = request.POST.get('passcode')
        object = self.get_object()

        if len(passcode) != 8:
            request.session['error'] = 'The passcode must contain 8 letters.'
        else:
            cipherpasscode = eval(object.passcode)
            nonce = eval(object.nonce)
            key = str.encode(passcode + passcode)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            newpasscode = cipher.decrypt(cipherpasscode)

            if newpasscode == key:
                ciphermessage = eval(object.message)
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                decryptedmessage = cipher.decrypt(ciphermessage)
                request.session['message'] = decryptedmessage.decode('utf8')
                request.session['error'] = ''
            else:
                request.session['error'] = 'Please, try again.'

        return redirect(reverse('email-secret-passcode', args=[object.id]))


class MailCreateView(LoginRequiredMixin, CreateView):
    model = Mail
    fields = ['send_to', 'subject', 'message', 'passcode']

    def form_valid(self, form):
        form.instance.send_from = self.request.user.email

        if form.instance.passcode != '':
            form.instance.passcode = form.instance.passcode + form.instance.passcode
            key = str.encode(form.instance.passcode)

            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            form.instance.nonce = nonce
            cipherpasscode, tag = cipher.encrypt_and_digest(str.encode(form.instance.passcode))
            form.instance.passcode = cipherpasscode

            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            ciphermessage, tag = cipher.encrypt_and_digest(str.encode(form.instance.message))
            form.instance.message = ciphermessage

        return super().form_valid(form)

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        form = super(MailCreateView, self).get_form(form_class)

        form.fields['passcode'].widget.attrs = {'placeholder': '8-letter Passcode'}

        return form
    