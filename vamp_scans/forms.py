
import django.forms.fields
from django import forms
from django.forms import ModelForm

from vamp_scans.models import Tag
from vamp_api.models import TenableAPI

class ConfigureTenableAPIForm(ModelForm):
    class Meta:
        model = TenableAPI
        fields = ['server', 'access_key', 'secret_key', 'severities']

    def __init__(self, *args, **kwargs):
        super(ConfigureTenableAPIForm, self).__init__(*args, **kwargs)
        self.fields['server'].widget.attrs.update({'class': 'form-control'})
        self.fields['access_key'].widget.attrs.update({'class': 'form-control'})
        self.fields['secret_key'].widget.attrs.update({'class': 'form-control'})
        self.fields['severities'].widget.attrs.update({'class': 'form-control'})
        self.fields['severities'].widget.attrs.update({'placeholder': '<critical,high,medium,low> empty for all'})

    def validate_unique(self):
        pass


class UploadNessusFileForm(forms.Form):
    file = forms.FileField()


class AddTagForm(ModelForm):
    class Meta:
        model = Tag
        fields = ['tag', 'link', 'description']

    def __init__(self, *args, **kwargs):
        super(AddTagForm, self).__init__(*args, **kwargs)
        self.fields['tag'].widget.attrs.update({'class': 'form-control'})
        self.fields['link'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})

    def validate_unique(self):
        pass
