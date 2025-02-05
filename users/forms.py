from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from .models import CustomUser
import re

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['email', 'name', 'surname', 'control_number', 'age', 'tel', 'password1', 'password2']
        widgets = {
            'email': forms.EmailInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Correo electrónico',
                    'required': True,
                    'pattern': '^[a-zA-Z0-9]+@utez\.edu\.mx$',
                    'title': 'Por favor, introduce un correo electrónico válido de la utez.',
                }
            ),
            'name': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Nombre',
                    'required': True,
                    'minlength': '2',
                    'maxlength': '50',
                    'title': 'El nombre debe tener entre 2 y 50 caracteres.',
                }
            ),
            'surname': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Apellido',
                    'required': True,
                    'minlength': '2',
                    'maxlength': '50',
                    'title': 'El apellido debe tener entre 2 y 50 caracteres.',
                }
            ),
            'control_number': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Número de Control',
                    'required': True,
                    'pattern': '^\d{5}TN\d{3}$',
                    'title': 'El número de control debe ser una matrícula de la utez.',
                }
            ),
            'age': forms.NumberInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Edad',
                    'required': True,
                    'min': '18',
                    'max': '100',
                    'title': 'La edad debe estar entre 18 y 100 años.',
                }
            ),
            'tel': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Teléfono',
                    'required': True,
                    'pattern': '[0-9]{10}',
                    'title': 'El teléfono debe tener 10 dígitos.',
                }
            ),
            'password1': forms.PasswordInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Contraseña',
                    'required': True,
                    'pattern': '(?=.*\d)(?=.*[A-Z])(?=.*[!#$%&?]).{8,}',
                    'title': 'La contraseña debe tener al menos 8 caracteres, un número, una mayúscula y un símbolo.',
                }
            ),
            'password2': forms.PasswordInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Confirmar contraseña',
                    'required': True,
                    'pattern': '(?=.*\d)(?=.*[A-Z])(?=.*[!#$%&?]).{8,}',
                    'title': 'La contraseña debe tener al menos 8 caracteres, un número, una mayúscula y un símbolo.',
                }
            ),
        }

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError("Las contraseñas no coinciden.")

            # Validación de la contraseña: al menos 8 caracteres, un número, una mayúscula y un símbolo
            if len(password1) < 8:
                raise forms.ValidationError("La contraseña debe tener al menos 8 caracteres.")
            if not re.search(r'[0-9]', password1):
                raise forms.ValidationError("La contraseña debe contener al menos un número.")
            if not re.search(r'[A-Z]', password1):
                raise forms.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
            if not re.search(r'[!#$%&?]', password1):
                raise forms.ValidationError("La contraseña debe contener al menos un símbolo: !, #, $, %, & o ?")

        return cleaned_data

    def clean_email(self):
        email = self.cleaned_data.get('email')
        # Validación para asegurar que el correo sea de la UTEZ
        if not re.match(r'^[a-zA-Z0-9]+@utez\.edu\.mx$', email):
            raise forms.ValidationError("El correo electrónico debe ser del dominio @utez.edu.mx")
        return email

    def clean_control_number(self):
        control_number = self.cleaned_data.get('control_number')
        # Validar que la matrícula tenga exactamente 10 caracteres y siga el formato adecuado
        if len(control_number) != 10:
            raise forms.ValidationError("La matrícula debe tener exactamente 10 caracteres.")
        if not re.match(r'^\d{5}TN\d{3}$', control_number):
            raise forms.ValidationError("La matrícula debe tener el formato adecuado, por ejemplo: 12345TN123.")
        return control_number

    def clean_tel(self):
        tel = self.cleaned_data.get('tel')
        # Validar que el teléfono tenga exactamente 10 dígitos
        if len(tel) != 10 or not tel.isdigit():
            raise forms.ValidationError("El teléfono debe tener exactamente 10 dígitos.")
        return tel

class CustomUserLoginForm(AuthenticationForm):
    username = forms.CharField(label="Correo electrónico", max_length=150)
    password = forms.CharField(label="Contraseña", widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("username")
        password = cleaned_data.get("password")
        if email and password:
            user = authenticate(username=email, password=password)
            if not user:
                raise forms.ValidationError("Usuario o contraseña incorrectos.")
        return cleaned_data