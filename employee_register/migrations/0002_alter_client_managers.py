# Generated by Django 5.0.3 on 2024-03-13 16:14

import django.contrib.auth.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('employee_register', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='client',
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
    ]
