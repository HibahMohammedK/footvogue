# Generated by Django 5.1.4 on 2025-02-12 12:10

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('footvogueapp', '0004_alter_customuser_referral_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='referral',
            name='referred_user',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='referral', to=settings.AUTH_USER_MODEL),
        ),
    ]
