# Generated by Django 3.2.6 on 2021-08-17 20:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mainApp', '0002_phoneotp_profile_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='m_services',
            name='banner',
            field=models.ImageField(default=1, upload_to='images/'),
            preserve_default=False,
        ),
    ]
