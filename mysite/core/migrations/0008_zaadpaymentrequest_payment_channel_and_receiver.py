from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0007_zaadpaymentrequest"),
    ]

    operations = [
        migrations.AddField(
            model_name="zaadpaymentrequest",
            name="payment_channel",
            field=models.CharField(
                choices=[("zaad", "Zaad"), ("evc", "EVC Plus"), ("sahal", "Sahal"), ("bank", "Bank Transfer")],
                default="zaad",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="zaadpaymentrequest",
            name="recipient_account",
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name="zaadpaymentrequest",
            name="recipient_label",
            field=models.CharField(blank=True, max_length=80),
        ),
    ]
