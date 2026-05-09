from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vms", "0002_visitorpass_barcode_data_to_text"),
    ]

    operations = [
        migrations.AddField(
            model_name="securityincident",
            name="audit_log",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="securityincident",
            name="containment_actions",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="securityincident",
            name="escalation_level",
            field=models.PositiveSmallIntegerField(default=1),
        ),
        migrations.AddField(
            model_name="securityincident",
            name="notified_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="securityincident",
            name="notified_authorities",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="securityincident",
            name="response_protocol",
            field=models.CharField(
                choices=[
                    ("standard_response", "Standard Response"),
                    ("high_severity_response", "High Severity Response"),
                    ("low_severity_response", "Low Severity Response"),
                ],
                default="standard_response",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="securityincident",
            name="tracking_number",
            field=models.CharField(blank=True, max_length=32, null=True, unique=True),
        ),
    ]
