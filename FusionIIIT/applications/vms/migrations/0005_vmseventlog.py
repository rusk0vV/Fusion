from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("vms", "0004_system_configuration_hardening"),
    ]

    operations = [
        migrations.CreateModel(
            name="VmsEventLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_type", models.CharField(db_index=True, max_length=64)),
                ("reference", models.CharField(blank=True, db_index=True, max_length=80)),
                ("actor_username", models.CharField(blank=True, max_length=150)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "visit",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_events",
                        to="vms.visit",
                    ),
                ),
                (
                    "visitor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_events",
                        to="vms.visitor",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
