from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("globals", "0005_moduleaccess_patent_management"),
        ("vms", "0003_securityincident_flow_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="AccessZoneConfig",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=80, unique=True)),
                ("description", models.CharField(blank=True, max_length=255)),
                ("requires_vip", models.BooleanField(default=False)),
                ("requires_escort", models.BooleanField(default=False)),
                ("is_restricted", models.BooleanField(default=False)),
                ("active", models.BooleanField(default=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_access_zones",
                        to="globals.extrainfo",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="SystemConfig",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.CharField(max_length=80, unique=True)),
                ("value", models.TextField()),
                ("description", models.CharField(blank=True, max_length=255)),
                ("category", models.CharField(choices=[("general", "General"), ("integration", "Integration")], default="general", max_length=20)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_configs",
                        to="globals.extrainfo",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="VisitingHoursConfig",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "day",
                    models.CharField(
                        choices=[
                            ("monday", "Monday"),
                            ("tuesday", "Tuesday"),
                            ("wednesday", "Wednesday"),
                            ("thursday", "Thursday"),
                            ("friday", "Friday"),
                            ("saturday", "Saturday"),
                            ("sunday", "Sunday"),
                        ],
                        max_length=12,
                        unique=True,
                    ),
                ),
                ("start_time", models.TimeField(blank=True, null=True)),
                ("end_time", models.TimeField(blank=True, null=True)),
                ("is_holiday", models.BooleanField(default=False)),
                ("active", models.BooleanField(default=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_visiting_hours",
                        to="globals.extrainfo",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="ConfigChangeLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("old_value", models.TextField(blank=True)),
                ("new_value", models.TextField()),
                ("description", models.CharField(blank=True, max_length=255)),
                ("action", models.CharField(choices=[("created", "Created"), ("updated", "Updated")], max_length=20)),
                ("changed_at", models.DateTimeField(auto_now_add=True)),
                (
                    "changed_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_config_changes",
                        to="globals.extrainfo",
                    ),
                ),
                (
                    "config",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="change_logs",
                        to="vms.systemconfig",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="ConfigNotificationLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("recipients", models.JSONField(blank=True, default=list)),
                ("sent_at", models.DateTimeField(auto_now_add=True)),
                ("payload", models.JSONField(blank=True, default=dict)),
                (
                    "config",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notifications",
                        to="vms.systemconfig",
                    ),
                ),
                (
                    "sent_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="vms_config_notifications",
                        to="globals.extrainfo",
                    ),
                ),
            ],
        ),
    ]
