import uuid
from datetime import timedelta

from django.db import models
from django.utils import timezone

from applications.globals.models import ExtraInfo


class Visitor(models.Model):
    ID_PASSPORT = "passport"
    ID_NATIONAL = "national_id"
    ID_DL = "driver_license"
    ID_AADHAAR = "aadhaar"

    ID_TYPES = (
        (ID_PASSPORT, "Passport"),
        (ID_NATIONAL, "National ID"),
        (ID_DL, "Driver License"),
        (ID_AADHAAR, "Aadhaar Card"),
    )

    full_name = models.CharField(max_length=120)
    id_number = models.CharField(max_length=64, unique=True)
    id_type = models.CharField(max_length=20, choices=ID_TYPES)
    contact_phone = models.CharField(max_length=20)
    contact_email = models.EmailField(blank=True)
    photo_reference = models.CharField(max_length=256, blank=True)

    def __str__(self):
        return f"{self.full_name} ({self.id_number})"


class BlacklistEntry(models.Model):
    id_number = models.CharField(max_length=64, db_index=True)
    reason = models.CharField(max_length=200)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Blacklist Entry"
        verbose_name_plural = "Blacklist Entries"

    def __str__(self):
        state = "active" if self.active else "inactive"
        return f"{self.id_number} - {state}"


class Visit(models.Model):
    STATUS_REGISTERED = "registered"
    STATUS_VERIFIED = "id_verified"
    STATUS_PASS_ISSUED = "pass_issued"
    STATUS_INSIDE = "inside"
    STATUS_EXITED = "exited"
    STATUS_DENIED = "denied"

    STATUS_CHOICES = (
        (STATUS_REGISTERED, "Registered"),
        (STATUS_VERIFIED, "ID Verified"),
        (STATUS_PASS_ISSUED, "Pass Issued"),
        (STATUS_INSIDE, "Inside"),
        (STATUS_EXITED, "Exited"),
        (STATUS_DENIED, "Denied"),
    )

    visitor = models.ForeignKey(Visitor, on_delete=models.CASCADE, related_name="visits")
    purpose = models.CharField(max_length=200)
    host_name = models.CharField(max_length=120)
    host_department = models.CharField(max_length=120)
    host_contact = models.CharField(max_length=50, blank=True)
    expected_duration_minutes = models.PositiveIntegerField(default=60)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_REGISTERED)
    registered_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    pass_issued_at = models.DateTimeField(null=True, blank=True)
    entry_at = models.DateTimeField(null=True, blank=True)
    exit_at = models.DateTimeField(null=True, blank=True)
    denial_reason = models.CharField(max_length=200, blank=True)
    denial_remarks = models.TextField(blank=True)
    is_vip = models.BooleanField(default=False)

    def __str__(self):
        return f"Visit {self.id} for {self.visitor.full_name}"


def _generate_pass_number() -> str:
    return f"VMS-{uuid.uuid4().hex[:10].upper()}"


def _generate_incident_tracking_number() -> str:
    return f"INC-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


class VisitorPass(models.Model):
    PASS_PENDING = "pending"
    PASS_ISSUED = "issued"
    PASS_RETURNED = "returned"
    PASS_LOST = "lost"

    PASS_STATUS = (
        (PASS_PENDING, "Pending"),
        (PASS_ISSUED, "Issued"),
        (PASS_RETURNED, "Returned"),
        (PASS_LOST, "Lost"),
    )

    visit = models.OneToOneField(Visit, on_delete=models.CASCADE, related_name="visitor_pass")
    pass_number = models.CharField(max_length=32, unique=True, default=_generate_pass_number)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField()
    authorized_zones = models.CharField(max_length=200, default="public")
    status = models.CharField(max_length=20, choices=PASS_STATUS, default=PASS_PENDING)
    barcode_data = models.TextField(blank=True)
    is_vip_pass = models.BooleanField(default=False)

    def __str__(self):
        return f"Pass {self.pass_number}"


class VerificationLog(models.Model):
    METHOD_MANUAL = "manual"
    METHOD_BIOMETRIC = "biometric"

    METHODS = (
        (METHOD_MANUAL, "Manual"),
        (METHOD_BIOMETRIC, "Biometric"),
    )

    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="verification_logs")
    verifier = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_verifications")
    method = models.CharField(max_length=20, choices=METHODS, default=METHOD_MANUAL)
    result = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        status = "passed" if self.result else "failed"
        return f"Verification {self.id} ({status})"


class DenialLog(models.Model):
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="denials")
    reason = models.CharField(max_length=120)
    remarks = models.TextField(blank=True)
    escalated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Denial {self.id} - {self.reason}"


class EntryExitLog(models.Model):
    ACTION_ENTRY = "entry"
    ACTION_EXIT = "exit"

    ACTIONS = (
        (ACTION_ENTRY, "Entry"),
        (ACTION_EXIT, "Exit"),
    )

    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name="movement_logs")
    action = models.CharField(max_length=10, choices=ACTIONS)
    gate_name = models.CharField(max_length=120)
    recorded_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_movements")
    items_declared = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action.title()} log for visit {self.visit_id}"


class SecurityIncident(models.Model):
    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_LOW = "low"

    SEVERITIES = (
        (SEVERITY_CRITICAL, "Critical"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_LOW, "Low"),
    )

    ISSUE_TYPES = (
        ("unauthorized_access", "Unauthorized Access"),
        ("policy_violation", "Policy Violation"),
        ("equipment_failure", "Equipment Failure"),
        ("suspicious_behavior", "Suspicious Behavior"),
        ("other", "Other"),
    )

    RESPONSE_STANDARD = "standard_response"
    RESPONSE_HIGH = "high_severity_response"
    RESPONSE_LOW = "low_severity_response"

    RESPONSE_PROTOCOLS = (
        (RESPONSE_STANDARD, "Standard Response"),
        (RESPONSE_HIGH, "High Severity Response"),
        (RESPONSE_LOW, "Low Severity Response"),
    )

    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents")
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents")
    recorded_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_incidents")
    severity = models.CharField(max_length=10, choices=SEVERITIES)
    issue_type = models.CharField(max_length=40, choices=ISSUE_TYPES, default="other")
    description = models.TextField()
    status = models.CharField(max_length=20, default="open")
    escalation_level = models.PositiveSmallIntegerField(default=1)
    notified_authorities = models.JSONField(default=list, blank=True)
    containment_actions = models.JSONField(default=list, blank=True)
    response_protocol = models.CharField(max_length=30, choices=RESPONSE_PROTOCOLS, default=RESPONSE_STANDARD)
    tracking_number = models.CharField(max_length=32, unique=True, null=True, blank=True)
    notified_at = models.DateTimeField(null=True, blank=True)
    audit_log = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Incident {self.id} ({self.severity})"

    def save(self, *args, **kwargs):
        if not self.tracking_number:
            self.tracking_number = _generate_incident_tracking_number()
        super().save(*args, **kwargs)

    @property
    def requires_escalation(self) -> bool:
        return self.severity in {self.SEVERITY_CRITICAL, self.SEVERITY_HIGH}


class SystemConfig(models.Model):
    CATEGORY_GENERAL = "general"
    CATEGORY_INTEGRATION = "integration"

    CATEGORIES = (
        (CATEGORY_GENERAL, "General"),
        (CATEGORY_INTEGRATION, "Integration"),
    )

    key = models.CharField(max_length=80, unique=True)
    value = models.TextField()
    description = models.CharField(max_length=255, blank=True)
    category = models.CharField(max_length=20, choices=CATEGORIES, default=CATEGORY_GENERAL)
    updated_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_configs")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key}={self.value}"


class ConfigChangeLog(models.Model):
    ACTION_CREATED = "created"
    ACTION_UPDATED = "updated"

    ACTIONS = (
        (ACTION_CREATED, "Created"),
        (ACTION_UPDATED, "Updated"),
    )

    config = models.ForeignKey(SystemConfig, on_delete=models.CASCADE, related_name="change_logs")
    old_value = models.TextField(blank=True)
    new_value = models.TextField()
    description = models.CharField(max_length=255, blank=True)
    action = models.CharField(max_length=20, choices=ACTIONS)
    changed_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_config_changes")
    changed_at = models.DateTimeField(auto_now_add=True)


class ConfigNotificationLog(models.Model):
    config = models.ForeignKey(SystemConfig, on_delete=models.CASCADE, related_name="notifications")
    recipients = models.JSONField(default=list, blank=True)
    sent_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_config_notifications")
    sent_at = models.DateTimeField(auto_now_add=True)
    payload = models.JSONField(default=dict, blank=True)


class VisitingHoursConfig(models.Model):
    DAY_CHOICES = (
        ("monday", "Monday"),
        ("tuesday", "Tuesday"),
        ("wednesday", "Wednesday"),
        ("thursday", "Thursday"),
        ("friday", "Friday"),
        ("saturday", "Saturday"),
        ("sunday", "Sunday"),
    )

    day = models.CharField(max_length=12, choices=DAY_CHOICES, unique=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    is_holiday = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    updated_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_visiting_hours")
    updated_at = models.DateTimeField(auto_now=True)


class AccessZoneConfig(models.Model):
    name = models.CharField(max_length=80, unique=True)
    description = models.CharField(max_length=255, blank=True)
    requires_vip = models.BooleanField(default=False)
    requires_escort = models.BooleanField(default=False)
    is_restricted = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    updated_by = models.ForeignKey(ExtraInfo, on_delete=models.SET_NULL, null=True, related_name="vms_access_zones")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class VmsEventLog(models.Model):
    event_type = models.CharField(max_length=64, db_index=True)
    reference = models.CharField(max_length=80, blank=True, db_index=True)
    actor_username = models.CharField(max_length=150, blank=True)
    visit = models.ForeignKey(Visit, on_delete=models.SET_NULL, null=True, blank=True, related_name="vms_events")
    visitor = models.ForeignKey(Visitor, on_delete=models.SET_NULL, null=True, blank=True, related_name="vms_events")
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        suffix = f" ({self.reference})" if self.reference else ""
        return f"{self.event_type}{suffix}"


def calculate_valid_until(start_time: timezone.datetime, duration_minutes: int, is_vip: bool = False) -> timezone.datetime:
    base_duration = duration_minutes
    extra = 60 if is_vip else 0
    return start_time + timedelta(minutes=base_duration + extra)
