import base64
import io
import json

import pyqrcode
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .models import (
    BlacklistEntry,
    AccessZoneConfig,
    ConfigChangeLog,
    ConfigNotificationLog,
    DenialLog,
    EntryExitLog,
    SecurityIncident,
    SystemConfig,
    VerificationLog,
    Visit,
    Visitor,
    VisitorPass,
    VisitingHoursConfig,
    calculate_valid_until,
)
from .selectors import get_current_staff


class RegistrationError(Exception):
    pass


class WorkflowError(Exception):
    pass


class DataOperationError(Exception):
    pass


_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    if value is None:
        safe_value = ""
    else:
        safe_value = str(value)

    if safe_value.startswith(_CSV_INJECTION_PREFIXES):
        return f"'{safe_value}"

    return safe_value


ESCALATION_LEVELS = {
    SecurityIncident.SEVERITY_LOW: 1,
    SecurityIncident.SEVERITY_MEDIUM: 2,
    SecurityIncident.SEVERITY_HIGH: 3,
    SecurityIncident.SEVERITY_CRITICAL: 4,
}

ESCALATION_RECIPIENTS = {
    1: ["shift_supervisor"],
    2: ["security_supervisor", "operations_manager"],
    3: ["security_supervisor", "operations_manager", "campus_security_all", "police_liaison"],
    4: [
        "security_supervisor",
        "operations_manager",
        "campus_security_all",
        "police_liaison",
        "emergency_response_team",
    ],
}

CONTAINMENT_ACTIONS = {
    SecurityIncident.SEVERITY_LOW: ["monitor_and_document", "supervisor_review"],
    SecurityIncident.SEVERITY_MEDIUM: ["increase_zone_monitoring", "assign_security_followup"],
    SecurityIncident.SEVERITY_HIGH: ["restrict_visitor_movement", "dispatch_security_team", "prepare_eviction"],
    SecurityIncident.SEVERITY_CRITICAL: [
        "initiate_lockdown",
        "dispatch_security_team",
        "contact_emergency_services",
        "secure_incident_zone",
    ],
}

INTEGRATION_CONFIG_KEYS = {
    "integration_cctv_enabled",
    "integration_hr_sync_enabled",
    "integration_notifications_webhook",
    "integration_auto_approve_host",
}

CONFLICTING_KEY_GROUPS = [
    (
        "strict_security_mode",
        "enable_vip_bypass",
        "strict_security_mode cannot be enabled when enable_vip_bypass is true.",
    ),
    (
        "enforce_host_approval",
        "integration_auto_approve_host",
        "enforce_host_approval conflicts with integration_auto_approve_host.",
    ),
]

_config_cache = {}


def _normalize_bool(value, key):
    if isinstance(value, bool):
        return "true" if value else "false"
    normalized = str(value).strip().lower()
    if normalized not in {"true", "false"}:
        raise WorkflowError(f"{key} must be a boolean value: true/false")
    return normalized


def _normalize_int(value, key, minimum, maximum):
    try:
        parsed = int(str(value).strip())
    except ValueError as exc:
        raise WorkflowError(f"{key} must be an integer.") from exc
    if parsed < minimum or parsed > maximum:
        raise WorkflowError(f"{key} must be between {minimum} and {maximum}.")
    return str(parsed)


CONFIG_VALIDATORS = {
    "max_daily_visitors": lambda value: _normalize_int(value, "max_daily_visitors", 1, 10000),
    "strict_security_mode": lambda value: _normalize_bool(value, "strict_security_mode"),
    "enable_vip_bypass": lambda value: _normalize_bool(value, "enable_vip_bypass"),
    "enforce_host_approval": lambda value: _normalize_bool(value, "enforce_host_approval"),
    "integration_auto_approve_host": lambda value: _normalize_bool(value, "integration_auto_approve_host"),
    "integration_cctv_enabled": lambda value: _normalize_bool(value, "integration_cctv_enabled"),
    "integration_hr_sync_enabled": lambda value: _normalize_bool(value, "integration_hr_sync_enabled"),
}


def _is_true(config_value):
    return str(config_value).strip().lower() == "true"


def refresh_config_cache():
    global _config_cache
    _config_cache = {row.key: row.value for row in SystemConfig.objects.all()}
    return dict(_config_cache)


def get_config_cache():
    if not _config_cache:
        return refresh_config_cache()
    return dict(_config_cache)


def validate_config_value(key, value):
    if key in CONFIG_VALIDATORS:
        return CONFIG_VALIDATORS[key](value)

    if key.startswith("integration_"):
        normalized = str(value).strip()
        if not normalized:
            raise WorkflowError(f"{key} cannot be empty.")
        return normalized

    normalized = str(value).strip()
    if not normalized:
        raise WorkflowError(f"{key} cannot be empty.")
    return normalized


def detect_config_conflicts(key, value, cache=None):
    working = dict(cache or get_config_cache())
    working[key] = value

    for left_key, right_key, message in CONFLICTING_KEY_GROUPS:
        if _is_true(working.get(left_key, "false")) and _is_true(working.get(right_key, "false")):
            return message

    return None


def notify_config_change(config, actor, old_value, new_value):
    recipients = ["all_vms_users"]
    if config.category == SystemConfig.CATEGORY_INTEGRATION:
        recipients.append("integration_admins")

    return ConfigNotificationLog.objects.create(
        config=config,
        recipients=recipients,
        sent_by=actor,
        payload={
            "key": config.key,
            "old_value": old_value,
            "new_value": new_value,
        },
    )


def upsert_system_config(data, user):
    key = data["key"].strip()
    normalized_value = validate_config_value(key, data["value"])

    conflict = detect_config_conflicts(key, normalized_value)
    if conflict:
        raise WorkflowError(conflict)

    actor = get_current_staff(user)
    category = (
        SystemConfig.CATEGORY_INTEGRATION
        if key.startswith("integration_") or key in INTEGRATION_CONFIG_KEYS
        else SystemConfig.CATEGORY_GENERAL
    )

    existing = SystemConfig.objects.filter(key=key).first()
    old_value = existing.value if existing else ""

    if existing:
        existing.value = normalized_value
        existing.description = data.get("description", "")
        existing.category = category
        existing.updated_by = actor
        existing.save(update_fields=["value", "description", "category", "updated_by", "updated_at"])
        config = existing
        action = ConfigChangeLog.ACTION_UPDATED
    else:
        config = SystemConfig.objects.create(
            key=key,
            value=normalized_value,
            description=data.get("description", ""),
            category=category,
            updated_by=actor,
        )
        action = ConfigChangeLog.ACTION_CREATED

    change_log = ConfigChangeLog.objects.create(
        config=config,
        old_value=old_value,
        new_value=normalized_value,
        description=data.get("description", ""),
        action=action,
        changed_by=actor,
    )
    notification_log = notify_config_change(config, actor, old_value, normalized_value)
    refresh_config_cache()

    return config, change_log, notification_log


def list_system_configs():
    return SystemConfig.objects.order_by("key")


def list_config_change_logs():
    return ConfigChangeLog.objects.select_related("config", "changed_by").order_by("-changed_at")


def configure_visiting_hours(data, user):
    actor = get_current_staff(user)
    day = str(data["day"]).strip().lower()
    is_holiday = data.get("is_holiday", False)
    start_time = data.get("start_time")
    end_time = data.get("end_time")

    if is_holiday:
        start_time = None
        end_time = None
    else:
        if not start_time or not end_time:
            raise WorkflowError("start_time and end_time are required when day is not a holiday.")
        if start_time >= end_time:
            raise WorkflowError("start_time must be earlier than end_time.")

    entry, _created = VisitingHoursConfig.objects.update_or_create(
        day=day,
        defaults={
            "start_time": start_time,
            "end_time": end_time,
            "is_holiday": is_holiday,
            "active": True,
            "updated_by": actor,
        },
    )
    return entry


def list_visiting_hours_configs():
    return VisitingHoursConfig.objects.order_by("day")


def configure_access_zone(data, user):
    actor = get_current_staff(user)
    name = str(data["name"]).strip().lower()
    if not name:
        raise WorkflowError("Zone name cannot be empty.")

    zone, _created = AccessZoneConfig.objects.update_or_create(
        name=name,
        defaults={
            "description": data.get("description", ""),
            "requires_vip": data.get("requires_vip", False),
            "requires_escort": data.get("requires_escort", False),
            "is_restricted": data.get("is_restricted", False),
            "active": data.get("active", True),
            "updated_by": actor,
        },
    )
    return zone


def list_access_zones():
    return AccessZoneConfig.objects.order_by("name")


def determine_escalation_level(severity):
    level = ESCALATION_LEVELS.get(severity)
    if level is None:
        raise WorkflowError(f"Unsupported incident severity: {severity}")
    return level


def notify_escalation(escalation_level, severity):
    recipients = list(ESCALATION_RECIPIENTS.get(escalation_level, []))
    if severity == SecurityIncident.SEVERITY_LOW:
        recipients = ["shift_supervisor"]
    return list(dict.fromkeys(recipients))


def determine_containment_actions(severity):
    actions = CONTAINMENT_ACTIONS.get(severity)
    if actions is None:
        raise WorkflowError(f"Unsupported incident severity: {severity}")
    return list(actions)


def determine_response_protocol(severity):
    if severity in {SecurityIncident.SEVERITY_HIGH, SecurityIncident.SEVERITY_CRITICAL}:
        return SecurityIncident.RESPONSE_HIGH
    if severity == SecurityIncident.SEVERITY_LOW:
        return SecurityIncident.RESPONSE_LOW
    return SecurityIncident.RESPONSE_STANDARD


def update_visitor_status_on_incident(visit, severity):
    if not visit:
        return None

    if severity in {SecurityIncident.SEVERITY_HIGH, SecurityIncident.SEVERITY_CRITICAL}:
        visit.status = Visit.STATUS_DENIED
        visit.denial_reason = f"security_incident_{severity}"
        visit.denial_remarks = "Visitor status automatically updated due to security incident severity."
        visit.save(update_fields=["status", "denial_reason", "denial_remarks"])

    return visit.status


def _generate_pass_qr(visitor_pass, visit):
    """Generate a QR payload with non-PII pass metadata only.

    Visitor identity is resolved server-side on /vms/scan/, so scanning the
    printed QR code with a personal phone does not reveal visitor details.
    """
    qr_payload = json.dumps({
        "pass_number": visitor_pass.pass_number,
        "visit_id": visit.id,
        "valid_until": visitor_pass.valid_until.isoformat(),
    })
    qr = pyqrcode.create(qr_payload, error="M")
    buffer = io.BytesIO()
    qr.png(buffer, scale=6, quiet_zone=2)
    b64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def register_visitor(data):
    """Register a visitor and create a new visit. Returns (visitor, visit).

    Raises RegistrationError if the visitor is blacklisted.
    """
    blacklist_hit = BlacklistEntry.objects.filter(
        id_number=data["id_number"], active=True,
    ).exists()
    if blacklist_hit:
        raise RegistrationError("Visitor is blacklisted; registration blocked.")

    visitor, _ = Visitor.objects.update_or_create(
        id_number=data["id_number"],
        defaults={
            "full_name": data["full_name"],
            "id_type": data["id_type"],
            "contact_phone": data["contact_phone"],
            "contact_email": data.get("contact_email", ""),
            "photo_reference": data.get("photo_reference", ""),
        },
    )

    visit = Visit.objects.create(
        visitor=visitor,
        purpose=data["purpose"],
        host_name=data["host_name"],
        host_department=data["host_department"],
        host_contact=data.get("host_contact", ""),
        expected_duration_minutes=data.get("expected_duration_minutes", 60),
        is_vip=data.get("is_vip", False),
    )
    return visitor, visit


def verify_visitor(data, user):
    """Verify a visitor's identity. Returns (visit, passed).

    Raises WorkflowError on verification failure.
    """
    visit = get_object_or_404(Visit, id=data["visit_id"])
    verifier = get_current_staff(user)

    VerificationLog.objects.create(
        visit=visit,
        verifier=verifier,
        method=data["method"],
        result=data["result"],
        notes=data.get("notes", ""),
    )

    if not data["result"]:
        visit.status = Visit.STATUS_DENIED
        visit.denial_reason = "verification_failed"
        visit.denial_remarks = data.get("notes", "")
        visit.save(update_fields=["status", "denial_reason", "denial_remarks"])
        DenialLog.objects.create(
            visit=visit,
            reason="verification_failed",
            remarks=data.get("notes", ""),
            escalated=True,
        )
        raise WorkflowError("Verification failed; entry denied.")

    visit.status = Visit.STATUS_VERIFIED
    visit.verified_at = timezone.now()
    visit.save(update_fields=["status", "verified_at"])
    return visit


def issue_pass(data):
    """Issue a visitor pass with QR code. Returns (visit, visitor_pass, qr_data_uri).

    Raises WorkflowError if the visit is in an invalid state.
    """
    visit = get_object_or_404(Visit, id=data["visit_id"])

    if visit.status in {Visit.STATUS_DENIED, Visit.STATUS_EXITED}:
        raise WorkflowError("Cannot issue pass for denied or closed visit.")
    if visit.status not in {Visit.STATUS_VERIFIED, Visit.STATUS_PASS_ISSUED}:
        raise WorkflowError("Visit must be verified before issuing a pass.")

    now = timezone.now()
    valid_until = calculate_valid_until(now, visit.expected_duration_minutes, visit.is_vip)
    visitor_pass, _ = VisitorPass.objects.update_or_create(
        visit=visit,
        defaults={
            "valid_from": now,
            "valid_until": valid_until,
            "authorized_zones": data.get("authorized_zones", "public"),
            "status": VisitorPass.PASS_ISSUED,
            "is_vip_pass": visit.is_vip,
        },
    )

    qr_data_uri = _generate_pass_qr(visitor_pass, visit)
    visitor_pass.barcode_data = qr_data_uri
    visitor_pass.save(update_fields=["barcode_data"])

    visit.status = Visit.STATUS_PASS_ISSUED
    visit.pass_issued_at = now
    visit.save(update_fields=["status", "pass_issued_at"])

    return visit, visitor_pass, qr_data_uri


def record_entry(data, user):
    """Record a visitor entry. Returns the visit.

    Raises WorkflowError if the visit is in an invalid state.
    """
    visit = get_object_or_404(Visit, id=data["visit_id"])
    if visit.status not in {Visit.STATUS_PASS_ISSUED, Visit.STATUS_INSIDE}:
        raise WorkflowError("Pass must be issued before entry.")

    EntryExitLog.objects.create(
        visit=visit,
        action=EntryExitLog.ACTION_ENTRY,
        gate_name=data["gate_name"],
        recorded_by=get_current_staff(user),
        items_declared=data.get("items_declared", ""),
    )

    visit.status = Visit.STATUS_INSIDE
    visit.entry_at = visit.entry_at or timezone.now()
    visit.save(update_fields=["status", "entry_at"])
    return visit


def record_exit(data, user):
    """Record a visitor exit. Returns the visit.

    Raises WorkflowError if the visitor is not inside.
    """
    visit = get_object_or_404(Visit, id=data["visit_id"])
    if visit.status != Visit.STATUS_INSIDE:
        raise WorkflowError("Visitor is not inside.")

    EntryExitLog.objects.create(
        visit=visit,
        action=EntryExitLog.ACTION_EXIT,
        gate_name=data["gate_name"],
        recorded_by=get_current_staff(user),
        items_declared=data.get("items_declared", ""),
    )

    visit.status = Visit.STATUS_EXITED
    visit.exit_at = timezone.now()
    visit.save(update_fields=["status", "exit_at"])

    visitor_pass = getattr(visit, "visitor_pass", None)
    if visitor_pass:
        visitor_pass.status = VisitorPass.PASS_RETURNED
        visitor_pass.save(update_fields=["status"])

    return visit


def deny_entry(data):
    """Deny entry for a visit. Returns (visit, denial_log)."""
    visit = get_object_or_404(Visit, id=data["visit_id"])
    visit.status = Visit.STATUS_DENIED
    visit.denial_reason = data["reason"]
    visit.denial_remarks = data.get("remarks", "")
    visit.save(update_fields=["status", "denial_reason", "denial_remarks"])

    denial = DenialLog.objects.create(
        visit=visit,
        reason=data["reason"],
        remarks=data.get("remarks", ""),
        escalated=data.get("escalated", False),
    )
    return visit, denial


def log_incident(data, user):
    """Log a security incident. Returns the incident."""
    visit = None
    visitor = None
    if data.get("visit_id"):
        visit = get_object_or_404(Visit, id=data["visit_id"])
        visitor = visit.visitor
    elif data.get("visitor_id"):
        visitor = get_object_or_404(Visitor, id=data["visitor_id"])

    severity = data["severity"]
    escalation_level = determine_escalation_level(severity)
    notified_authorities = notify_escalation(escalation_level, severity)
    containment_actions = determine_containment_actions(severity)
    response_protocol = determine_response_protocol(severity)
    visit_status_after = update_visitor_status_on_incident(visit, severity)
    notified_at = timezone.now() if notified_authorities else None

    audit_log = [
        {
            "event": "incident_logged",
            "severity": severity,
            "timestamp": timezone.now().isoformat(),
        },
        {
            "event": "escalation_routed",
            "level": escalation_level,
            "authorities": notified_authorities,
            "timestamp": timezone.now().isoformat(),
        },
        {
            "event": "containment_actions_assigned",
            "actions": containment_actions,
            "timestamp": timezone.now().isoformat(),
        },
    ]

    if visit_status_after is not None:
        audit_log.append(
            {
                "event": "visitor_status_updated",
                "visit_id": visit.id,
                "status": visit_status_after,
                "timestamp": timezone.now().isoformat(),
            }
        )

    return SecurityIncident.objects.create(
        visit=visit,
        visitor=visitor,
        recorded_by=get_current_staff(user),
        severity=severity,
        issue_type=data["issue_type"],
        description=data["description"],
        escalation_level=escalation_level,
        notified_authorities=notified_authorities,
        containment_actions=containment_actions,
        response_protocol=response_protocol,
        notified_at=notified_at,
        audit_log=audit_log,
    )


def export_visitor_data(start_date, end_date, op_log=None):
    try:
        visits = Visit.objects.filter(
            registered_at__date__gte=start_date,
            registered_at__date__lte=end_date,
        ).select_related("visitor")

        rows = []
        for visit in visits:
            rows.append(
                {
                    "visit_id": visit.id,
                    "visitor_name": _csv_safe(visit.visitor.full_name),
                    "id_number": _csv_safe(visit.visitor.id_number),
                    "id_type": _csv_safe(visit.visitor.id_type),
                    "purpose": _csv_safe(visit.purpose),
                    "host_name": _csv_safe(visit.host_name),
                    "host_department": _csv_safe(visit.host_department),
                    "status": _csv_safe(visit.status),
                    "is_vip": visit.is_vip,
                    "registered_at": visit.registered_at.isoformat() if visit.registered_at else "",
                }
            )

        return rows
    except Exception as exc:
        if op_log is not None:
            if isinstance(op_log, dict):
                op_log["error_details"] = str(exc)
            else:
                setattr(op_log, "error_details", str(exc))
                save = getattr(op_log, "save", None)
                if callable(save):
                    save()
        raise DataOperationError("Export failed; see operation log for details.") from exc


def import_visitor_data(rows, field_mapping=None, op_log=None):
    failed_rows = []
    try:
        if not isinstance(rows, list):
            raise ValueError("rows must be a list")

        mapping = field_mapping or {}
        normalized_rows = []
        for index, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                raise ValueError("each row must be an object")

            if mapping:
                normalized = {target: row.get(source) for source, target in mapping.items()}
            else:
                normalized = dict(row)
            normalized_rows.append({"row_number": index, "data": normalized})

        imported_rows = []
        valid_statuses = {choice for choice, _label in Visit.STATUS_CHOICES}

        with transaction.atomic():
            for item in normalized_rows:
                row_number = item["row_number"]
                normalized = item["data"]

                try:
                    id_number = str(normalized.get("id_number") or "").strip()
                    if not id_number:
                        raise ValueError("id_number is required")

                    full_name = str(
                        normalized.get("full_name")
                        or normalized.get("visitor_name")
                        or "Unknown Visitor"
                    ).strip()

                    id_type = str(normalized.get("id_type") or Visitor.ID_NATIONAL).strip()
                    allowed_id_types = {choice for choice, _label in Visitor.ID_TYPES}
                    if id_type not in allowed_id_types:
                        id_type = Visitor.ID_NATIONAL

                    contact_phone = str(normalized.get("contact_phone") or "0000000000").strip()
                    contact_email = str(normalized.get("contact_email") or "").strip()
                    photo_reference = str(normalized.get("photo_reference") or "").strip()

                    visitor, _visitor_created = Visitor.objects.update_or_create(
                        id_number=id_number,
                        defaults={
                            "full_name": full_name,
                            "id_type": id_type,
                            "contact_phone": contact_phone,
                            "contact_email": contact_email,
                            "photo_reference": photo_reference,
                        },
                    )

                    host_name = str(normalized.get("host_name") or "Unknown Host").strip()
                    host_department = str(normalized.get("host_department") or "General").strip()
                    purpose = str(normalized.get("purpose") or "Imported visitor record").strip()
                    host_contact = str(normalized.get("host_contact") or "").strip()

                    try:
                        expected_duration = int(normalized.get("expected_duration_minutes") or 60)
                    except (TypeError, ValueError):
                        expected_duration = 60
                    expected_duration = max(5, expected_duration)

                    raw_status = str(normalized.get("status") or Visit.STATUS_REGISTERED).strip().lower()
                    status_value = raw_status if raw_status in valid_statuses else Visit.STATUS_REGISTERED

                    raw_is_vip = normalized.get("is_vip", False)
                    is_vip = raw_is_vip if isinstance(raw_is_vip, bool) else str(raw_is_vip).strip().lower() in {"true", "1", "yes", "y"}

                    visit = Visit.objects.create(
                        visitor=visitor,
                        purpose=purpose,
                        host_name=host_name,
                        host_department=host_department,
                        host_contact=host_contact,
                        expected_duration_minutes=expected_duration,
                        status=status_value,
                        is_vip=is_vip,
                    )

                    imported_rows.append(
                        {
                            "row_number": row_number,
                            "visit_id": visit.id,
                            "id_number": visitor.id_number,
                            "status": visit.status,
                        }
                    )
                except Exception as row_exc:
                    failed_rows.append(
                        {
                            "row_number": row_number,
                            "detail": str(row_exc),
                        }
                    )

            if failed_rows:
                raise ValueError(f"Import validation failed for {len(failed_rows)} row(s).")

        return {
            "imported_count": len(imported_rows),
            "failed_count": 0,
            "rows": imported_rows,
        }
    except Exception as exc:
        if op_log is not None:
            if isinstance(op_log, dict):
                op_log["error_details"] = str(exc)
                if failed_rows:
                    op_log["row_errors"] = failed_rows
            else:
                setattr(op_log, "error_details", str(exc))
                save = getattr(op_log, "save", None)
                if callable(save):
                    save()
        raise DataOperationError("Import failed and rolled back; see operation log for details.") from exc
