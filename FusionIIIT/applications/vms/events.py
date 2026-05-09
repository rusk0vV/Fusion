import json
import logging
from urllib import error as urllib_error
from urllib import request as urllib_request

from django.contrib.auth import get_user_model
from django.dispatch import Signal, receiver

try:
    from notifications.signals import notify
except Exception:  # pragma: no cover - optional runtime integration
    notify = None

from .models import SystemConfig, VmsEventLog

logger = logging.getLogger(__name__)

vms_event_signal = Signal()

_WEBHOOK_CONFIG_KEYS = (
    "integration_notifications_webhook",
    "vms_event_webhooks",
)


def _coerce_urls(raw_value):
    text = str(raw_value or "").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None

    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]

    return [chunk.strip() for chunk in text.split(",") if chunk.strip()]


def _resolve_webhook_urls():
    values = SystemConfig.objects.filter(key__in=_WEBHOOK_CONFIG_KEYS).values_list("value", flat=True)
    urls = []
    for value in values:
        urls.extend(_coerce_urls(value))

    # Preserve insertion order while removing duplicates.
    return list(dict.fromkeys(urls))


def emit_vms_event(
    event_type,
    *,
    reference="",
    actor_user=None,
    actor_username="",
    visit=None,
    visitor=None,
    payload=None,
):
    effective_actor = ""
    if actor_user is not None and getattr(actor_user, "is_authenticated", False):
        effective_actor = actor_user.username
    elif actor_username:
        effective_actor = actor_username

    event = VmsEventLog.objects.create(
        event_type=event_type,
        reference=str(reference or ""),
        actor_username=effective_actor,
        visit=visit,
        visitor=visitor,
        payload=payload or {},
    )

    vms_event_signal.send(
        sender=VmsEventLog,
        event=event,
        actor_user=actor_user,
    )
    return event


@receiver(vms_event_signal)
def _send_notifications(sender, event, actor_user=None, **kwargs):
    if notify is None:
        return

    User = get_user_model()
    recipients = User.objects.filter(
        username__in=["vms_admin", "vms_super_admin", "securityadmin"],
        is_active=True,
    )

    if actor_user is not None and getattr(actor_user, "is_authenticated", False):
        recipients = recipients.exclude(id=actor_user.id)

    if not recipients.exists():
        return

    sender_user = actor_user if actor_user is not None and getattr(actor_user, "is_authenticated", False) else recipients.first()
    verb = f"VMS event: {event.event_type.replace('_', ' ')}"

    try:
        notify.send(
            sender=sender_user,
            recipient=recipients,
            module="vms",
            verb=verb,
            url="/vms-demo-admin",
        )
    except Exception:
        logger.exception("Failed to emit VMS notification for event %s", event.id)


@receiver(vms_event_signal)
def _dispatch_webhooks(sender, event, **kwargs):
    urls = _resolve_webhook_urls()
    if not urls:
        return

    body = json.dumps(
        {
            "event_id": event.id,
            "event_type": event.event_type,
            "reference": event.reference,
            "actor_username": event.actor_username,
            "visit_id": event.visit_id,
            "visitor_id": event.visitor_id,
            "payload": event.payload,
            "created_at": event.created_at.isoformat(),
        }
    ).encode("utf-8")

    for url in urls:
        try:
            request = urllib_request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib_request.urlopen(request, timeout=2):
                pass
        except (urllib_error.URLError, ValueError):
            logger.warning("Webhook delivery failed for VMS event %s to %s", event.id, url)
