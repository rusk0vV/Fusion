from applications.globals.models import ExtraInfo
from django.db.models import OuterRef, Subquery

from .models import EntryExitLog, SecurityIncident, Visit, VisitorPass


def _with_visit_annotations(queryset):
    latest_gate = EntryExitLog.objects.filter(
        visit_id=OuterRef("pk"),
    ).order_by("-created_at").values("gate_name")[:1]

    latest_zone = VisitorPass.objects.filter(
        visit_id=OuterRef("pk"),
    ).values("authorized_zones")[:1]

    return queryset.select_related("visitor").annotate(
        latest_gate_name=Subquery(latest_gate),
        latest_authorized_zones=Subquery(latest_zone),
    )


def get_current_staff(user):
    """Return the ExtraInfo record for the given user, or None."""
    return ExtraInfo.objects.filter(user=user).first()


def get_active_visitors():
    """Return visits that are currently inside or have a pass issued."""
    return _with_visit_annotations(Visit.objects.filter(
        status__in=[Visit.STATUS_INSIDE, Visit.STATUS_PASS_ISSUED],
    ).order_by("-registered_at"))


def get_recent_visits(limit=5):
    """Return the most recent visits, ordered newest-first."""
    return _with_visit_annotations(Visit.objects.order_by("-registered_at"))[:limit]


def get_incidents(limit=20):
    """Return the most recent security incidents."""
    return SecurityIncident.objects.order_by("-created_at")[:limit]
