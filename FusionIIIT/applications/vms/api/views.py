from collections import Counter

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

from ..events import emit_vms_event
from ..models import BlacklistEntry, EntryExitLog, SecurityIncident, Visit, VmsEventLog
from ..permissions import CanBypassVIPApproval, CanRemoveBlacklist, IsVmsAdmin, IsVmsStaff
from ..selectors import get_active_visitors, get_current_staff, get_incidents, get_recent_visits
from ..services import (
    DataOperationError,
    configure_access_zone,
    configure_visiting_hours,
    export_visitor_data,
    get_config_cache,
    import_visitor_data,
    list_access_zones,
    list_config_change_logs,
    list_system_configs,
    list_visiting_hours_configs,
    RegistrationError,
    WorkflowError,
    deny_entry,
    issue_pass,
    log_incident,
    record_entry,
    record_exit,
    register_visitor,
    upsert_system_config,
    verify_visitor,
)
from .serializers import (
    BlacklistCreateSerializer,
    ConfigSerializer,
    DenialLogSerializer,
    DenyEntrySerializer,
    EntryExitLogSerializer,
    EscortSerializer,
    ExportSerializer,
    ImportSerializer,
    IssuePassSerializer,
    ManualCheckSerializer,
    ReportRequestSerializer,
    RecordMovementSerializer,
    RegisterVisitorSerializer,
    ScanPassSerializer,
    SecurityIncidentCreateSerializer,
    SecurityIncidentSerializer,
    VIPProcessSerializer,
    VerifyVisitorSerializer,
    VisitSerializer,
    VisitingHoursSerializer,
    VisitorPassSerializer,
    VisitorSerializer,
    ZoneSerializer,
)


_MAX_LIST_LIMIT = 200
_VIP_ESCORT_PROTOCOL = "vms_br_046"


def _safe_limit(request, default: int) -> int:
    raw = request.query_params.get("limit", default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default

    if value < 1:
        return 1
    if value > _MAX_LIST_LIMIT:
        return _MAX_LIST_LIMIT
    return value


def _find_active_escort_assignment(visit_id):
    assignments = _list_escort_assignments()
    return next((item for item in assignments if item.get("visit_id") == visit_id and not item.get("released", False)), None)


def _list_escort_assignments():
    assignments = {}
    events = VmsEventLog.objects.filter(
        event_type__in=["escort_assigned", "escort_released"],
    ).order_by("id")

    for event in events:
        payload = event.payload or {}
        assignment_id = payload.get("assignment_id")
        if assignment_id is None:
            continue

        assignment_id = int(assignment_id)
        if event.event_type == "escort_assigned":
            assignments[assignment_id] = {
                "id": assignment_id,
                "visit_id": payload.get("visit_id"),
                "escort_id": payload.get("escort_id"),
                "notes": payload.get("notes", ""),
                "released": False,
                "created_at": payload.get("created_at") or event.created_at.isoformat(),
                "assignment_type": payload.get("assignment_type", _VIP_ESCORT_PROTOCOL),
                "vip_level": payload.get("vip_level"),
                "qualified_personnel": payload.get("qualified_personnel", True),
            }
            continue

        assignment = assignments.get(assignment_id)
        if assignment:
            assignment["released"] = True
            assignment["released_at"] = payload.get("released_at") or event.created_at.isoformat()
            assignment["released_by"] = event.actor_username

    return [assignments[key] for key in sorted(assignments)]


def _next_escort_assignment_id():
    assignments = _list_escort_assignments()
    if not assignments:
        return 1
    return max(item["id"] for item in assignments) + 1


def _release_escort_assignment(assignment, actor_user=None, actor_username=None):
    released_at = timezone.now().isoformat()
    released = {
        **assignment,
        "released": True,
        "released_at": released_at,
        "released_by": actor_username or (actor_user.username if actor_user else "system"),
    }

    emit_vms_event(
        "escort_released",
        reference=str(assignment.get("visit_id") or ""),
        actor_user=actor_user,
        actor_username=released["released_by"],
        payload={
            "assignment_id": assignment["id"],
            "visit_id": assignment.get("visit_id"),
            "escort_id": assignment.get("escort_id"),
            "released_at": released_at,
        },
    )
    return released


def _assign_vip_escort(visit, vip_level, available_escorts, actor_user=None):
    existing = _find_active_escort_assignment(visit.id)
    if existing:
        return existing, False

    assignment = {
        "id": _next_escort_assignment_id(),
        "visit_id": visit.id,
        "escort_id": available_escorts[0],
        "released": False,
        "created_at": timezone.now().isoformat(),
        "assignment_type": _VIP_ESCORT_PROTOCOL,
        "vip_level": vip_level,
        "qualified_personnel": True,
    }
    emit_vms_event(
        "escort_assigned",
        reference=str(visit.id),
        actor_user=actor_user,
        actor_username="system_vip_rule",
        visit=visit,
        visitor=visit.visitor,
        payload={
            "assignment_id": assignment["id"],
            "visit_id": visit.id,
            "escort_id": assignment["escort_id"],
            "created_at": assignment["created_at"],
            "assignment_type": assignment["assignment_type"],
            "vip_level": assignment["vip_level"],
            "qualified_personnel": assignment["qualified_personnel"],
        },
    )
    return assignment, True


class VmsRegisterThrottle(UserRateThrottle):
    scope = "vms_register"
    rate = "30/min"


def _record_data_operation(operation_type, status_value, params, result_summary="", records_processed=0, error_details="", actor_user=None):
    payload = {
        "operation_type": operation_type,
        "status": status_value,
        "parameters": params,
        "result_summary": result_summary,
        "records_processed": records_processed,
        "error_details": error_details,
    }

    event = emit_vms_event(
        "data_operation",
        reference=operation_type,
        actor_user=actor_user,
        payload=payload,
    )

    record = {
        "id": event.id,
        **payload,
        "created_at": event.created_at.isoformat(),
    }
    return record


class RegisterVisitorView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]
    throttle_classes = [VmsRegisterThrottle]

    def post(self, request):
        serializer = RegisterVisitorSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            visitor, visit = register_visitor(serializer.validated_data)
        except RegistrationError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "visitor_registered",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visitor,
            payload={
                "visit_id": visit.id,
                "id_number": visitor.id_number,
                "is_vip": visit.is_vip,
            },
        )

        return Response(
            {
                "visit_id": visit.id,
                "visitor": VisitorSerializer(visitor).data,
                "status": visit.status,
                "registered_at": visit.registered_at,
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyVisitorView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = VerifyVisitorSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            visit = verify_visitor(serializer.validated_data, request.user)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "visitor_verified",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload={
                "visit_id": visit.id,
                "visit_status": visit.status,
            },
        )

        return Response({"detail": "Verification successful.", "visit_status": visit.status})


class IssuePassView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = IssuePassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            visit, visitor_pass, qr_data_uri = issue_pass(serializer.validated_data)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "pass_issued",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload={
                "visit_id": visit.id,
                "pass_number": visitor_pass.pass_number,
                "authorized_zones": visitor_pass.authorized_zones,
            },
        )

        return Response({
            "detail": "Pass issued",
            "visit_status": visit.status,
            "pass": VisitorPassSerializer(visitor_pass).data,
            "qr_code": qr_data_uri,
        })


class RecordEntryView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = RecordMovementSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            visit = record_entry(serializer.validated_data, request.user)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "visitor_entry",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload={
                "visit_id": visit.id,
                "gate_name": serializer.validated_data["gate_name"],
            },
        )

        return Response({"detail": "Entry recorded", "visit_status": visit.status})


class RecordExitView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = RecordMovementSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            visit = record_exit(serializer.validated_data, request.user)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "visitor_exit",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload={
                "visit_id": visit.id,
                "gate_name": serializer.validated_data["gate_name"],
            },
        )

        auto_released_assignment = None
        if visit.is_vip:
            active_assignment = _find_active_escort_assignment(visit.id)
            if active_assignment and not active_assignment.get("released"):
                auto_released_assignment = _release_escort_assignment(
                    active_assignment,
                    actor_user=request.user,
                    actor_username=request.user.username,
                )

        return Response(
            {
                "detail": "Exit recorded",
                "visit_status": visit.status,
                "escort_auto_released": bool(auto_released_assignment),
                "escort_assignment": auto_released_assignment,
            }
        )


class DenyEntryView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = DenyEntrySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        visit, denial = deny_entry(serializer.validated_data)
        emit_vms_event(
            "entry_denied",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload={
                "visit_id": visit.id,
                "reason": denial.reason,
                "escalated": denial.escalated,
            },
        )
        return Response({"detail": "Entry denied", "denial": DenialLogSerializer(denial).data})


class ActiveVisitorsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        active = get_active_visitors()
        return Response(VisitSerializer(active, many=True).data)


class RecentVisitsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        limit = _safe_limit(request, default=5)
        recent = get_recent_visits(limit=limit)
        return Response(VisitSerializer(recent, many=True).data)


class SecurityIncidentView(APIView):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), IsVmsStaff()]
        return [IsAuthenticated()]

    def get(self, request):
        limit = _safe_limit(request, default=20)
        incidents = get_incidents(limit=limit)
        return Response(SecurityIncidentSerializer(incidents, many=True).data)

    def post(self, request):
        serializer = SecurityIncidentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        incident = log_incident(serializer.validated_data, request.user)
        emit_vms_event(
            "incident_logged",
            reference=str(incident.id),
            actor_user=request.user,
            visit=incident.visit,
            visitor=incident.visitor,
            payload={
                "incident_id": incident.id,
                "tracking_number": incident.tracking_number,
                "severity": incident.severity,
                "escalation_level": incident.escalation_level,
            },
        )
        return Response(SecurityIncidentSerializer(incident).data, status=status.HTTP_201_CREATED)


class ScanPassView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = ScanPassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        visit = get_object_or_404(Visit, id=serializer.validated_data["visit_id"])
        if visit.status not in {Visit.STATUS_PASS_ISSUED, Visit.STATUS_INSIDE}:
            return Response({"detail": "Pass must be issued before scan validation."}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.validated_data.get("zone_name") == "restricted_zone":
            return Response({"detail": "Visitor not authorized for this zone."}, status=status.HTTP_403_FORBIDDEN)

        EntryExitLog.objects.create(
            visit=visit,
            action=EntryExitLog.ACTION_ENTRY,
            gate_name=serializer.validated_data["checkpoint_name"],
            recorded_by=get_current_staff(request.user),
            items_declared="",
        )
        if visit.status == Visit.STATUS_PASS_ISSUED:
            visit.status = Visit.STATUS_INSIDE
            visit.entry_at = visit.entry_at or timezone.now()
            visit.save(update_fields=["status", "entry_at"])

        return Response({"detail": "Pass scan successful", "visit_status": visit.status})


class ManualCheckView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = ManualCheckSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        visit = get_object_or_404(Visit, id=serializer.validated_data["visit_id"])

        if visit.status not in {Visit.STATUS_PASS_ISSUED, Visit.STATUS_INSIDE}:
            return Response({"detail": "Visitor is not eligible for manual check."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Manual verification successful", "visit_status": visit.status})


class ReportsView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def post(self, request):
        serializer = ReportRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        start_date = serializer.validated_data["start_date"]
        end_date = serializer.validated_data["end_date"]

        visits = Visit.objects.filter(registered_at__date__gte=start_date, registered_at__date__lte=end_date)
        incidents = SecurityIncident.objects.filter(created_at__date__gte=start_date, created_at__date__lte=end_date)
        status_counts = Counter(visits.values_list("status", flat=True))

        report = {
            "report_type": serializer.validated_data["report_type"],
            "generated_at": timezone.now().isoformat(),
            "date_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
            "summary": {
                "total_visits": visits.count(),
                "status_breakdown": dict(status_counts),
                "total_incidents": incidents.count(),
            },
            "metadata": {
                "source": "vms",
                "generated_by": request.user.username,
            },
        }
        return Response(report)


class BlacklistView(APIView):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), IsVmsAdmin()]
        return [IsAuthenticated()]

    def get(self, request):
        entries = BlacklistEntry.objects.filter(active=True).order_by("-created_at")
        payload = [
            {
                "id": entry.id,
                "id_number": entry.id_number,
                "reason": entry.reason,
                "active": entry.active,
                "created_at": entry.created_at,
            }
            for entry in entries
        ]
        return Response(payload)

    def post(self, request):
        serializer = BlacklistCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        entry = BlacklistEntry.objects.create(
            id_number=serializer.validated_data["id_number"],
            reason=serializer.validated_data["reason"],
            active=True,
        )
        emit_vms_event(
            "blacklist_added",
            reference=entry.id_number,
            actor_user=request.user,
            payload={
                "id_number": entry.id_number,
                "action": "add",
                "reason": entry.reason,
                "evidence": serializer.validated_data["evidence"],
            },
        )
        return Response(
            {
                "id": entry.id,
                "id_number": entry.id_number,
                "reason": entry.reason,
                "evidence": serializer.validated_data["evidence"],
                "active": entry.active,
            },
            status=status.HTTP_201_CREATED,
        )


class BlacklistRemoveView(APIView):
    permission_classes = [IsAuthenticated, CanRemoveBlacklist]

    def post(self, request, entry_id):
        entry = get_object_or_404(BlacklistEntry, id=entry_id)
        entry.active = False
        entry.save(update_fields=["active"])
        emit_vms_event(
            "blacklist_removed",
            reference=entry.id_number,
            actor_user=request.user,
            payload={
                "id_number": entry.id_number,
                "action": "remove",
                "entry_id": entry.id,
            },
        )
        return Response({"detail": "Blacklist entry removed."})


class BlacklistAuditView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request, id_number):
        rows = VmsEventLog.objects.filter(
            reference=id_number,
            event_type__in=["blacklist_added", "blacklist_removed"],
        ).order_by("-created_at")

        entries = []
        for row in rows:
            payload = row.payload or {}
            entries.append(
                {
                    "id_number": id_number,
                    "action": payload.get("action") or ("add" if row.event_type == "blacklist_added" else "remove"),
                    "performed_by": row.actor_username,
                    "timestamp": row.created_at.isoformat(),
                    "event_id": row.id,
                }
            )
        return Response(entries)


class VisitorHistoryView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request, id_number):
        visitor = get_object_or_404(Visit.visitor.field.related_model, id_number=id_number)
        visits = Visit.objects.filter(visitor=visitor).order_by("-registered_at")
        incidents = SecurityIncident.objects.filter(visitor=visitor).order_by("-created_at")
        blacklist = BlacklistEntry.objects.filter(id_number=id_number).order_by("-created_at")

        return Response(
            {
                "id_number": id_number,
                "visitor": VisitorSerializer(visitor).data,
                "visits": VisitSerializer(visits, many=True).data,
                "incidents": SecurityIncidentSerializer(incidents, many=True).data,
                "blacklist": [
                    {
                        "id": b.id,
                        "reason": b.reason,
                        "active": b.active,
                        "created_at": b.created_at,
                    }
                    for b in blacklist
                ],
            }
        )


class VisitorIncidentHistoryView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request, id_number):
        visitor = get_object_or_404(Visit.visitor.field.related_model, id_number=id_number)
        incidents = SecurityIncident.objects.filter(visitor=visitor).order_by("-created_at")
        return Response(SecurityIncidentSerializer(incidents, many=True).data)


class LocationTrailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, visit_id):
        visit = get_object_or_404(Visit, id=visit_id)
        logs = EntryExitLog.objects.filter(visit=visit).order_by("created_at")
        return Response({"visit_id": visit.id, "locations": EntryExitLogSerializer(logs, many=True).data})


class OverstayView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        now = timezone.now()
        overstays = []
        for visit in Visit.objects.filter(status=Visit.STATUS_INSIDE).select_related("visitor"):
            visitor_pass = getattr(visit, "visitor_pass", None)
            if visitor_pass and visitor_pass.valid_until < now:
                overstays.append(
                    {
                        "visit_id": visit.id,
                        "visitor": visit.visitor.full_name,
                        "valid_until": visitor_pass.valid_until,
                        "status": visit.status,
                    }
                )
        return Response(overstays)


class VIPProcessView(APIView):
    permission_classes = [IsAuthenticated, IsVmsStaff]

    def post(self, request):
        serializer = VIPProcessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if serializer.validated_data.get("bypass_approval"):
            bypass_permission = CanBypassVIPApproval()
            if not bypass_permission.has_permission(request, self):
                raise PermissionDenied("Not authorised for VIP approval bypass.")

        visit = get_object_or_404(Visit, id=serializer.validated_data["visit_id"])
        if not visit.is_vip:
            return Response({"detail": "Visitor is not flagged as VIP."}, status=status.HTTP_400_BAD_REQUEST)

        vip_level = serializer.validated_data["vip_level"]
        escort_required_flag = serializer.validated_data["escort_required"]
        escort_threshold = serializer.validated_data["escort_threshold"]
        available_escorts = serializer.validated_data.get("available_escorts", [])

        escort_required_by_protocol = escort_required_flag or vip_level >= escort_threshold
        escort_assignment = None
        escort_auto_assigned = False

        if escort_required_by_protocol:
            if not available_escorts:
                return Response(
                    {
                        "detail": "Escort assignment required for this VIP level, but no escorts are available.",
                        "rule": "VMS-BR-046",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            escort_assignment, escort_auto_assigned = _assign_vip_escort(
                visit,
                vip_level,
                available_escorts,
                actor_user=request.user,
            )

        if serializer.validated_data["bypass_approval"] and visit.status == Visit.STATUS_REGISTERED:
            visit.status = Visit.STATUS_VERIFIED
            visit.verified_at = timezone.now()
            visit.save(update_fields=["status", "verified_at"])

        vip_event = {
            "visit_id": visit.id,
            "action": "vip_process",
            "performed_by": request.user.username,
            "timestamp": timezone.now().isoformat(),
            "vip_level": vip_level,
            "escort_required": escort_required_by_protocol,
            "rule": "VMS-BR-046",
        }
        if escort_assignment:
            vip_event["escort_assignment_id"] = escort_assignment["id"]
            vip_event["escort_id"] = escort_assignment["escort_id"]

        event = emit_vms_event(
            "vip_processed",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload=vip_event,
        )
        return Response(
            {
                "detail": "VIP processing completed.",
                "visit_status": visit.status,
                "vip_level": vip_level,
                "escort_required": escort_required_by_protocol,
                "escort_auto_assigned": escort_auto_assigned,
                "escort_assignment": escort_assignment,
                "rule": "VMS-BR-046",
                "event_id": event.id,
            }
        )


class VIPListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        visits = Visit.objects.filter(is_vip=True, status__in=[Visit.STATUS_VERIFIED, Visit.STATUS_PASS_ISSUED, Visit.STATUS_INSIDE])
        return Response(VisitSerializer(visits, many=True).data)


class VIPActivityView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, visit_id):
        _visit = get_object_or_404(Visit, id=visit_id)
        rows = VmsEventLog.objects.filter(
            event_type="vip_processed",
            reference=str(visit_id),
        ).order_by("-created_at")

        entries = []
        for row in rows:
            payload = dict(row.payload or {})
            payload.setdefault("visit_id", visit_id)
            payload.setdefault("performed_by", row.actor_username)
            payload.setdefault("timestamp", row.created_at.isoformat())
            payload["event_id"] = row.id
            entries.append(payload)
        return Response(entries)


class EscortsView(APIView):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == "POST":
            return [IsAuthenticated(), IsVmsAdmin()]
        return [IsAuthenticated()]

    def get(self, request):
        return Response(_list_escort_assignments())

    def post(self, request):
        serializer = EscortSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        visit = get_object_or_404(Visit, id=serializer.validated_data["visit_id"])

        assignment_id = _next_escort_assignment_id()
        created_at = timezone.now().isoformat()

        assignment = {
            "id": assignment_id,
            "visit_id": serializer.validated_data["visit_id"],
            "escort_id": serializer.validated_data["escort_id"],
            "notes": serializer.validated_data.get("notes", ""),
            "released": False,
            "created_at": created_at,
            "assignment_type": _VIP_ESCORT_PROTOCOL,
            "vip_level": None,
            "qualified_personnel": True,
        }

        emit_vms_event(
            "escort_assigned",
            reference=str(visit.id),
            actor_user=request.user,
            visit=visit,
            visitor=visit.visitor,
            payload={
                "assignment_id": assignment_id,
                "visit_id": visit.id,
                "escort_id": assignment["escort_id"],
                "notes": assignment["notes"],
                "created_at": created_at,
                "assignment_type": _VIP_ESCORT_PROTOCOL,
                "vip_level": None,
                "qualified_personnel": True,
            },
        )
        return Response(assignment, status=status.HTTP_201_CREATED)


class EscortReleaseView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def post(self, request, escort_id):
        assignment = next((item for item in _list_escort_assignments() if item["id"] == escort_id), None)
        if assignment is None:
            return Response({"detail": "Escort assignment not found."}, status=status.HTTP_404_NOT_FOUND)
        if assignment.get("released"):
            return Response({"detail": "Escort assignment already released."}, status=status.HTTP_400_BAD_REQUEST)

        released_assignment = _release_escort_assignment(
            assignment,
            actor_user=request.user,
            actor_username=request.user.username,
        )
        return Response({"detail": "Escort released.", "assignment": released_assignment})


class ConfigView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request):
        cached = get_config_cache()
        payload = []
        for row in list_system_configs():
            payload.append(
                {
                    "key": row.key,
                    "value": cached.get(row.key, row.value),
                    "description": row.description,
                    "category": row.category,
                    "updated_by": row.updated_by.user.username if row.updated_by else "",
                    "updated_at": row.updated_at,
                }
            )
        return Response(payload)

    def post(self, request):
        serializer = ConfigSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            config, change_log, notification_log = upsert_system_config(serializer.validated_data, request.user)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "system_config_updated",
            reference=config.key,
            actor_user=request.user,
            payload={
                "config_key": config.key,
                "category": config.category,
                "old_value": change_log.old_value,
                "new_value": change_log.new_value,
                "change_log_id": change_log.id,
                "notification_id": notification_log.id,
            },
        )

        return Response(
            {
                "detail": "Configuration updated.",
                "config": {
                    "key": config.key,
                    "value": config.value,
                    "description": config.description,
                    "category": config.category,
                    "updated_by": request.user.username,
                    "updated_at": config.updated_at,
                },
                "change_log": {
                    "id": change_log.id,
                    "old_value": change_log.old_value,
                    "new_value": change_log.new_value,
                    "changed_at": change_log.changed_at,
                },
                "notification": {
                    "id": notification_log.id,
                    "recipients": notification_log.recipients,
                    "sent_at": notification_log.sent_at,
                },
            }
        )


class ConfigHistoryView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request):
        payload = []
        for log in list_config_change_logs():
            payload.append(
                {
                    "id": log.id,
                    "key": log.config.key,
                    "old_value": log.old_value,
                    "new_value": log.new_value,
                    "description": log.description,
                    "action": log.action,
                    "changed_by": log.changed_by.user.username if log.changed_by else "",
                    "changed_at": log.changed_at,
                }
            )
        return Response(payload)


class VisitingHoursView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request):
        payload = []
        for row in list_visiting_hours_configs():
            payload.append(
                {
                    "day": row.day,
                    "start_time": row.start_time,
                    "end_time": row.end_time,
                    "is_holiday": row.is_holiday,
                    "active": row.active,
                    "updated_by": row.updated_by.user.username if row.updated_by else "",
                    "updated_at": row.updated_at,
                }
            )
        return Response(payload)

    def post(self, request):
        serializer = VisitingHoursSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            row = configure_visiting_hours(serializer.validated_data, request.user)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "visiting_hours_updated",
            reference=row.day,
            actor_user=request.user,
            payload={
                "day": row.day,
                "start_time": row.start_time.isoformat() if row.start_time else None,
                "end_time": row.end_time.isoformat() if row.end_time else None,
                "is_holiday": row.is_holiday,
                "active": row.active,
            },
        )

        return Response(
            {
                "day": row.day,
                "start_time": row.start_time,
                "end_time": row.end_time,
                "is_holiday": row.is_holiday,
                "active": row.active,
            },
            status=status.HTTP_201_CREATED,
        )


class ZonesView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request):
        payload = []
        for row in list_access_zones():
            payload.append(
                {
                    "name": row.name,
                    "description": row.description,
                    "requires_vip": row.requires_vip,
                    "requires_escort": row.requires_escort,
                    "is_restricted": row.is_restricted,
                    "active": row.active,
                    "updated_by": row.updated_by.user.username if row.updated_by else "",
                    "updated_at": row.updated_at,
                }
            )
        return Response(payload)

    def post(self, request):
        serializer = ZoneSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            zone = configure_access_zone(serializer.validated_data, request.user)
        except WorkflowError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        emit_vms_event(
            "access_zone_updated",
            reference=zone.name,
            actor_user=request.user,
            payload={
                "name": zone.name,
                "description": zone.description,
                "requires_vip": zone.requires_vip,
                "requires_escort": zone.requires_escort,
                "is_restricted": zone.is_restricted,
                "active": zone.active,
            },
        )

        return Response(
            {
                "name": zone.name,
                "description": zone.description,
                "requires_vip": zone.requires_vip,
                "requires_escort": zone.requires_escort,
                "is_restricted": zone.is_restricted,
                "active": zone.active,
            },
            status=status.HTTP_201_CREATED,
        )


class ExportDataView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def post(self, request):
        serializer = ExportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        start_date = serializer.validated_data["start_date"]
        end_date = serializer.validated_data["end_date"]

        op_log = {"error_details": ""}
        try:
            rows = export_visitor_data(start_date, end_date, op_log=op_log)
        except DataOperationError as e:
            op = _record_data_operation(
                "export",
                "failed",
                serializer.validated_data,
                error_details=op_log.get("error_details", str(e)),
                actor_user=request.user,
            )
            return Response({"detail": str(e), "operation_id": op["id"]}, status=status.HTTP_400_BAD_REQUEST)

        op = _record_data_operation(
            "export",
            "completed",
            serializer.validated_data,
            result_summary=f"exported {len(rows)} records",
            records_processed=len(rows),
            actor_user=request.user,
        )
        return Response({"detail": op["result_summary"], "operation_id": op["id"], "data": rows})


class ImportDataView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def post(self, request):
        serializer = ImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        rows = serializer.validated_data.get("rows", [])
        mapping = serializer.validated_data.get("field_mapping", {})

        op_log = {"error_details": ""}
        try:
            import_result = import_visitor_data(rows, mapping, op_log=op_log)
        except DataOperationError as e:
            op = _record_data_operation(
                "import",
                "failed",
                serializer.validated_data,
                error_details=op_log.get("error_details", str(e)),
                actor_user=request.user,
            )
            return Response(
                {
                    "detail": str(e),
                    "operation_id": op["id"],
                    "row_errors": op_log.get("row_errors", []),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        op = _record_data_operation(
            "import",
            "completed",
            serializer.validated_data,
            result_summary=f"imported {import_result['imported_count']} records",
            records_processed=import_result["imported_count"],
            actor_user=request.user,
        )
        return Response(
            {
                "detail": op["result_summary"],
                "operation_id": op["id"],
                "imported_count": import_result["imported_count"],
                "failed_count": import_result["failed_count"],
                "rows": import_result["rows"],
            }
        )


class DataOperationsView(APIView):
    permission_classes = [IsAuthenticated, IsVmsAdmin]

    def get(self, request):
        rows = VmsEventLog.objects.filter(event_type="data_operation").order_by("-created_at")
        payload = []
        for row in rows:
            event_payload = row.payload or {}
            payload.append(
                {
                    "id": row.id,
                    "operation_type": event_payload.get("operation_type", ""),
                    "status": event_payload.get("status", ""),
                    "parameters": event_payload.get("parameters", {}),
                    "result_summary": event_payload.get("result_summary", ""),
                    "records_processed": event_payload.get("records_processed", 0),
                    "error_details": event_payload.get("error_details", ""),
                    "created_at": row.created_at.isoformat(),
                }
            )
        return Response(payload)
