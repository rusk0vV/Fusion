from rest_framework import serializers

from ..models import (
    BlacklistEntry,
    DenialLog,
    EntryExitLog,
    SecurityIncident,
    VerificationLog,
    Visit,
    Visitor,
    VisitorPass,
)


def _mask_id_number(value):
    if not value:
        return ""

    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)

    return "*" * (len(value) - 4) + value[-4:]


class VisitorSerializer(serializers.ModelSerializer):
    """Admin-only serializer with full PII fields."""

    class Meta:
        model = Visitor
        fields = "__all__"


class VisitorPublicSerializer(serializers.ModelSerializer):
    id_number = serializers.SerializerMethodField()

    class Meta:
        model = Visitor
        fields = ("id", "full_name", "id_type", "id_number")

    def get_id_number(self, obj):
        return _mask_id_number(obj.id_number)


class VisitSerializer(serializers.ModelSerializer):
    visitor = VisitorPublicSerializer()
    gate_name = serializers.SerializerMethodField()
    authorized_zones = serializers.SerializerMethodField()

    class Meta:
        model = Visit
        fields = "__all__"

    def get_gate_name(self, obj):
        annotated_gate = getattr(obj, "latest_gate_name", None)
        if annotated_gate:
            return annotated_gate

        last_log = obj.movement_logs.order_by("-created_at").first()
        return last_log.gate_name if last_log else ""

    def get_authorized_zones(self, obj):
        annotated_zone = getattr(obj, "latest_authorized_zones", None)
        if annotated_zone:
            return annotated_zone

        try:
            return obj.visitor_pass.authorized_zones
        except VisitorPass.DoesNotExist:
            return ""


class VisitorPassSerializer(serializers.ModelSerializer):
    class Meta:
        model = VisitorPass
        exclude = ("barcode_data",)


class VerificationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationLog
        fields = "__all__"


class DenialLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DenialLog
        fields = "__all__"


class EntryExitLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = EntryExitLog
        fields = "__all__"


class SecurityIncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityIncident
        fields = "__all__"


class RegisterVisitorSerializer(serializers.Serializer):
    full_name = serializers.CharField()
    id_number = serializers.CharField()
    id_type = serializers.CharField()
    contact_phone = serializers.CharField()
    contact_email = serializers.EmailField(required=False, allow_blank=True)
    photo_reference = serializers.CharField(required=False, allow_blank=True)
    purpose = serializers.CharField()
    host_name = serializers.CharField()
    host_department = serializers.CharField()
    host_contact = serializers.CharField(required=False, allow_blank=True)
    expected_duration_minutes = serializers.IntegerField(min_value=5, default=60)
    is_vip = serializers.BooleanField(default=False)

    def validate_id_type(self, value):
        canonical = {choice for choice, _label in Visitor.ID_TYPES}
        aliases = {
            "drivers_license": Visitor.ID_DL,
            "driving_license": Visitor.ID_DL,
        }
        normalized = aliases.get(value, value)
        if normalized not in canonical:
            raise serializers.ValidationError(
                f"Invalid id_type '{value}'. Use one of: {', '.join(sorted(canonical))}"
            )
        return normalized


class VerifyVisitorSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    method = serializers.ChoiceField(choices=VerificationLog.METHODS, default=VerificationLog.METHOD_MANUAL)
    result = serializers.BooleanField()
    notes = serializers.CharField(required=False, allow_blank=True)


class IssuePassSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    authorized_zones = serializers.CharField(default="public")


class RecordMovementSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    gate_name = serializers.CharField()
    items_declared = serializers.CharField(required=False, allow_blank=True)


class DenyEntrySerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    reason = serializers.CharField()
    remarks = serializers.CharField(required=False, allow_blank=True)
    escalated = serializers.BooleanField(default=False)


class SecurityIncidentCreateSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField(required=False)
    visitor_id = serializers.IntegerField(required=False)
    severity = serializers.ChoiceField(choices=SecurityIncident.SEVERITIES)
    issue_type = serializers.ChoiceField(choices=SecurityIncident.ISSUE_TYPES)
    description = serializers.CharField()


class ScanPassSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    checkpoint_name = serializers.CharField()
    zone_name = serializers.CharField(required=False, allow_blank=True, default="public")


class ManualCheckSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    notes = serializers.CharField(required=False, allow_blank=True)


class ReportRequestSerializer(serializers.Serializer):
    REPORT_TYPES = (
        ("visitor_summary", "Visitor Summary"),
        ("incident_summary", "Incident Summary"),
    )

    report_type = serializers.ChoiceField(choices=REPORT_TYPES)
    start_date = serializers.DateField()
    end_date = serializers.DateField()

    def validate(self, attrs):
        if attrs["start_date"] > attrs["end_date"]:
            raise serializers.ValidationError("start_date must be less than or equal to end_date")
        return attrs


class BlacklistCreateSerializer(serializers.Serializer):
    id_number = serializers.CharField()
    reason = serializers.CharField()
    evidence = serializers.CharField(required=True)


class VIPProcessSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    bypass_approval = serializers.BooleanField(default=False)
    vip_level = serializers.IntegerField(min_value=1, max_value=10, default=1)
    escort_required = serializers.BooleanField(default=False)
    available_escorts = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        default=list,
    )
    escort_threshold = serializers.IntegerField(min_value=1, max_value=10, default=3)


class EscortSerializer(serializers.Serializer):
    visit_id = serializers.IntegerField()
    escort_id = serializers.IntegerField()
    notes = serializers.CharField(required=False, allow_blank=True, max_length=500)


class ConfigSerializer(serializers.Serializer):
    key = serializers.CharField()
    value = serializers.CharField()
    description = serializers.CharField(required=False, allow_blank=True)

    def validate_key(self, value):
        key = value.strip().lower()
        if not key:
            raise serializers.ValidationError("key cannot be empty")
        return key


class VisitingHoursSerializer(serializers.Serializer):
    day = serializers.CharField()
    start_time = serializers.TimeField(required=False, allow_null=True)
    end_time = serializers.TimeField(required=False, allow_null=True)
    is_holiday = serializers.BooleanField(default=False)

    def validate_day(self, value):
        normalized = value.strip().lower()
        valid = {
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        }
        if normalized not in valid:
            raise serializers.ValidationError("day must be a valid weekday")
        return normalized


class ZoneSerializer(serializers.Serializer):
    name = serializers.CharField()
    description = serializers.CharField(required=False, allow_blank=True)
    requires_vip = serializers.BooleanField(default=False)
    requires_escort = serializers.BooleanField(default=False)
    is_restricted = serializers.BooleanField(default=False)
    active = serializers.BooleanField(default=True)

    def validate_name(self, value):
        normalized = value.strip().lower()
        if not normalized:
            raise serializers.ValidationError("name cannot be empty")
        return normalized


class ExportSerializer(serializers.Serializer):
    format = serializers.ChoiceField(choices=(("csv", "csv"), ("json", "json"), ("xlsx", "xlsx")))
    start_date = serializers.DateField()
    end_date = serializers.DateField()

    def validate(self, attrs):
        if attrs["start_date"] > attrs["end_date"]:
            raise serializers.ValidationError("start_date must be less than or equal to end_date")
        return attrs


class ImportSerializer(serializers.Serializer):
    format = serializers.ChoiceField(choices=(("csv", "csv"), ("json", "json"), ("xlsx", "xlsx")))
    field_mapping = serializers.DictField(child=serializers.CharField())
    rows = serializers.ListField(required=False)
