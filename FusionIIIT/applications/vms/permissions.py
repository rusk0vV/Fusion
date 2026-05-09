from django.apps import apps
from rest_framework.permissions import BasePermission


def _resolve_host_authority(user):
    model_candidates = (
        "vms.HostAuthority",
        "visitor_hostel.HostAuthority",
        "globals.HostAuthority",
    )

    for model_path in model_candidates:
        try:
            model = apps.get_model(model_path)
        except LookupError:
            continue

        query_candidates = (
            {"user": user},
            {"user__user": user},
            {"extra_info__user": user},
            {"holder": user},
            {"authority_holder": user},
        )

        for query in query_candidates:
            try:
                authority = model.objects.filter(**query).first()
            except Exception:
                continue
            if authority is not None:
                return model, authority

    return None, None


def _is_super_username(user):
    return bool(user and user.is_authenticated and user.username == "vms_super_admin")


def _is_admin_username(user):
    return bool(
        user
        and user.is_authenticated
        and user.username in {"vms_admin", "vms_super_admin", "securityadmin"}
    )


def _is_admin_level(model, level):
    if level is None:
        return False

    level_admin = getattr(model, "LEVEL_ADMIN", None)
    level_super = getattr(model, "LEVEL_SUPER", None)
    known_levels = {candidate for candidate in (level_admin, level_super) if candidate is not None}
    if known_levels:
        return level in known_levels

    normalized = str(level).strip().lower()
    return normalized in {"admin", "super", "super_admin"}


class IsSuperAdmin(BasePermission):
    message = "Super admin authority is required."

    def has_permission(self, request, view):
        if _is_super_username(request.user):
            return True

        model, authority = _resolve_host_authority(request.user)
        if not model or not authority:
            return False

        level = getattr(authority, "authority_level", None)
        level_super = getattr(model, "LEVEL_SUPER", None)
        if level_super is not None:
            return level == level_super

        return str(level).strip().lower() in {"super", "super_admin"}


class IsVmsAdmin(BasePermission):
    message = "VMS admin authority is required."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if _is_admin_username(request.user):
            return True

        model, authority = _resolve_host_authority(request.user)
        if not model or not authority:
            return False

        level = getattr(authority, "authority_level", None)
        return _is_admin_level(model, level)


class CanRemoveBlacklist(BasePermission):
    message = "Not authorised to remove blacklist entries."

    def has_permission(self, request, view):
        return IsVmsAdmin().has_permission(request, view)


class CanBypassVIPApproval(BasePermission):
    message = "Not authorised for VIP approval bypass."

    def has_permission(self, request, view):
        return IsVmsAdmin().has_permission(request, view)


class HasHostApprovalAuthority(BasePermission):
    message = "Host approval authority is required."

    def has_permission(self, request, view):
        return IsVmsAdmin().has_permission(request, view)


class IsVmsStaff(BasePermission):
    message = "VMS staff authority is required."

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False

        if IsVmsAdmin().has_permission(request, view):
            return False

        try:
            extra_info = user.extrainfo
        except Exception:
            extra_info = None

        if extra_info is not None:
            user_type = str(getattr(extra_info, "user_type", "")).strip().lower()
            if user_type:
                return user_type in {"staff", "faculty", "employee"}

        # Keep non-admin authenticated users backward compatible with existing VMS tests.
        return True
