from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from applications.vms.models import SystemConfig, VmsEventLog, Visit, Visitor
from applications.vms.services import RegistrationError, register_visitor


class RegisterVisitorServiceTest(TestCase):
    def test_register_creates_visitor_and_visit(self):
        data = {
            "full_name": "Test Visitor",
            "id_number": "TEST001",
            "id_type": "aadhaar",
            "contact_phone": "9999999999",
            "purpose": "Meeting",
            "host_name": "Dr. Host",
            "host_department": "CSE",
        }
        visitor, visit = register_visitor(data)
        self.assertEqual(visitor.full_name, "Test Visitor")
        self.assertEqual(visit.status, Visit.STATUS_REGISTERED)
        self.assertEqual(visit.visitor, visitor)

    def test_blacklisted_visitor_blocked(self):
        from applications.vms.models import BlacklistEntry
        BlacklistEntry.objects.create(id_number="BL001", reason="test", active=True)
        data = {
            "full_name": "Blocked Person",
            "id_number": "BL001",
            "id_type": "aadhaar",
            "contact_phone": "0000000000",
            "purpose": "Visit",
            "host_name": "Host",
            "host_department": "Dept",
        }
        with self.assertRaises(RegistrationError):
            register_visitor(data)


class RegisterVisitorAPITest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="teststaff", password="pass1234")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_register_endpoint_returns_201(self):
        payload = {
            "full_name": "API Visitor",
            "id_number": "API001",
            "id_type": "passport",
            "contact_phone": "1234567890",
            "purpose": "Conference",
            "host_name": "Prof. X",
            "host_department": "ECE",
        }
        response = self.client.post("/vms/register/", payload, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertIn("visit_id", response.data)

    def test_active_endpoint_returns_200(self):
        response = self.client.get("/vms/active/")
        self.assertEqual(response.status_code, 200)


class VIPEscortAssignmentRuleTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="vipstaff", password="pass1234")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        self.visitor = Visitor.objects.create(
            full_name="VIP Visitor",
            id_number="VIP001",
            id_type=Visitor.ID_PASSPORT,
            contact_phone="9999999999",
            contact_email="vip@example.com",
        )
        self.visit = Visit.objects.create(
            visitor=self.visitor,
            purpose="VIP Meeting",
            host_name="Director",
            host_department="Admin",
            status=Visit.STATUS_REGISTERED,
            is_vip=True,
        )

    def test_vip_br046_assigns_escort_when_threshold_met(self):
        payload = {
            "visit_id": self.visit.id,
            "vip_level": 5,
            "escort_required": False,
            "escort_threshold": 3,
            "available_escorts": [101],
        }
        response = self.client.post("/vms/vip/process/", payload, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["rule"], "VMS-BR-046")
        self.assertTrue(response.data["escort_required"])
        self.assertTrue(response.data["escort_auto_assigned"])
        self.assertEqual(response.data["escort_assignment"]["escort_id"], 101)

    def test_vip_br046_blocks_when_escort_required_but_unavailable(self):
        payload = {
            "visit_id": self.visit.id,
            "vip_level": 4,
            "escort_required": False,
            "escort_threshold": 3,
            "available_escorts": [],
        }
        response = self.client.post("/vms/vip/process/", payload, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["rule"], "VMS-BR-046")


class EscortAssignmentAdminAccessTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(username="vms_admin", password="pass1234")
        self.staff = User.objects.create_user(username="gate_staff", password="pass1234")

        visitor = Visitor.objects.create(
            full_name="Escort Target",
            id_number="ESC-001",
            id_type=Visitor.ID_PASSPORT,
            contact_phone="9999999999",
            contact_email="escort@example.com",
        )
        self.visit = Visit.objects.create(
            visitor=visitor,
            purpose="VIP Escort Test",
            host_name="Admin",
            host_department="Administration",
            status=Visit.STATUS_VERIFIED,
            is_vip=True,
        )

    def test_admin_can_assign_and_release_escort(self):
        self.client.force_authenticate(user=self.admin)
        assign_payload = {
            "visit_id": self.visit.id,
            "escort_id": 101,
            "notes": "Protocol: accompany to admin block",
        }

        assign_response = self.client.post("/vms/escorts/", assign_payload, format="json")
        self.assertEqual(assign_response.status_code, 201)
        self.assertEqual(assign_response.data["visit_id"], self.visit.id)
        self.assertEqual(assign_response.data["escort_id"], 101)
        self.assertEqual(assign_response.data.get("notes"), assign_payload["notes"])

        assignment_id = assign_response.data["id"]

        list_response = self.client.get("/vms/escorts/")
        self.assertEqual(list_response.status_code, 200)
        self.assertTrue(any(item.get("id") == assignment_id for item in list_response.data))

        release_response = self.client.post(f"/vms/escorts/{assignment_id}/release/", {}, format="json")
        self.assertEqual(release_response.status_code, 200)
        self.assertTrue(release_response.data["assignment"]["released"])

    def test_staff_is_denied_for_escort_assign_and_release(self):
        self.client.force_authenticate(user=self.staff)

        assign_response = self.client.post(
            "/vms/escorts/",
            {
                "visit_id": self.visit.id,
                "escort_id": 102,
            },
            format="json",
        )
        self.assertEqual(assign_response.status_code, 403)

        release_response = self.client.post("/vms/escorts/1/release/", {}, format="json")
        self.assertEqual(release_response.status_code, 403)


class VmsRbacTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin_user = User.objects.create_user(username="vms_admin", password="pass1234")
        self.staff_user = User.objects.create_user(username="gate_staff", password="pass1234")

    def test_admin_cannot_access_staff_register_endpoint(self):
        self.client.force_authenticate(user=self.admin_user)
        payload = {
            "full_name": "Admin Attempt",
            "id_number": "ADMIN-001",
            "id_type": "passport",
            "contact_phone": "1234567890",
            "purpose": "Test",
            "host_name": "Host",
            "host_department": "CSE",
        }
        response = self.client.post("/vms/register/", payload, format="json")
        self.assertEqual(response.status_code, 403)

    def test_staff_cannot_access_admin_reports_endpoint(self):
        self.client.force_authenticate(user=self.staff_user)
        payload = {
            "report_type": "visitor_summary",
            "start_date": "2026-01-01",
            "end_date": "2026-01-31",
        }
        response = self.client.post("/vms/reports/", payload, format="json")
        self.assertEqual(response.status_code, 403)


class ImportPersistenceApiTest(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(username="vms_admin", password="pass1234")
        self.client = APIClient()
        self.client.force_authenticate(user=self.admin)

    def test_import_creates_visitor_and_visit_records(self):
        payload = {
            "format": "json",
            "field_mapping": {
                "visitor_name": "full_name",
                "visitor_id": "id_number",
                "dept": "host_department",
            },
            "rows": [
                {
                    "visitor_name": "Imported User",
                    "visitor_id": "IMP-1001",
                    "dept": "ECE",
                }
            ],
        }

        response = self.client.post("/vms/import/", payload, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["imported_count"], 1)
        self.assertEqual(response.data["failed_count"], 0)
        self.assertTrue(Visitor.objects.filter(id_number="IMP-1001").exists())
        self.assertTrue(Visit.objects.filter(visitor__id_number="IMP-1001").exists())


class EventLogPersistenceTest(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(username="vms_admin", password="pass1234")
        self.client = APIClient()
        self.client.force_authenticate(user=self.admin)

    def test_blacklist_actions_are_logged_in_persistent_event_store(self):
        payload = {
            "id_number": "BL-2001",
            "reason": "Policy violation",
            "evidence": "INC-TEST-01",
        }

        add_response = self.client.post("/vms/blacklist/", payload, format="json")
        self.assertEqual(add_response.status_code, 201)

        audit_response = self.client.get("/vms/blacklist/audit/BL-2001/")
        self.assertEqual(audit_response.status_code, 200)
        self.assertTrue(any(row.get("action") == "add" for row in audit_response.data))

        self.assertTrue(
            VmsEventLog.objects.filter(
                event_type="blacklist_added",
                reference="BL-2001",
            ).exists()
        )


class SystemConfigurationWorkflowAccessTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(username="vms_admin", password="pass1234")
        self.staff = User.objects.create_user(username="gate_staff", password="pass1234")

    def test_staff_is_denied_for_system_configuration_endpoints(self):
        self.client.force_authenticate(user=self.staff)

        get_config = self.client.get("/vms/config/")
        self.assertEqual(get_config.status_code, 403)

        get_history = self.client.get("/vms/config/history/")
        self.assertEqual(get_history.status_code, 403)

        get_hours = self.client.get("/vms/visiting-hours/")
        self.assertEqual(get_hours.status_code, 403)

        get_zones = self.client.get("/vms/zones/")
        self.assertEqual(get_zones.status_code, 403)

        post_config = self.client.post(
            "/vms/config/",
            {"key": "max_daily_visitors", "value": "500", "description": "test"},
            format="json",
        )
        self.assertEqual(post_config.status_code, 403)

    def test_admin_can_update_system_configuration_and_conflicts_are_blocked(self):
        self.client.force_authenticate(user=self.admin)

        update_response = self.client.post(
            "/vms/config/",
            {
                "key": "strict_security_mode",
                "value": "true",
                "description": "Enable strict checks",
            },
            format="json",
        )
        self.assertEqual(update_response.status_code, 200)
        self.assertTrue(SystemConfig.objects.filter(key="strict_security_mode").exists())

        conflict_response = self.client.post(
            "/vms/config/",
            {
                "key": "enable_vip_bypass",
                "value": "true",
                "description": "Should conflict with strict mode",
            },
            format="json",
        )
        self.assertEqual(conflict_response.status_code, 400)

        hours_response = self.client.post(
            "/vms/visiting-hours/",
            {
                "day": "monday",
                "start_time": "09:00",
                "end_time": "17:00",
                "is_holiday": False,
            },
            format="json",
        )
        self.assertEqual(hours_response.status_code, 201)

        zones_response = self.client.post(
            "/vms/zones/",
            {
                "name": "server_room",
                "description": "restricted infrastructure area",
                "requires_vip": True,
                "requires_escort": True,
                "is_restricted": True,
                "active": True,
            },
            format="json",
        )
        self.assertEqual(zones_response.status_code, 201)

        history_response = self.client.get("/vms/config/history/")
        self.assertEqual(history_response.status_code, 200)
        self.assertGreaterEqual(len(history_response.data), 1)

        self.assertTrue(
            VmsEventLog.objects.filter(
                event_type="system_config_updated",
                reference="strict_security_mode",
            ).exists()
        )
