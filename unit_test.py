"""
Test Cases for Company Meeting Room Booking System
Tests identity management, security hardening, and audit logging
"""

import pytest
import time
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
from main import app, get_db_connection, cleanup_old_audit_logs

client = TestClient(app)

# Test data
test_employee = {
    "employee_id": "EMP001",
    "email": "john.doe@company.com",
    "password": "SecurePass123!",
    "full_name": "John Doe",
    "department": "Engineering",
    "role": "employee"
}

test_manager = {
    "employee_id": "MGR001",
    "email": "jane.manager@company.com",
    "password": "ManagerPass456#",
    "full_name": "Jane Manager",
    "department": "Management",
    "role": "manager"
}

test_admin = {
    "employee_id": "ADM001",
    "email": "admin@company.com",
    "password": "AdminPass789$",
    "full_name": "System Admin",
    "department": "IT",
    "role": "admin"
}

class TestEmployeeRegistration:
    """Test employee registration with password complexity"""
    
    def test_employee_registration_success(self):
        """Test successful employee registration"""
        response = client.post("/auth/register", json=test_employee)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Employee registered successfully"
        assert data["employee_id"] == test_employee["employee_id"]
        assert data["email"] == test_employee["email"]
        assert data["role"] == test_employee["role"]
    
    def test_password_complexity_requirements(self):
        """Test password complexity validation"""
        # Test password too short
        weak_employee = test_employee.copy()
        weak_employee["email"] = "weak1@company.com"
        weak_employee["employee_id"] = "WEAK001"
        weak_employee["password"] = "weak"  # Too short
        
        response = client.post("/auth/register", json=weak_employee)
        assert response.status_code == 422
        assert "at least 8 characters" in str(response.json())
        
        # Test password without number
        no_number = test_employee.copy()
        no_number["email"] = "weak2@company.com"
        no_number["employee_id"] = "WEAK002"
        no_number["password"] = "NoNumberPass!"  # No number
        
        response = client.post("/auth/register", json=no_number)
        assert response.status_code == 422
        assert "at least one number" in str(response.json())
        
        # Test password without special character
        no_special = test_employee.copy()
        no_special["email"] = "weak3@company.com"
        no_special["employee_id"] = "WEAK003"
        no_special["password"] = "NoSpecial123"  # No special char
        
        response = client.post("/auth/register", json=no_special)
        assert response.status_code == 422
        assert "special character" in str(response.json())
    
    def test_duplicate_employee_registration(self):
        """Test duplicate employee registration"""
        # Register first time
        client.post("/auth/register", json=test_employee)
        
        # Try to register again
        duplicate = test_employee.copy()
        response = client.post("/auth/register", json=duplicate)
        
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
    
    def test_invalid_role_registration(self):
        """Test registration with invalid role"""
        invalid_role = test_employee.copy()
        invalid_role["email"] = "invalid@company.com"
        invalid_role["employee_id"] = "INV001"
        invalid_role["role"] = "invalid_role"
        
        response = client.post("/auth/register", json=invalid_role)
        assert response.status_code == 422

class TestAuthentication:
    """Test authentication and security features"""
    
    def test_successful_login(self):
        """Test successful employee login"""
        # Register employee first
        client.post("/auth/register", json=test_employee)
        
        # Login
        login_data = {"email": test_employee["email"], "password": test_employee["password"]}
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 30 * 60  # 30 minutes in seconds
    
    def test_invalid_login_credentials(self):
        """Test login with invalid credentials"""
        # Register employee first
        client.post("/auth/register", json=test_employee)
        
        # Try login with wrong password
        login_data = {"email": test_employee["email"], "password": "wrongpassword"}
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]
    
    def test_account_lockout_after_failed_attempts(self):
        """Test account lockout after 3 failed attempts"""
        # Register employee
        lockout_employee = {
            "employee_id": "LOCK001",
            "email": "lockout@company.com",
            "password": "LockoutTest123!",
            "full_name": "Lockout Test",
            "department": "Testing",
            "role": "employee"
        }
        client.post("/auth/register", json=lockout_employee)
        
        # Make 3 failed login attempts
        login_data = {"email": lockout_employee["email"], "password": "wrongpassword"}
        
        for i in range(3):
            response = client.post("/auth/login", json=login_data)
            assert response.status_code == 401
        
        # 4th attempt should result in account lockout
        response = client.post("/auth/login", json=login_data)
        assert response.status_code == 423  # Locked
        assert "Account locked" in response.json()["detail"]
        
        # Even correct password should be rejected when locked
        correct_login = {"email": lockout_employee["email"], "password": lockout_employee["password"]}
        response = client.post("/auth/login", json=correct_login)
        assert response.status_code == 423

class TestSessionManagement:
    """Test session timeout and management"""
    
    def get_auth_headers(self, employee_data):
        """Helper to get authentication headers"""
        client.post("/auth/register", json=employee_data)
        login_response = client.post("/auth/login", json={
            "email": employee_data["email"],
            "password": employee_data["password"]
        })
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_session_activity_update(self):
        """Test that session activity is updated on API calls"""
        session_employee = {
            "employee_id": "SESS001",
            "email": "session@company.com",
            "password": "SessionTest123!",
            "full_name": "Session Test",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(session_employee)
        
        # Make API call to update session
        response = client.get("/profile", headers=headers)
        assert response.status_code == 200
        
        # Session should be active
        from main import active_sessions
        assert session_employee["email"] in active_sessions
    
    def test_logout_functionality(self):
        """Test logout removes session"""
        logout_employee = {
            "employee_id": "LOGOUT001",
            "email": "logout@company.com",
            "password": "LogoutTest123!",
            "full_name": "Logout Test",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(logout_employee)
        
        # Logout
        response = client.post("/auth/logout", headers=headers)
        assert response.status_code == 200
        assert "Logged out successfully" in response.json()["message"]

class TestMeetingRoomBooking:
    """Test meeting room booking functionality"""
    
    def get_auth_headers(self, employee_data):
        """Helper to get authentication headers"""
        client.post("/auth/register", json=employee_data)
        login_response = client.post("/auth/login", json={
            "email": employee_data["email"],
            "password": employee_data["password"]
        })
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_get_available_rooms(self):
        """Test getting available meeting rooms"""
        booking_employee = {
            "employee_id": "BOOK001",
            "email": "booking@company.com",
            "password": "BookingTest123!",
            "full_name": "Booking Test",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(booking_employee)
        
        response = client.get("/rooms", headers=headers)
        assert response.status_code == 200
        
        rooms = response.json()
        assert len(rooms) >= 5  # We have 5 sample rooms
        
        # Check room structure
        room = rooms[0]
        assert "id" in room
        assert "name" in room
        assert "capacity" in room
        assert "location" in room
    
    def test_create_booking_success(self):
        """Test successful room booking"""
        booking_employee = {
            "employee_id": "BOOK002",
            "email": "booking2@company.com",
            "password": "BookingTest123!",
            "full_name": "Booking Test 2",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(booking_employee)
        
        # Create booking for tomorrow
        tomorrow = datetime.now() + timedelta(days=1)
        start_time = tomorrow.replace(hour=10, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            "room_id": 1,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "purpose": "Team Meeting"
        }
        
        response = client.post("/bookings", json=booking_data, headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "Booking created successfully" in data["message"]
        assert "booking_id" in data
        assert "room_name" in data
    
    def test_booking_conflict_prevention(self):
        """Test that conflicting bookings are prevented"""
        conflict_employee1 = {
            "employee_id": "CONF001",
            "email": "conflict1@company.com",
            "password": "ConflictTest123!",
            "full_name": "Conflict Test 1",
            "department": "Testing",
            "role": "employee"
        }
        
        conflict_employee2 = {
            "employee_id": "CONF002",
            "email": "conflict2@company.com",
            "password": "ConflictTest123!",
            "full_name": "Conflict Test 2",
            "department": "Testing",
            "role": "employee"
        }
        
        headers1 = self.get_auth_headers(conflict_employee1)
        headers2 = self.get_auth_headers(conflict_employee2)
        
        # Create first booking
        tomorrow = datetime.now() + timedelta(days=1)
        start_time = tomorrow.replace(hour=14, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            "room_id": 1,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "purpose": "First Meeting"
        }
        
        response1 = client.post("/bookings", json=booking_data, headers=headers1)
        assert response1.status_code == 200
        
        # Try to create conflicting booking
        conflicting_booking = {
            "room_id": 1,  # Same room
            "start_time": (start_time + timedelta(minutes=30)).isoformat(),  # Overlapping time
            "end_time": (end_time + timedelta(minutes=30)).isoformat(),
            "purpose": "Conflicting Meeting"
        }
        
        response2 = client.post("/bookings", json=conflicting_booking, headers=headers2)
        assert response2.status_code == 409  # Conflict
        assert "already booked" in response2.json()["detail"]
    
    def test_get_my_bookings(self):
        """Test getting employee's own bookings"""
        my_bookings_employee = {
            "employee_id": "MYBOOK001",
            "email": "mybookings@company.com",
            "password": "MyBookings123!",
            "full_name": "My Bookings Test",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(my_bookings_employee)
        
        # Create a booking first
        tomorrow = datetime.now() + timedelta(days=1)
        start_time = tomorrow.replace(hour=16, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            "room_id": 2,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "purpose": "My Test Meeting"
        }
        
        client.post("/bookings", json=booking_data, headers=headers)
        
        # Get my bookings
        response = client.get("/bookings/my", headers=headers)
        assert response.status_code == 200
        
        bookings = response.json()
        assert len(bookings) >= 1
        
        booking = bookings[0]
        assert "id" in booking
        assert "room_name" in booking
        assert "purpose" in booking
        assert booking["purpose"] == "My Test Meeting"

class TestRoleBasedAccess:
    """Test role-based access control"""
    
    def get_auth_headers(self, employee_data):
        """Helper to get authentication headers"""
        client.post("/auth/register", json=employee_data)
        login_response = client.post("/auth/login", json={
            "email": employee_data["email"],
            "password": employee_data["password"]
        })
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_admin_access_to_employees(self):
        """Test admin can access employee list"""
        admin_headers = self.get_auth_headers(test_admin)
        
        response = client.get("/admin/employees", headers=admin_headers)
        assert response.status_code == 200
        
        employees = response.json()
        assert isinstance(employees, list)
        assert len(employees) >= 1
    
    def test_employee_cannot_access_admin_endpoints(self):
        """Test employee cannot access admin endpoints"""
        employee_headers = self.get_auth_headers(test_employee)
        
        response = client.get("/admin/employees", headers=employee_headers)
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]
    
    def test_manager_access_to_audit_logs(self):
        """Test manager can access audit logs"""
        manager_headers = self.get_auth_headers(test_manager)
        
        response = client.get("/admin/audit-logs", headers=manager_headers)
        assert response.status_code == 200
        
        logs = response.json()
        assert isinstance(logs, list)
    
    def test_employee_cannot_access_audit_logs(self):
        """Test employee cannot access audit logs"""
        employee_headers = self.get_auth_headers(test_employee)
        
        response = client.get("/admin/audit-logs", headers=employee_headers)
        assert response.status_code == 403

class TestAuditLogging:
    """Test audit logging functionality"""
    
    def test_login_audit_logging(self):
        """Test that login attempts are logged"""
        audit_employee = {
            "employee_id": "AUDIT001",
            "email": "audit@company.com",
            "password": "AuditTest123!",
            "full_name": "Audit Test",
            "department": "Testing",
            "role": "manager"  # Manager to access audit logs
        }
        
        # Register employee
        client.post("/auth/register", json=audit_employee)
        
        # Login to generate audit log
        login_data = {"email": audit_employee["email"], "password": audit_employee["password"]}
        client.post("/auth/login", json=login_data)
        
        # Get auth headers to check audit logs
        login_response = client.post("/auth/login", json=login_data)
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Check audit logs
        response = client.get("/admin/audit-logs?event_type=LOGIN_SUCCESS", headers=headers)
        assert response.status_code == 200
        
        logs = response.json()
        assert len(logs) >= 1
        
        # Find our login log
        login_log = None
        for log in logs:
            if log["employee_email"] == audit_employee["email"]:
                login_log = log
                break
        
        assert login_log is not None
        assert login_log["event_type"] == "LOGIN_SUCCESS"
        assert login_log["success"] == True
    
    def test_booking_audit_logging(self):
        """Test that booking activities are logged"""
        booking_audit_employee = {
            "employee_id": "BOOKAUDIT001",
            "email": "bookaudit@company.com",
            "password": "BookAudit123!",
            "full_name": "Book Audit Test",
            "department": "Testing",
            "role": "manager"
        }
        
        headers = self.get_auth_headers(booking_audit_employee)
        
        # Create a booking
        tomorrow = datetime.now() + timedelta(days=1)
        start_time = tomorrow.replace(hour=11, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            "room_id": 3,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "purpose": "Audit Test Meeting"
        }
        
        client.post("/bookings", json=booking_data, headers=headers)
        
        # Check audit logs for booking creation
        response = client.get("/admin/audit-logs?event_type=BOOKING_CREATED", headers=headers)
        assert response.status_code == 200
        
        logs = response.json()
        booking_log = None
        for log in logs:
            if log["employee_email"] == booking_audit_employee["email"]:
                booking_log = log
                break
        
        assert booking_log is not None
        assert booking_log["event_type"] == "BOOKING_CREATED"
        assert "Audit Test Meeting" in booking_log["details"]
    
    def get_auth_headers(self, employee_data):
        """Helper to get authentication headers"""
        client.post("/auth/register", json=employee_data)
        login_response = client.post("/auth/login", json={
            "email": employee_data["email"],
            "password": employee_data["password"]
        })
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

class TestProfileManagement:
    """Test profile management and audit logging"""
    
    def get_auth_headers(self, employee_data):
        """Helper to get authentication headers"""
        client.post("/auth/register", json=employee_data)
        login_response = client.post("/auth/login", json={
            "email": employee_data["email"],
            "password": employee_data["password"]
        })
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_get_profile(self):
        """Test getting employee profile"""
        profile_employee = {
            "employee_id": "PROF001",
            "email": "profile@company.com",
            "password": "ProfileTest123!",
            "full_name": "Profile Test",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(profile_employee)
        
        response = client.get("/profile", headers=headers)
        assert response.status_code == 200
        
        profile = response.json()
        assert profile["email"] == profile_employee["email"]
        assert profile["full_name"] == profile_employee["full_name"]
        assert profile["department"] == profile_employee["department"]
        assert profile["role"] == profile_employee["role"]
    
    def test_update_profile_with_audit(self):
        """Test profile update creates audit log"""
        update_employee = {
            "employee_id": "UPDATE001",
            "email": "update@company.com",
            "password": "UpdateTest123!",
            "full_name": "Update Test",
            "department": "Testing",
            "role": "manager"  # Manager to check audit logs
        }
        
        headers = self.get_auth_headers(update_employee)
        
        # Update profile
        update_data = {
            "full_name": "Updated Name",
            "department": "Updated Department"
        }
        
        response = client.put("/profile/update", params=update_data, headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "Profile updated successfully" in data["message"]
        assert len(data["changes"]) == 2  # Two fields updated

class TestSecurityFeatures:
    """Test security hardening features"""
    
    def test_protected_endpoints_require_auth(self):
        """Test that protected endpoints require authentication"""
        # Try accessing protected endpoints without token
        protected_endpoints = [
            "/profile",
            "/rooms",
            "/bookings/my",
            "/admin/employees"
        ]
        
        for endpoint in protected_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 403  # Forbidden
    
    def test_invalid_token_rejection(self):
        """Test that invalid tokens are rejected"""
        headers = {"Authorization": "Bearer invalid_token"}
        
        response = client.get("/profile", headers=headers)
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]
    
    def test_room_booking_validation(self):
        """Test room booking time validation"""
        validation_employee = {
            "employee_id": "VALID001",
            "email": "validation@company.com",
            "password": "ValidationTest123!",
            "full_name": "Validation Test",
            "department": "Testing",
            "role": "employee"
        }
        
        headers = self.get_auth_headers(validation_employee)
        
        # Try booking with end time before start time
        tomorrow = datetime.now() + timedelta(days=1)
        start_time = tomorrow.replace(hour=15, minute=0, second=0, microsecond=0)
        end_time = start_time - timedelta(hours=1)  # End before start
        
        invalid_booking = {
            "room_id": 1,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "purpose": "Invalid Meeting"
        }
        
        response = client.post("/bookings", json=invalid_booking, headers=headers)
        assert response.status_code == 422  # Validation error
    
    def get_auth_headers(self, employee_data):
        """Helper to get authentication headers"""
        client.post("/auth/register", json=employee_data)
        login_response = client.post("/auth/login", json={
            "email": employee_data["email"],
            "password": employee_data["password"]
        })
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

class TestSystemHealth:
    """Test system health and status"""
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "database" in data
        assert "active_sessions" in data
    
    def test_root_endpoint(self):
        """Test root endpoint information"""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "features" in data
        assert "endpoints" in data
        
        # Check that all expected features are listed
        features = data["features"]
        assert "Local Identity Management" in features
        assert any("Security Hardening" in feature for feature in features)
        assert any("Audit Logging" in feature for feature in features)

# Simple test runner
if __name__ == "__main__":
    pytest.main([__file__, "-v"])