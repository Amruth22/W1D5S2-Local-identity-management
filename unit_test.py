"""
Test Cases for Company Meeting Room Booking System
Tests identity management, security hardening, and audit logging via live server
"""

import pytest
import time
import requests
import json
from datetime import datetime, timedelta

# Configuration for live server testing
BASE_URL = "http://localhost:8000"
TIMEOUT = 30  # seconds

def check_server_running():
    """Check if the server is running"""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        return response.status_code == 200
    except:
        return False

def get_unique_employee_id(prefix="EMP"):
    """Generate unique employee ID for testing"""
    timestamp = int(time.time() * 1000)  # milliseconds for uniqueness
    return f"{prefix}{timestamp}"

def get_unique_email(prefix="test"):
    """Generate unique email for testing"""
    timestamp = int(time.time() * 1000)
    return f"{prefix}_{timestamp}@company.com"

# Test result tracking
test_results = {"passed": 0, "failed": 0, "total": 0}

def run_test(test_func, test_name):
    """Run a single test and track results"""
    global test_results
    test_results["total"] += 1
    
    try:
        test_func()
        test_results["passed"] += 1
        print(f"  ✅ {test_name} - PASSED")
        return True
    except Exception as e:
        test_results["failed"] += 1
        print(f"  ❌ {test_name} - FAILED: {str(e)}")
        return False

def create_test_employee(role="employee", prefix="test"):
    """Create test employee data with unique identifiers"""
    return {
        "employee_id": get_unique_employee_id(prefix.upper()),
        "email": get_unique_email(prefix),
        "password": "SecurePass123!",
        "full_name": f"{prefix.title()} User",
        "department": "Testing",
        "role": role
    }

def get_auth_headers(employee_data):
    """Helper to register employee and get auth headers"""
    # Register employee
    requests.post(f"{BASE_URL}/auth/register", json=employee_data, timeout=TIMEOUT)
    
    # Login to get token
    login_response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": employee_data["email"],
        "password": employee_data["password"]
    }, timeout=TIMEOUT)
    
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

class TestEmployeeRegistration:
    """Test employee registration with password complexity via live API"""
    
    def test_employee_registration_success(self):
        """Test successful employee registration"""
        test_employee = create_test_employee("employee", "register")
        
        response = requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Employee registered successfully"
        assert data["employee_id"] == test_employee["employee_id"]
        assert data["email"] == test_employee["email"]
        assert data["role"] == test_employee["role"]
    
    def test_password_complexity_requirements(self):
        """Test password complexity validation"""
        # Test password too short
        weak_employee = create_test_employee("employee", "weak1")
        weak_employee["password"] = "weak"  # Too short
        
        response = requests.post(f"{BASE_URL}/auth/register", json=weak_employee, timeout=TIMEOUT)
        assert response.status_code == 422
        assert "at least 8 characters" in str(response.json())
        
        # Test password without number
        no_number = create_test_employee("employee", "weak2")
        no_number["password"] = "NoNumberPass!"  # No number
        
        response = requests.post(f"{BASE_URL}/auth/register", json=no_number, timeout=TIMEOUT)
        assert response.status_code == 422
        assert "at least one number" in str(response.json())
        
        # Test password without special character
        no_special = create_test_employee("employee", "weak3")
        no_special["password"] = "NoSpecial123"  # No special char
        
        response = requests.post(f"{BASE_URL}/auth/register", json=no_special, timeout=TIMEOUT)
        assert response.status_code == 422
        assert "special character" in str(response.json())
    
    def test_duplicate_employee_registration(self):
        """Test duplicate employee registration"""
        test_employee = create_test_employee("employee", "duplicate")
        
        # Register first time
        requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        # Try to register again
        response = requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
    
    def test_invalid_role_registration(self):
        """Test registration with invalid role"""
        invalid_role = create_test_employee("employee", "invalid")
        invalid_role["role"] = "invalid_role"
        
        response = requests.post(f"{BASE_URL}/auth/register", json=invalid_role, timeout=TIMEOUT)
        assert response.status_code == 422

class TestEmployeeRegistration:
    """Test employee registration with password complexity via live API"""
    
    def test_employee_registration_success(self):
        """Test successful employee registration"""
        test_employee = create_test_employee("employee", "register")
        
        response = requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Employee registered successfully"
        assert data["employee_id"] == test_employee["employee_id"]
        assert data["email"] == test_employee["email"]
        assert data["role"] == test_employee["role"]
    
    def test_password_complexity_requirements(self):
        """Test password complexity validation"""
        # Test password too short
        weak_employee = create_test_employee("employee", "weak1")
        weak_employee["password"] = "weak"  # Too short
        
        response = requests.post(f"{BASE_URL}/auth/register", json=weak_employee, timeout=TIMEOUT)
        assert response.status_code == 422
        assert "at least 8 characters" in str(response.json())
        
        # Test password without number
        no_number = create_test_employee("employee", "weak2")
        no_number["password"] = "NoNumberPass!"  # No number
        
        response = requests.post(f"{BASE_URL}/auth/register", json=no_number, timeout=TIMEOUT)
        assert response.status_code == 422
        assert "at least one number" in str(response.json())
        
        # Test password without special character
        no_special = create_test_employee("employee", "weak3")
        no_special["password"] = "NoSpecial123"  # No special char
        
        response = requests.post(f"{BASE_URL}/auth/register", json=no_special, timeout=TIMEOUT)
        assert response.status_code == 422
        assert "special character" in str(response.json())
    
    def test_duplicate_employee_registration(self):
        """Test duplicate employee registration"""
        test_employee = create_test_employee("employee", "duplicate")
        
        # Register first time
        requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        # Try to register again
        response = requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

class TestAuthentication:
    """Test authentication and security features via live API"""
    
    def test_successful_login(self):
        """Test successful employee login"""
        test_employee = create_test_employee("employee", "login")
        
        # Register employee first
        requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        # Login
        login_data = {"email": test_employee["email"], "password": test_employee["password"]}
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data, timeout=TIMEOUT)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 30 * 60  # 30 minutes in seconds
    
    def test_invalid_login_credentials(self):
        """Test login with invalid credentials"""
        test_employee = create_test_employee("employee", "invalid")
        
        # Register employee first
        requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        # Try login with wrong password
        login_data = {"email": test_employee["email"], "password": "wrongpassword"}
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data, timeout=TIMEOUT)
        
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]
    
    def test_account_lockout_after_failed_attempts(self):
        """Test account lockout after 3 failed attempts"""
        lockout_employee = create_test_employee("employee", "lockout")
        
        # Register employee
        requests.post(f"{BASE_URL}/auth/register", json=lockout_employee, timeout=TIMEOUT)
        
        # Make 3 failed login attempts
        login_data = {"email": lockout_employee["email"], "password": "wrongpassword"}
        
        for i in range(3):
            response = requests.post(f"{BASE_URL}/auth/login", json=login_data, timeout=TIMEOUT)
            assert response.status_code == 401
        
        # 4th attempt should result in account lockout
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data, timeout=TIMEOUT)
        assert response.status_code == 423  # Locked
        assert "Account locked" in response.json()["detail"]
        
        # Even correct password should be rejected when locked
        correct_login = {"email": lockout_employee["email"], "password": lockout_employee["password"]}
        response = requests.post(f"{BASE_URL}/auth/login", json=correct_login, timeout=TIMEOUT)
        assert response.status_code == 423

class TestAuthentication:
    """Test authentication and security features via live API"""
    
    def test_successful_login(self):
        """Test successful employee login"""
        test_employee = create_test_employee("employee", "login")
        
        # Register employee first
        requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        # Login
        login_data = {"email": test_employee["email"], "password": test_employee["password"]}
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data, timeout=TIMEOUT)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 30 * 60  # 30 minutes in seconds
    
    def test_invalid_login_credentials(self):
        """Test login with invalid credentials"""
        test_employee = create_test_employee("employee", "invalid")
        
        # Register employee first
        requests.post(f"{BASE_URL}/auth/register", json=test_employee, timeout=TIMEOUT)
        
        # Try login with wrong password
        login_data = {"email": test_employee["email"], "password": "wrongpassword"}
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data, timeout=TIMEOUT)
        
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]
    
    def test_session_activity_and_profile_access(self):
        """Test session activity through profile access"""
        session_employee = create_test_employee("employee", "session")
        headers = get_auth_headers(session_employee)
        
        # Make API call to test session
        response = requests.get(f"{BASE_URL}/profile", headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200
        
        profile_data = response.json()
        assert profile_data["email"] == session_employee["email"]
        assert profile_data["role"] == session_employee["role"]
    
    def test_logout_functionality(self):
        """Test logout removes session"""
        logout_employee = create_test_employee("employee", "logout")
        headers = get_auth_headers(logout_employee)
        
        # Logout
        response = requests.post(f"{BASE_URL}/auth/logout", headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200
        assert "Logged out successfully" in response.json()["message"]
    
    def test_protected_endpoints_require_auth(self):
        """Test that protected endpoints require authentication"""
        # Try accessing protected endpoints without token
        protected_endpoints = [
            "/profile",
            "/rooms",
            "/bookings/my"
        ]
        
        for endpoint in protected_endpoints:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=TIMEOUT)
            assert response.status_code == 403  # Forbidden
    
    def test_invalid_token_rejection(self):
        """Test that invalid tokens are rejected"""
        headers = {"Authorization": "Bearer invalid_token"}
        
        response = requests.get(f"{BASE_URL}/profile", headers=headers, timeout=TIMEOUT)
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]

class TestMeetingRoomBooking:
    """Test meeting room booking functionality via live API"""
    
    def test_get_available_rooms(self):
        """Test getting available meeting rooms"""
        booking_employee = create_test_employee("employee", "rooms")
        headers = get_auth_headers(booking_employee)
        
        response = requests.get(f"{BASE_URL}/rooms", headers=headers, timeout=TIMEOUT)
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
        booking_employee = create_test_employee("employee", "booking")
        headers = get_auth_headers(booking_employee)
        
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
        
        response = requests.post(f"{BASE_URL}/bookings", json=booking_data, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200
        
        data = response.json()
        assert "Booking created successfully" in data["message"]
        assert "booking_id" in data
        assert "room_name" in data
    
    def test_get_my_bookings(self):
        """Test getting employee's own bookings"""
        my_bookings_employee = create_test_employee("employee", "mybookings")
        headers = get_auth_headers(my_bookings_employee)
        
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
        
        requests.post(f"{BASE_URL}/bookings", json=booking_data, headers=headers, timeout=TIMEOUT)
        
        # Get my bookings
        response = requests.get(f"{BASE_URL}/bookings/my", headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200
        
        bookings = response.json()
        assert len(bookings) >= 1
        
        booking = bookings[0]
        assert "id" in booking
        assert "room_name" in booking
        assert "purpose" in booking
        assert booking["purpose"] == "My Test Meeting"

class TestRoleBasedAccess:
    """Test role-based access control via live API"""
    
    def test_admin_access_to_employees(self):
        """Test admin can access employee list"""
        admin_employee = create_test_employee("admin", "admin")
        admin_headers = get_auth_headers(admin_employee)
        
        response = requests.get(f"{BASE_URL}/admin/employees", headers=admin_headers, timeout=TIMEOUT)
        assert response.status_code == 200
        
        employees = response.json()
        assert isinstance(employees, list)
        assert len(employees) >= 1
    
    def test_employee_cannot_access_admin_endpoints(self):
        """Test employee cannot access admin endpoints"""
        employee = create_test_employee("employee", "noadmin")
        employee_headers = get_auth_headers(employee)
        
        response = requests.get(f"{BASE_URL}/admin/employees", headers=employee_headers, timeout=TIMEOUT)
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]
    
    def test_manager_access_to_audit_logs(self):
        """Test manager can access audit logs"""
        manager_employee = create_test_employee("manager", "manager")
        manager_headers = get_auth_headers(manager_employee)
        
        response = requests.get(f"{BASE_URL}/admin/audit-logs", headers=manager_headers, timeout=TIMEOUT)
        assert response.status_code == 200
        
        logs = response.json()
        assert isinstance(logs, list)

class TestSystemHealth:
    """Test system health and status via live API"""
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = requests.get(f"{BASE_URL}/health", timeout=TIMEOUT)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "database" in data
        assert "active_sessions" in data
    
    def test_root_endpoint(self):
        """Test root endpoint information"""
        response = requests.get(f"{BASE_URL}/", timeout=TIMEOUT)
        
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

# Simple test runner for live API tests
def run_live_api_tests():
    """Run API tests against live server"""
    global test_results
    test_results = {"passed": 0, "failed": 0, "total": 0}
    
    print("🧪 Running Live API Tests (Meeting Room System)")
    print("=" * 60)
    
    # Check if server is running
    if not check_server_running():
        print("❌ ERROR: Server is not running!")
        print("")
        print("Please start the server first:")
        print("  1. Open a terminal and run: python main.py")
        print("  2. Wait for the server to start")
        print("  3. Then run these tests in another terminal")
        print("")
        return False
    
    print(f"✅ Server is running at {BASE_URL}")
    print("")
    
    # Core 10 Essential Tests
    print("🎯 Running Core 10 Essential Tests:")
    
    # System Health Tests
    test_health = TestSystemHealth()
    run_test(test_health.test_root_endpoint, "1. Root Endpoint Information")
    run_test(test_health.test_health_check, "2. Health Check Endpoint")
    
    # Employee Registration Tests
    test_reg = TestEmployeeRegistration()
    run_test(test_reg.test_employee_registration_success, "3. Employee Registration Success")
    run_test(test_reg.test_password_complexity_requirements, "4. Password Complexity Validation")
    run_test(test_reg.test_duplicate_employee_registration, "5. Duplicate Registration Prevention")
    
    # Authentication Tests
    test_auth = TestAuthentication()
    run_test(test_auth.test_successful_login, "6. Successful Login")
    run_test(test_auth.test_invalid_login_credentials, "7. Invalid Login Rejection")
    run_test(test_auth.test_session_activity_and_profile_access, "8. Session Management & Profile Access")
    
    # Meeting Room Tests
    test_booking = TestMeetingRoomBooking()
    run_test(test_booking.test_get_available_rooms, "9. Meeting Room Access")
    run_test(test_booking.test_create_booking_success, "10. Room Booking Functionality")
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"🎯 Total Tests: {test_results['total']}")
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    
    if test_results['failed'] == 0:
        print(f"\n🎉 ALL TESTS PASSED! ({test_results['passed']}/{test_results['total']})")
        success_rate = 100.0
    else:
        success_rate = (test_results['passed'] / test_results['total']) * 100
        print(f"\n⚠️  SOME TESTS FAILED ({test_results['passed']}/{test_results['total']})")
    
    print(f"📊 Success Rate: {success_rate:.1f}%")
    
    print("\n" + "=" * 60)
    print("📚 Core 10 Tests Covered:")
    print("• 1-2: System health and information endpoints")
    print("• 3-5: Employee registration and validation")
    print("• 6-8: Authentication, login security, and session management")
    print("• 9-10: Meeting room access and booking functionality")
    
    print("\n💡 Why These Tests Matter:")
    print("• Validate identity management security")
    print("• Test authentication and authorization")
    print("• Verify business logic functionality")
    print("• Ensure system security hardening")
    
    return test_results['failed'] == 0

# Simple test runner for live API tests
def run_live_api_tests():
    """Run API tests against live server"""
    global test_results
    test_results = {"passed": 0, "failed": 0, "total": 0}
    
    print("🧪 Running Live API Tests (Meeting Room System)")
    print("=" * 60)
    
    # Check if server is running
    if not check_server_running():
        print("❌ ERROR: Server is not running!")
        print("")
        print("Please start the server first:")
        print("  1. Open a terminal and run: python main.py")
        print("  2. Wait for the server to start")
        print("  3. Then run these tests in another terminal")
        print("")
        return False
    
    print(f"✅ Server is running at {BASE_URL}")
    print("")
    
    # Core 10 Essential Tests
    print("🎯 Running Core 10 Essential Tests:")
    
    # System Health Tests
    test_health = TestSystemHealth()
    run_test(test_health.test_root_endpoint, "1. Root Endpoint Information")
    run_test(test_health.test_health_check, "2. Health Check Endpoint")
    
    # Employee Registration Tests
    test_reg = TestEmployeeRegistration()
    run_test(test_reg.test_employee_registration_success, "3. Employee Registration Success")
    run_test(test_reg.test_password_complexity_requirements, "4. Password Complexity Validation")
    run_test(test_reg.test_duplicate_employee_registration, "5. Duplicate Registration Prevention")
    
    # Authentication Tests
    test_auth = TestAuthentication()
    run_test(test_auth.test_successful_login, "6. Successful Login")
    run_test(test_auth.test_invalid_login_credentials, "7. Invalid Login Rejection")
    run_test(test_auth.test_session_activity_and_profile_access, "8. Session Management & Profile Access")
    
    # Meeting Room Tests
    test_booking = TestMeetingRoomBooking()
    run_test(test_booking.test_get_available_rooms, "9. Meeting Room Access")
    run_test(test_booking.test_create_booking_success, "10. Room Booking Functionality")
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"🎯 Total Tests: {test_results['total']}")
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    
    if test_results['failed'] == 0:
        print(f"\n🎉 ALL TESTS PASSED! ({test_results['passed']}/{test_results['total']})")
        success_rate = 100.0
    else:
        success_rate = (test_results['passed'] / test_results['total']) * 100
        print(f"\n⚠️  SOME TESTS FAILED ({test_results['passed']}/{test_results['total']})")
    
    print(f"📊 Success Rate: {success_rate:.1f}%")
    
    print("\n" + "=" * 60)
    print("📚 Core 10 Tests Covered:")
    print("• 1-2: System health and information endpoints")
    print("• 3-5: Employee registration and validation")
    print("• 6-8: Authentication, login security, and session management")
    print("• 9-10: Meeting room access and booking functionality")
    
    print("\n💡 Why These Tests Matter:")
    print("• Validate identity management security")
    print("• Test authentication and authorization")
    print("• Verify business logic functionality")
    print("• Ensure system security hardening")
    
    return test_results['failed'] == 0

if __name__ == "__main__":
    # Run live API tests
    success = run_live_api_tests()
    
    print("\n" + "=" * 60)
    if success:
        print("🎆 ALL TESTS SUCCESSFUL!")
        print("🔄 You can also run with pytest: pytest unit_test.py -v")
    else:
        print("⚠️  SOME TESTS FAILED!")
        print("🔧 Check the error messages above for details")
        print("🔄 You can also run with pytest: pytest unit_test.py -v")
    print("=" * 60)
    
    exit(0 if success else 1)

# Simple test runner for live API tests
def run_live_api_tests():
    """Run API tests against live server"""
    global test_results
    test_results = {"passed": 0, "failed": 0, "total": 0}
    
    print("🧪 Running Live API Tests (Meeting Room System)")
    print("=" * 60)
    
    # Check if server is running
    if not check_server_running():
        print("❌ ERROR: Server is not running!")
        print("")
        print("Please start the server first:")
        print("  1. Open a terminal and run: python main.py")
        print("  2. Wait for the server to start")
        print("  3. Then run these tests in another terminal")
        print("")
        return False
    
    print(f"✅ Server is running at {BASE_URL}")
    print("")
    
    # Core 10 Essential Tests
    print("🎯 Running Core 10 Essential Tests:")
    
    # Employee Registration Tests
    test_reg = TestEmployeeRegistration()
    run_test(test_reg.test_employee_registration_success, "1. Employee Registration Success")
    run_test(test_reg.test_password_complexity_requirements, "2. Password Complexity Validation")
    run_test(test_reg.test_duplicate_employee_registration, "3. Duplicate Registration Prevention")
    
    # Authentication Tests
    test_auth = TestAuthentication()
    run_test(test_auth.test_successful_login, "4. Successful Login")
    run_test(test_auth.test_invalid_login_credentials, "5. Invalid Login Rejection")
    run_test(test_auth.test_account_lockout_after_failed_attempts, "6. Account Lockout Security")
    
    # Session and Security Tests
    run_test(test_auth.test_session_activity_and_profile_access, "7. Session Management")
    run_test(test_auth.test_protected_endpoints_require_auth, "8. Protected Endpoint Security")
    
    # Meeting Room Tests
    test_booking = TestMeetingRoomBooking()
    run_test(test_booking.test_get_available_rooms, "9. Meeting Room Access")
    run_test(test_booking.test_create_booking_success, "10. Room Booking Functionality")
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"🎯 Total Tests: {test_results['total']}")
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    
    if test_results['failed'] == 0:
        print(f"\n🎉 ALL TESTS PASSED! ({test_results['passed']}/{test_results['total']})")
        success_rate = 100.0
    else:
        success_rate = (test_results['passed'] / test_results['total']) * 100
        print(f"\n⚠️  SOME TESTS FAILED ({test_results['passed']}/{test_results['total']})")
    
    print(f"📊 Success Rate: {success_rate:.1f}%")
    
    print("\n" + "=" * 60)
    print("📚 Core 10 Tests Covered:")
    print("• 1-3: Employee registration and validation")
    print("• 4-6: Authentication and security (login, lockout)")
    print("• 7-8: Session management and endpoint protection")
    print("• 9-10: Meeting room access and booking")
    
    print("\n💡 Why These Tests Matter:")
    print("• Validate identity management security")
    print("• Test authentication and authorization")
    print("• Verify business logic functionality")
    print("• Ensure system security hardening")
    
    return test_results['failed'] == 0

# Simple test runner for live API tests
def run_live_api_tests():
    """Run API tests against live server"""
    global test_results
    test_results = {"passed": 0, "failed": 0, "total": 0}
    
    print("🧪 Running Live API Tests (Meeting Room System)")
    print("=" * 60)
    
    # Check if server is running
    if not check_server_running():
        print("❌ ERROR: Server is not running!")
        print("")
        print("Please start the server first:")
        print("  1. Open a terminal and run: python main.py")
        print("  2. Wait for the server to start")
        print("  3. Then run these tests in another terminal")
        print("")
        return False
    
    print(f"✅ Server is running at {BASE_URL}")
    print("")
    
    # Core 10 Essential Tests
    print("🎯 Running Core 10 Essential Tests:")
    
    # System Health Tests
    test_health = TestSystemHealth()
    run_test(test_health.test_root_endpoint, "1. Root Endpoint Information")
    run_test(test_health.test_health_check, "2. Health Check Endpoint")
    
    # Employee Registration Tests
    test_reg = TestEmployeeRegistration()
    run_test(test_reg.test_employee_registration_success, "3. Employee Registration Success")
    run_test(test_reg.test_password_complexity_requirements, "4. Password Complexity Validation")
    run_test(test_reg.test_duplicate_employee_registration, "5. Duplicate Registration Prevention")
    
    # Authentication Tests
    test_auth = TestAuthentication()
    run_test(test_auth.test_successful_login, "6. Successful Login")
    run_test(test_auth.test_invalid_login_credentials, "7. Invalid Login Rejection")
    run_test(test_auth.test_session_activity_and_profile_access, "8. Session Management & Profile Access")
    
    # Meeting Room Tests
    test_booking = TestMeetingRoomBooking()
    run_test(test_booking.test_get_available_rooms, "9. Meeting Room Access")
    run_test(test_booking.test_create_booking_success, "10. Room Booking Functionality")
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"🎯 Total Tests: {test_results['total']}")
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    
    if test_results['failed'] == 0:
        print(f"\n🎉 ALL TESTS PASSED! ({test_results['passed']}/{test_results['total']})")
        success_rate = 100.0
    else:
        success_rate = (test_results['passed'] / test_results['total']) * 100
        print(f"\n⚠️  SOME TESTS FAILED ({test_results['passed']}/{test_results['total']})")
    
    print(f"📊 Success Rate: {success_rate:.1f}%")
    
    print("\n" + "=" * 60)
    print("📚 Core 10 Tests Covered:")
    print("• 1-2: System health and information endpoints")
    print("• 3-5: Employee registration and validation")
    print("• 6-8: Authentication, login security, and session management")
    print("• 9-10: Meeting room access and booking functionality")
    
    print("\n💡 Why These Tests Matter:")
    print("• Validate identity management security")
    print("• Test authentication and authorization")
    print("• Verify business logic functionality")
    print("• Ensure system security hardening")
    
    return test_results['failed'] == 0

if __name__ == "__main__":
    # Run live API tests
    success = run_live_api_tests()
    
    print("\n" + "=" * 60)
    if success:
        print("🎆 ALL TESTS SUCCESSFUL!")
        print("🔄 You can also run with pytest: pytest unit_test.py -v")
    else:
        print("⚠️  SOME TESTS FAILED!")
        print("🔧 Check the error messages above for details")
        print("🔄 You can also run with pytest: pytest unit_test.py -v")
    print("=" * 60)
    
    exit(0 if success else 1)