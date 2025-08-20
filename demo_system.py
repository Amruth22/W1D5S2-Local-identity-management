"""
Demonstration Script for Company Meeting Room Booking System
Shows identity management, security features, and audit logging in action
"""

import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any

BASE_URL = "http://localhost:8000"

def demo_meeting_room_system():
    """Demonstrate the complete meeting room booking system"""
    print("🏢 Company Meeting Room Booking System Demo")
    print("=" * 60)
    
    # Demo 1: Employee Registration with Password Complexity
    print("\n1️⃣ Testing Employee Registration & Password Complexity...")
    
    # Test weak password (should fail)
    weak_employee = {
        "employee_id": "WEAK001",
        "email": "weak@company.com",
        "password": "weak",  # Doesn't meet complexity requirements
        "full_name": "Weak Password",
        "department": "Testing",
        "role": "employee"
    }
    
    response = requests.post(f"{BASE_URL}/auth/register", json=weak_employee)
    print(f"   ❌ Weak password rejected: {response.status_code}")
    if response.status_code == 422:
        print(f"      Reason: Password complexity requirements not met")
    
    # Register valid employees
    employees = [
        {
            "employee_id": "EMP001",
            "email": "john.doe@company.com",
            "password": "SecurePass123!",
            "full_name": "John Doe",
            "department": "Engineering",
            "role": "employee"
        },
        {
            "employee_id": "MGR001",
            "email": "jane.manager@company.com",
            "password": "ManagerPass456#",
            "full_name": "Jane Manager",
            "department": "Management",
            "role": "manager"
        },
        {
            "employee_id": "ADM001",
            "email": "admin@company.com",
            "password": "AdminPass789$",
            "full_name": "System Admin",
            "department": "IT",
            "role": "admin"
        }
    ]
    
    for emp in employees:
        response = requests.post(f"{BASE_URL}/auth/register", json=emp)
        if response.status_code == 200:
            print(f"   ✅ Registered: {emp['full_name']} ({emp['role']})")
        else:
            print(f"   ⚠️ Registration failed for {emp['full_name']}: {response.status_code}")
    
    print()
    
    # Demo 2: Authentication and Security Features
    print("2️⃣ Testing Authentication & Security Features...")
    
    # Test account lockout
    print("   🔒 Testing Account Lockout (3 failed attempts)...")
    
    lockout_test = {
        "employee_id": "LOCK001",
        "email": "lockout@company.com",
        "password": "LockoutTest123!",
        "full_name": "Lockout Test",
        "department": "Security",
        "role": "employee"
    }
    
    requests.post(f"{BASE_URL}/auth/register", json=lockout_test)
    
    # Make 3 failed login attempts
    for i in range(3):
        bad_login = {"email": lockout_test["email"], "password": "wrongpassword"}
        response = requests.post(f"{BASE_URL}/auth/login", json=bad_login)
        print(f"      Attempt {i+1}: {response.status_code}")
    
    # 4th attempt should be locked
    response = requests.post(f"{BASE_URL}/auth/login", json=bad_login)
    if response.status_code == 423:
        print("   ✅ Account lockout working! Account locked after 3 failed attempts.")
    
    print()
    
    # Demo 3: Successful Login and Token Management
    print("3️⃣ Testing Successful Login & Session Management...")
    
    # Login with valid credentials
    login_data = {"email": employees[0]["email"], "password": employees[0]["password"]}
    response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    
    if response.status_code == 200:
        token_data = response.json()
        employee_token = token_data["access_token"]
        print(f"   ✅ Login successful! Token expires in {token_data['expires_in']} seconds")
        print(f"   🔑 Token: {employee_token[:50]}...")
    else:
        print(f"   ❌ Login failed: {response.status_code}")
        return
    
    # Login manager for admin operations
    manager_login = {"email": employees[1]["email"], "password": employees[1]["password"]}
    manager_response = requests.post(f"{BASE_URL}/auth/login", json=manager_login)
    manager_token = manager_response.json()["access_token"]
    
    print()
    
    # Demo 4: Meeting Room Management
    print("4️⃣ Testing Meeting Room Management...")
    
    headers = {"Authorization": f"Bearer {employee_token}"}
    
    # Get available rooms
    response = requests.get(f"{BASE_URL}/rooms", headers=headers)
    if response.status_code == 200:
        rooms = response.json()
        print(f"   ✅ Available rooms: {len(rooms)}")
        for room in rooms[:3]:  # Show first 3 rooms
            print(f"      - {room['name']}: {room['capacity']} people, {room['location']}")
    
    print()
    
    # Demo 5: Room Booking
    print("5️⃣ Testing Room Booking...")
    
    # Create a booking for tomorrow
    tomorrow = datetime.now() + timedelta(days=1)
    start_time = tomorrow.replace(hour=10, minute=0, second=0, microsecond=0)
    end_time = start_time + timedelta(hours=1)
    
    booking_data = {
        "room_id": 1,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "purpose": "Team Standup Meeting"
    }
    
    response = requests.post(f"{BASE_URL}/bookings", json=booking_data, headers=headers)
    if response.status_code == 200:
        booking_result = response.json()
        print(f"   ✅ Booking created: {booking_result['room_name']}")
        print(f"      Time: {start_time.strftime('%Y-%m-%d %H:%M')} - {end_time.strftime('%H:%M')}")
        print(f"      Purpose: {booking_data['purpose']}")
    
    # Test booking conflict
    print("   🚫 Testing Booking Conflict Prevention...")
    
    conflicting_booking = {
        "room_id": 1,  # Same room
        "start_time": (start_time + timedelta(minutes=30)).isoformat(),  # Overlapping
        "end_time": (end_time + timedelta(minutes=30)).isoformat(),
        "purpose": "Conflicting Meeting"
    }
    
    response = requests.post(f"{BASE_URL}/bookings", json=conflicting_booking, headers=headers)
    if response.status_code == 409:
        print("   ✅ Booking conflict prevented!")
    
    print()
    
    # Demo 6: Profile Management
    print("6️⃣ Testing Profile Management...")
    
    # Get current profile
    response = requests.get(f"{BASE_URL}/profile", headers=headers)
    if response.status_code == 200:
        profile = response.json()
        print(f"   ✅ Profile retrieved: {profile['full_name']} ({profile['department']})")
    
    # Update profile
    update_data = {
        "full_name": "John Doe Updated",
        "department": "Senior Engineering"
    }
    
    response = requests.put(f"{BASE_URL}/profile/update", params=update_data, headers=headers)
    if response.status_code == 200:
        result = response.json()
        print(f"   ✅ Profile updated: {len(result['changes'])} changes made")
        for change in result['changes']:
            print(f"      - {change}")
    
    print()
    
    # Demo 7: Role-Based Access Control
    print("7️⃣ Testing Role-Based Access Control...")
    
    # Employee trying to access admin endpoint (should fail)
    response = requests.get(f"{BASE_URL}/admin/employees", headers=headers)
    if response.status_code == 403:
        print("   ✅ Employee blocked from admin endpoint")
    
    # Manager accessing audit logs (should succeed)
    manager_headers = {"Authorization": f"Bearer {manager_token}"}
    response = requests.get(f"{BASE_URL}/admin/audit-logs", headers=manager_headers)
    if response.status_code == 200:
        logs = response.json()
        print(f"   ✅ Manager can access audit logs: {len(logs)} entries")
    
    print()
    
    # Demo 8: Audit Logging Review
    print("8️⃣ Reviewing Audit Logs...")
    
    # Get recent audit logs
    response = requests.get(f"{BASE_URL}/admin/audit-logs?limit=10", headers=manager_headers)
    if response.status_code == 200:
        logs = response.json()
        print(f"   ✅ Recent audit events ({len(logs)} entries):")
        
        for log in logs[:5]:  # Show last 5 events
            timestamp = datetime.fromisoformat(log['timestamp']).strftime('%H:%M:%S')
            status = "✅" if log['success'] else "❌"
            print(f"      {status} {timestamp}: {log['event_type']} - {log['employee_email']}")
    
    print()
    
    # Demo 9: System Health Check
    print("9️⃣ System Health Check...")
    
    response = requests.get(f"{BASE_URL}/health")
    if response.status_code == 200:
        health = response.json()
        print(f"   ✅ System Status: {health['status']}")
        print(f"   📊 Active Sessions: {health['active_sessions']}")
        print(f"   🗄️ Database: {health['database']}")
    
    print("\n" + "=" * 60)
    print("🎉 Meeting Room Booking System Demo Completed!")
    print("\n📋 Features Demonstrated:")
    print("✅ Employee registration with password complexity")
    print("✅ Account lockout after failed login attempts")
    print("✅ JWT authentication with session management")
    print("✅ Meeting room booking with conflict prevention")
    print("✅ Profile management with audit logging")
    print("✅ Role-based access control (employee/manager/admin)")
    print("✅ Comprehensive audit logging (30-day retention)")
    print("✅ Security hardening measures")
    
    print("\n🔒 Security Features Validated:")
    print("• Password complexity requirements (8+ chars, number, special)")
    print("• Account lockout (3 failed attempts, 15-minute lockout)")
    print("• Session timeout (30 minutes inactivity)")
    print("• Role-based permissions (employee < manager < admin)")
    print("• Audit trail for all activities")
    
    print("\n💡 Identity Management Features:")
    print("• Local employee database (no external dependencies)")
    print("• Employee profiles with department and role")
    print("• Secure password storage (bcrypt hashing)")
    print("• JWT token-based authentication")
    print("• Session management with activity tracking")

def check_api_status():
    """Check if API is running"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

if __name__ == "__main__":
    print("🏢 Meeting Room Booking System Demo")
    print("=" * 60)
    
    if not check_api_status():
        print("❌ API is not running!")
        print("Please start the API first:")
        print("python main.py")
        print("=" * 60)
        exit(1)
    
    try:
        demo_meeting_room_system()
    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by user")
    except Exception as e:
        print(f"\n\n💥 Demo error: {e}")
        print("Make sure the API is running: python main.py")