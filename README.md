# Company Meeting Room Booking System

A comprehensive local identity management system with security hardening and audit logging for managing company meeting room bookings.

## 🏢 System Overview

This system demonstrates:
- **Local Identity Management** for company employees
- **Security Hardening** with password policies and account protection
- **Comprehensive Audit Logging** for compliance and monitoring
- **Meeting Room Booking** with conflict prevention
- **Role-Based Access Control** (Employee/Manager/Admin)

## ✨ Key Features

### 🔐 **Identity Management**
- **Employee Registration** with unique employee IDs
- **Local Authentication** (no external dependencies)
- **Role-Based Permissions** (employee, manager, admin)
- **Profile Management** with audit trails

### 🛡️ **Security Hardening**
- **Password Complexity**: 8+ characters, 1 number, 1 special character
- **Account Lockout**: Lock after 3 failed login attempts (15-minute lockout)
- **Session Timeout**: Auto-logout after 30 minutes of inactivity
- **JWT Authentication** with secure token management

### 📊 **Audit Logging**
- **Login Attempts**: All successful/failed logins with IP and timestamp
- **Room Bookings**: Track all booking activities (create, cancel)
- **Profile Changes**: Log any updates to employee profiles
- **30-Day Retention**: Automatic cleanup of old audit logs
- **Separate SQLite Table**: Dedicated audit log storage

### 🏢 **Meeting Room Management**
- **Room Booking System** with conflict prevention
- **Real-time Availability** checking
- **Booking History** and management
- **Room Details** with equipment and capacity info

## 🚀 Quick Start

### 1. Setup
```bash
git clone https://github.com/Amruth22/W1D5S2-Local-identity-management.git
cd W1D5S2-Local-identity-management
pip install -r requirements.txt
```

### 2. Run the System
```bash
python main.py
```

The API will be available at: `http://localhost:8000`

### 3. View Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 4. Run Tests
```bash
python unit_test.py
```

## 📊 API Endpoints

### **Authentication**
```http
POST /auth/register    # Register new employee
POST /auth/login       # Login and get JWT token
POST /auth/logout      # Logout and invalidate session
```

### **Profile Management**
```http
GET  /profile          # Get employee profile
PUT  /profile/update   # Update profile (logs changes)
```

### **Meeting Rooms**
```http
GET  /rooms            # List all available rooms
GET  /rooms/{id}       # Get room details with today's bookings
```

### **Bookings**
```http
POST /bookings         # Create new booking
GET  /bookings/my      # Get my bookings
DELETE /bookings/{id}  # Cancel booking
```

### **Admin (Role-based)**
```http
GET /admin/employees   # List all employees (admin only)
GET /admin/audit-logs  # View audit logs (manager+ only)
```

### **System**
```http
GET /                  # System information
GET /health            # Health check
```

## 🔒 Security Features

### **Password Policy**
- **Minimum 8 characters**
- **At least 1 number**
- **At least 1 special character** (!@#$%^&*(),.?":{}|<>)
- **Bcrypt hashing** for secure storage

### **Account Protection**
- **Failed Attempt Tracking**: Monitor login failures
- **Account Lockout**: 3 failed attempts = 15-minute lockout
- **Automatic Unlock**: Accounts unlock after lockout period
- **Audit Trail**: All attempts logged with IP addresses

### **Session Security**
- **JWT Tokens**: Secure, stateless authentication
- **Session Timeout**: 30 minutes of inactivity
- **Activity Tracking**: Updates on each API call
- **Secure Logout**: Invalidates sessions properly

### **Role-Based Access**
- **Employee**: Basic access (profile, rooms, own bookings)
- **Manager**: Employee access + audit logs + cancel any booking
- **Admin**: Full access including employee management

## 📋 Usage Examples

### **1. Register Employee**
```bash
curl -X POST "http://localhost:8000/auth/register" \
     -H "Content-Type: application/json" \
     -d '{
       "employee_id": "EMP001",
       "email": "john@company.com",
       "password": "SecurePass123!",
       "full_name": "John Doe",
       "department": "Engineering",
       "role": "employee"
     }'
```

### **2. Login Employee**
```bash
curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/json" \
     -d '{
       "email": "john@company.com",
       "password": "SecurePass123!"
     }'
```

### **3. Book Meeting Room**
```bash
curl -X POST "http://localhost:8000/bookings" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "room_id": 1,
       "start_time": "2024-01-15T10:00:00",
       "end_time": "2024-01-15T11:00:00",
       "purpose": "Team Meeting"
     }'
```

### **4. View Audit Logs (Manager+)**
```bash
curl -X GET "http://localhost:8000/admin/audit-logs?limit=20" \
     -H "Authorization: Bearer MANAGER_JWT_TOKEN"
```

## 🗄️ Database Schema

### **Employees Table**
```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    department TEXT NOT NULL,
    role TEXT CHECK (role IN ('employee', 'manager', 'admin')),
    is_active BOOLEAN DEFAULT TRUE,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### **Rooms Table**
```sql
CREATE TABLE rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    capacity INTEGER NOT NULL,
    location TEXT NOT NULL,
    equipment TEXT,
    is_active BOOLEAN DEFAULT TRUE
);
```

### **Bookings Table**
```sql
CREATE TABLE bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER NOT NULL,
    employee_id INTEGER NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### **Audit Logs Table**
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    employee_email TEXT,
    ip_address TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN
);
```

## 🧪 Testing

### **Run All Tests**
```bash
python unit_test.py
```

### **Test Categories** (`unit_test.py`)
- **Employee Registration**: Password complexity, duplicate prevention
- **Authentication**: Login, account lockout, session management  
- **Session Management**: Activity tracking, logout functionality
- **Meeting Room Booking**: Booking creation, conflict prevention, my bookings
- **Role-Based Access**: Permission validation for different roles
- **Audit Logging**: Verification of all logged events
- **Profile Management**: Profile updates with audit trails
- **Security Features**: Token validation, protected endpoints
- **System Health**: Health checks and system status

## 📊 Audit Event Types

### **Authentication Events**
- `LOGIN_SUCCESS` - Successful login
- `LOGIN_FAILED` - Failed login attempt
- `LOGOUT` - Employee logout
- `ACCOUNT_LOCKED` - Account locked due to failed attempts

### **Profile Events**
- `EMPLOYEE_REGISTERED` - New employee registration
- `PROFILE_UPDATED` - Profile information changed

### **Booking Events**
- `BOOKING_CREATED` - New room booking
- `BOOKING_CANCELLED` - Booking cancellation
- `BOOKING_FAILED` - Failed booking attempt

### **System Events**
- `REGISTRATION_FAILED` - Failed registration attempt
- `REGISTRATION_ERROR` - Registration system error

## 🔧 Configuration

### **Security Settings**
```python
# Password complexity
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_NUMBER = True
PASSWORD_REQUIRE_SPECIAL = True

# Account lockout
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 15

# Session management
SESSION_TIMEOUT_MINUTES = 30
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Audit retention
AUDIT_LOG_RETENTION_DAYS = 30
```

### **Sample Meeting Rooms**
- **Conference Room A**: 10 people, 1st Floor (Projector, Video Conference)
- **Conference Room B**: 6 people, 1st Floor (Whiteboard, TV)
- **Meeting Room 1**: 4 people, 2nd Floor (Whiteboard)
- **Meeting Room 2**: 4 people, 2nd Floor (TV Screen)
- **Board Room**: 20 people, 3rd Floor (Full Equipment)

## 🎯 Learning Objectives

This project demonstrates:

### **Identity Management**
- **Local user storage** without external dependencies
- **Employee lifecycle** (registration, profile updates, deactivation)
- **Role-based permissions** with hierarchical access
- **Secure authentication** with modern practices

### **Security Hardening**
- **Password policies** for strong authentication
- **Account protection** against brute force attacks
- **Session management** with timeout protection
- **Input validation** and sanitization

### **Audit Logging**
- **Comprehensive event tracking** for compliance
- **Structured logging** with searchable fields
- **Automatic retention** management
- **Security event monitoring**

### **Business Logic**
- **Resource booking** with conflict resolution
- **Time-based validation** and scheduling
- **User permissions** and ownership models
- **Real-world scenarios** and edge cases

## 🚀 Production Considerations

For production deployment:

1. **Database**: Use PostgreSQL instead of SQLite
2. **Secret Management**: Use environment variables for secrets
3. **Session Storage**: Use Redis for distributed sessions
4. **Audit Storage**: Consider separate audit database
5. **Monitoring**: Add health checks and metrics
6. **Backup**: Implement regular database backups
7. **HTTPS**: Always use TLS in production
8. **Rate Limiting**: Add API rate limiting
9. **Logging**: Structured logging with log aggregation

## 🤝 Contributing

This is an educational project demonstrating identity management and security concepts. Feel free to:

- Add new features (email notifications, calendar integration)
- Improve security measures (2FA, password history)
- Enhance audit logging (more event types, analytics)
- Add more test cases
- Improve documentation

## 📚 Additional Resources

- **FastAPI Security**: https://fastapi.tiangolo.com/tutorial/security/
- **JWT Best Practices**: https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/
- **OWASP Authentication**: https://owasp.org/www-project-top-ten/
- **Audit Logging Standards**: https://www.sans.org/white-papers/1168/
- **Identity Management**: https://en.wikipedia.org/wiki/Identity_management

## 📄 License

This project is for educational purposes. Feel free to use and modify as needed.

---

**Built with ❤️ for learning identity management, security hardening, and audit logging**