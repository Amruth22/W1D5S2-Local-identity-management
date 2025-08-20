"""
Company Meeting Room Booking System
Local Identity Management + Security Hardening + Audit Logging
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import sqlite3
import re
import threading
import time
from typing import List, Optional, Dict, Any
import logging
import uvicorn
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Meeting Room Booking System",
    description="Company Meeting Room Management with Identity Management, Security Hardening, and Audit Logging",
    version="1.0.0"
)

# Security configuration
SECRET_KEY = "meeting-room-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SESSION_TIMEOUT_MINUTES = 30

# Password complexity requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_NUMBER = True
PASSWORD_REQUIRE_SPECIAL = True

# Account lockout settings
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_MINUTES = 15

# Audit log retention
AUDIT_LOG_RETENTION_DAYS = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# In-memory storage for failed attempts and sessions
failed_attempts = defaultdict(list)  # {email: [timestamp1, timestamp2, ...]}
active_sessions = {}  # {email: last_activity_timestamp}
failed_attempts_lock = threading.RLock()

# Pydantic models
class EmployeeRegister(BaseModel):
    employee_id: str
    email: EmailStr
    password: str
    full_name: str
    department: str
    role: str  # "employee", "manager", "admin"
    
    @validator('password')
    def validate_password_complexity(cls, v):
        if len(v) < PASSWORD_MIN_LENGTH:
            raise ValueError(f'Password must be at least {PASSWORD_MIN_LENGTH} characters long')
        
        if PASSWORD_REQUIRE_NUMBER and not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        
        if PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        
        return v
    
    @validator('role')
    def validate_role(cls, v):
        valid_roles = ["employee", "manager", "admin"]
        if v not in valid_roles:
            raise ValueError(f'Role must be one of: {", ".join(valid_roles)}')
        return v

class EmployeeLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class Employee(BaseModel):
    id: int
    employee_id: str
    email: str
    full_name: str
    department: str
    role: str
    is_active: bool
    created_at: datetime

class RoomBooking(BaseModel):
    room_id: int
    start_time: datetime
    end_time: datetime
    purpose: str
    
    @validator('end_time')
    def validate_end_time(cls, v, values):
        if 'start_time' in values and v <= values['start_time']:
            raise ValueError('End time must be after start time')
        return v

class Room(BaseModel):
    id: int
    name: str
    capacity: int
    location: str
    equipment: str

class Booking(BaseModel):
    id: int
    room_id: int
    employee_id: int
    start_time: datetime
    end_time: datetime
    purpose: str
    status: str
    created_at: datetime
    room_name: str
    employee_name: str

# Database initialization
def init_database():
    """Initialize SQLite database with all required tables"""
    conn = sqlite3.connect("meeting_room_system.db", check_same_thread=False)
    cursor = conn.cursor()
    
    # Employees table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('employee', 'manager', 'admin')),
            is_active BOOLEAN DEFAULT TRUE,
            failed_attempts INTEGER DEFAULT 0,
            locked_until DATETIME NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Meeting rooms table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            capacity INTEGER NOT NULL,
            location TEXT NOT NULL,
            equipment TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Bookings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            start_time DATETIME NOT NULL,
            end_time DATETIME NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT DEFAULT 'active' CHECK (status IN ('active', 'cancelled')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms (id),
            FOREIGN KEY (employee_id) REFERENCES employees (id)
        )
    """)
    
    # Audit logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            employee_email TEXT,
            ip_address TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN
        )
    """)
    
    # Create indexes for better performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_employees_email ON employees(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_bookings_room_time ON bookings(room_id, start_time, end_time)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
    
    # Add sample data if tables are empty
    cursor.execute("SELECT COUNT(*) FROM rooms")
    if cursor.fetchone()[0] == 0:
        sample_rooms = [
            ("Conference Room A", 10, "1st Floor", "Projector, Whiteboard, Video Conference"),
            ("Conference Room B", 6, "1st Floor", "Whiteboard, TV Screen"),
            ("Meeting Room 1", 4, "2nd Floor", "Whiteboard"),
            ("Meeting Room 2", 4, "2nd Floor", "TV Screen"),
            ("Board Room", 20, "3rd Floor", "Projector, Video Conference, Whiteboard")
        ]
        
        cursor.executemany(
            "INSERT INTO rooms (name, capacity, location, equipment) VALUES (?, ?, ?, ?)",
            sample_rooms
        )
        logger.info("Sample meeting rooms added")
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

def get_db_connection():
    """Get database connection"""
    return sqlite3.connect("meeting_room_system.db", check_same_thread=False)

def log_audit_event(event_type: str, employee_email: str = None, ip_address: str = None, 
                   details: str = None, success: bool = True):
    """Log audit event to database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit_logs (event_type, employee_email, ip_address, details, success)
            VALUES (?, ?, ?, ?, ?)
        """, (event_type, employee_email, ip_address, details, success))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Audit log: {event_type} - {employee_email} - {success}")
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")

def cleanup_old_audit_logs():
    """Remove audit logs older than retention period"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=AUDIT_LOG_RETENTION_DAYS)
        cursor.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff_date,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old audit logs")
    except Exception as e:
        logger.error(f"Failed to cleanup audit logs: {e}")

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(email: str):
    """Create JWT access token"""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": email, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def is_account_locked(email: str) -> bool:
    """Check if account is locked due to failed attempts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT locked_until FROM employees WHERE email = ?", (email,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0]:
        locked_until = datetime.fromisoformat(result[0])
        if datetime.now() < locked_until:
            return True
        else:
            # Unlock account if lockout period has passed
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE employees SET locked_until = NULL, failed_attempts = 0 WHERE email = ?",
                (email,)
            )
            conn.commit()
            conn.close()
    
    return False

def record_failed_attempt(email: str, ip_address: str):
    """Record failed login attempt and lock account if necessary"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Increment failed attempts
    cursor.execute(
        "UPDATE employees SET failed_attempts = failed_attempts + 1 WHERE email = ?",
        (email,)
    )
    
    # Check if account should be locked
    cursor.execute("SELECT failed_attempts FROM employees WHERE email = ?", (email,))
    result = cursor.fetchone()
    
    if result and result[0] >= MAX_FAILED_ATTEMPTS:
        # Lock account
        locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        cursor.execute(
            "UPDATE employees SET locked_until = ? WHERE email = ?",
            (locked_until, email)
        )
        
        log_audit_event("ACCOUNT_LOCKED", email, ip_address, 
                       f"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts")
    
    conn.commit()
    conn.close()

def reset_failed_attempts(email: str):
    """Reset failed attempts counter after successful login"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE employees SET failed_attempts = 0, locked_until = NULL WHERE email = ?",
        (email,)
    )
    conn.commit()
    conn.close()

def update_session_activity(email: str):
    """Update last activity timestamp for session timeout"""
    active_sessions[email] = time.time()

def is_session_expired(email: str) -> bool:
    """Check if user session has expired due to inactivity"""
    if email not in active_sessions:
        return True
    
    last_activity = active_sessions[email]
    current_time = time.time()
    
    if current_time - last_activity > (SESSION_TIMEOUT_MINUTES * 60):
        # Remove expired session
        active_sessions.pop(email, None)
        return True
    
    return False

def get_current_employee(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Employee:
    """Get current employee from JWT token with session validation"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check session timeout
        if is_session_expired(email):
            raise HTTPException(status_code=401, detail="Session expired due to inactivity")
        
        # Update session activity
        update_session_activity(email)
        
        # Get employee from database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, employee_id, email, full_name, department, role, is_active, created_at
            FROM employees WHERE email = ? AND is_active = TRUE
        """, (email,))
        
        employee_data = cursor.fetchone()
        conn.close()
        
        if employee_data is None:
            raise HTTPException(status_code=401, detail="Employee not found or inactive")
        
        return Employee(
            id=employee_data[0],
            employee_id=employee_data[1],
            email=employee_data[2],
            full_name=employee_data[3],
            department=employee_data[4],
            role=employee_data[5],
            is_active=employee_data[6],
            created_at=datetime.fromisoformat(employee_data[7])
        )
    
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_role: str):
    """Dependency to require specific role"""
    def role_checker(current_employee: Employee = Depends(get_current_employee)) -> Employee:
        role_hierarchy = {"employee": 1, "manager": 2, "admin": 3}
        
        current_level = role_hierarchy.get(current_employee.role, 0)
        required_level = role_hierarchy.get(required_role, 999)
        
        if current_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. {required_role} role required."
            )
        
        return current_employee
    
    return role_checker

# API Endpoints

@app.on_event("startup")
async def startup_event():
    """Initialize database and cleanup old logs on startup"""
    init_database()
    cleanup_old_audit_logs()
    logger.info("Meeting Room Booking System started")

@app.get("/")
async def root():
    """Root endpoint with system information"""
    return {
        "message": "Company Meeting Room Booking System",
        "version": "1.0.0",
        "features": [
            "Local Identity Management",
            "Security Hardening (Password complexity, Account lockout, Session timeout)",
            "Audit Logging (30-day retention)",
            "Meeting Room Booking",
            "Role-based Access Control"
        ],
        "endpoints": {
            "auth": ["/auth/register", "/auth/login", "/auth/logout"],
            "profile": ["/profile", "/profile/update"],
            "rooms": ["/rooms", "/rooms/{id}"],
            "bookings": ["/bookings", "/bookings/my", "/bookings/{id}"],
            "admin": ["/admin/employees", "/admin/audit-logs"]
        }
    }

# Authentication endpoints
@app.post("/auth/register", response_model=dict)
async def register_employee(employee: EmployeeRegister, request: Request):
    """Register a new employee"""
    client_ip = request.client.host
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if employee already exists
        cursor.execute("SELECT id FROM employees WHERE email = ? OR employee_id = ?", 
                      (employee.email, employee.employee_id))
        if cursor.fetchone():
            log_audit_event("REGISTRATION_FAILED", employee.email, client_ip, 
                           "Employee already exists", False)
            raise HTTPException(status_code=400, detail="Employee already exists")
        
        # Create new employee
        password_hash = hash_password(employee.password)
        cursor.execute("""
            INSERT INTO employees (employee_id, email, password_hash, full_name, department, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (employee.employee_id, employee.email, password_hash, 
              employee.full_name, employee.department, employee.role))
        
        conn.commit()
        employee_db_id = cursor.lastrowid
        
        log_audit_event("EMPLOYEE_REGISTERED", employee.email, client_ip, 
                       f"New employee registered: {employee.full_name} ({employee.department})")
        
        return {
            "message": "Employee registered successfully",
            "employee_id": employee.employee_id,
            "email": employee.email,
            "role": employee.role
        }
    
    except Exception as e:
        if "Employee already exists" not in str(e):
            log_audit_event("REGISTRATION_ERROR", employee.email, client_ip, str(e), False)
        raise
    finally:
        conn.close()

@app.post("/auth/login", response_model=Token)
async def login_employee(employee: EmployeeLogin, request: Request):
    """Login employee and return JWT token"""
    client_ip = request.client.host
    
    # Check if account is locked
    if is_account_locked(employee.email):
        log_audit_event("LOGIN_FAILED", employee.email, client_ip, "Account locked", False)
        raise HTTPException(status_code=423, detail="Account locked due to multiple failed attempts")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get employee from database
        cursor.execute("""
            SELECT id, employee_id, email, password_hash, full_name, department, role, is_active
            FROM employees WHERE email = ?
        """, (employee.email,))
        
        employee_data = cursor.fetchone()
        
        if not employee_data or not employee_data[7]:  # Check if active
            log_audit_event("LOGIN_FAILED", employee.email, client_ip, "Employee not found or inactive", False)
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # Verify password
        if not verify_password(employee.password, employee_data[3]):
            record_failed_attempt(employee.email, client_ip)
            log_audit_event("LOGIN_FAILED", employee.email, client_ip, "Invalid password", False)
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # Reset failed attempts on successful login
        reset_failed_attempts(employee.email)
        
        # Create access token and start session
        access_token = create_access_token(employee.email)
        update_session_activity(employee.email)
        
        log_audit_event("LOGIN_SUCCESS", employee.email, client_ip, 
                       f"Successful login: {employee_data[4]} ({employee_data[6]})")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    finally:
        conn.close()

@app.post("/auth/logout")
async def logout_employee(request: Request, current_employee: Employee = Depends(get_current_employee)):
    """Logout employee and invalidate session"""
    client_ip = request.client.host
    
    # Remove session
    active_sessions.pop(current_employee.email, None)
    
    log_audit_event("LOGOUT", current_employee.email, client_ip, "Employee logged out")
    
    return {"message": "Logged out successfully"}

# Profile endpoints
@app.get("/profile", response_model=Employee)
async def get_profile(current_employee: Employee = Depends(get_current_employee)):
    """Get current employee profile"""
    return current_employee

@app.put("/profile/update")
async def update_profile(
    full_name: Optional[str] = None,
    department: Optional[str] = None,
    request: Request = None,
    current_employee: Employee = Depends(get_current_employee)
):
    """Update employee profile"""
    client_ip = request.client.host
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    updates = []
    values = []
    changes = []
    
    if full_name:
        updates.append("full_name = ?")
        values.append(full_name)
        changes.append(f"name: {current_employee.full_name} -> {full_name}")
    
    if department:
        updates.append("department = ?")
        values.append(department)
        changes.append(f"department: {current_employee.department} -> {department}")
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    updates.append("updated_at = CURRENT_TIMESTAMP")
    values.append(current_employee.id)
    
    query = f"UPDATE employees SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(query, values)
    
    conn.commit()
    conn.close()
    
    log_audit_event("PROFILE_UPDATED", current_employee.email, client_ip, 
                   f"Profile updated: {'; '.join(changes)}")
    
    return {"message": "Profile updated successfully", "changes": changes}

# Room endpoints
@app.get("/rooms", response_model=List[Room])
async def get_rooms(current_employee: Employee = Depends(get_current_employee)):
    """Get all available meeting rooms"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, name, capacity, location, equipment
        FROM rooms WHERE is_active = TRUE
        ORDER BY name
    """)
    
    rooms = []
    for row in cursor.fetchall():
        rooms.append(Room(
            id=row[0],
            name=row[1],
            capacity=row[2],
            location=row[3],
            equipment=row[4]
        ))
    
    conn.close()
    return rooms

@app.get("/rooms/{room_id}")
async def get_room(room_id: int, current_employee: Employee = Depends(get_current_employee)):
    """Get specific room details with current bookings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get room details
    cursor.execute("SELECT id, name, capacity, location, equipment FROM rooms WHERE id = ? AND is_active = TRUE", (room_id,))
    room_data = cursor.fetchone()
    
    if not room_data:
        raise HTTPException(status_code=404, detail="Room not found")
    
    # Get current bookings for today
    today = datetime.now().date()
    tomorrow = today + timedelta(days=1)
    
    cursor.execute("""
        SELECT b.start_time, b.end_time, b.purpose, e.full_name
        FROM bookings b
        JOIN employees e ON b.employee_id = e.id
        WHERE b.room_id = ? AND b.status = 'active'
        AND DATE(b.start_time) = DATE(?)
        ORDER BY b.start_time
    """, (room_id, today))
    
    bookings = []
    for booking in cursor.fetchall():
        bookings.append({
            "start_time": booking[0],
            "end_time": booking[1],
            "purpose": booking[2],
            "booked_by": booking[3]
        })
    
    conn.close()
    
    return {
        "room": Room(
            id=room_data[0],
            name=room_data[1],
            capacity=room_data[2],
            location=room_data[3],
            equipment=room_data[4]
        ),
        "today_bookings": bookings
    }

# Booking endpoints
@app.post("/bookings")
async def create_booking(
    booking: RoomBooking,
    request: Request,
    current_employee: Employee = Depends(get_current_employee)
):
    """Create a new room booking"""
    client_ip = request.client.host
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if room exists
        cursor.execute("SELECT name FROM rooms WHERE id = ? AND is_active = TRUE", (booking.room_id,))
        room_data = cursor.fetchone()
        
        if not room_data:
            raise HTTPException(status_code=404, detail="Room not found")
        
        room_name = room_data[0]
        
        # Check for conflicting bookings
        cursor.execute("""
            SELECT id FROM bookings
            WHERE room_id = ? AND status = 'active'
            AND (
                (start_time <= ? AND end_time > ?) OR
                (start_time < ? AND end_time >= ?) OR
                (start_time >= ? AND end_time <= ?)
            )
        """, (booking.room_id, booking.start_time, booking.start_time,
              booking.end_time, booking.end_time,
              booking.start_time, booking.end_time))
        
        if cursor.fetchone():
            log_audit_event("BOOKING_FAILED", current_employee.email, client_ip,
                           f"Booking conflict for {room_name}: {booking.start_time} - {booking.end_time}", False)
            raise HTTPException(status_code=409, detail="Room is already booked for this time slot")
        
        # Create booking
        cursor.execute("""
            INSERT INTO bookings (room_id, employee_id, start_time, end_time, purpose)
            VALUES (?, ?, ?, ?, ?)
        """, (booking.room_id, current_employee.id, booking.start_time, booking.end_time, booking.purpose))
        
        booking_id = cursor.lastrowid
        conn.commit()
        
        log_audit_event("BOOKING_CREATED", current_employee.email, client_ip,
                       f"Booked {room_name}: {booking.start_time} - {booking.end_time} for {booking.purpose}")
        
        return {
            "message": "Booking created successfully",
            "booking_id": booking_id,
            "room_name": room_name,
            "start_time": booking.start_time,
            "end_time": booking.end_time
        }
    
    finally:
        conn.close()

@app.get("/bookings/my", response_model=List[Booking])
async def get_my_bookings(current_employee: Employee = Depends(get_current_employee)):
    """Get current employee's bookings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT b.id, b.room_id, b.employee_id, b.start_time, b.end_time, 
               b.purpose, b.status, b.created_at, r.name, e.full_name
        FROM bookings b
        JOIN rooms r ON b.room_id = r.id
        JOIN employees e ON b.employee_id = e.id
        WHERE b.employee_id = ? AND b.status = 'active'
        ORDER BY b.start_time DESC
    """, (current_employee.id,))
    
    bookings = []
    for row in cursor.fetchall():
        bookings.append(Booking(
            id=row[0],
            room_id=row[1],
            employee_id=row[2],
            start_time=datetime.fromisoformat(row[3]),
            end_time=datetime.fromisoformat(row[4]),
            purpose=row[5],
            status=row[6],
            created_at=datetime.fromisoformat(row[7]),
            room_name=row[8],
            employee_name=row[9]
        ))
    
    conn.close()
    return bookings

@app.delete("/bookings/{booking_id}")
async def cancel_booking(
    booking_id: int,
    request: Request,
    current_employee: Employee = Depends(get_current_employee)
):
    """Cancel a booking (only own bookings or managers can cancel any)"""
    client_ip = request.client.host
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get booking details
    cursor.execute("""
        SELECT b.id, b.employee_id, b.purpose, r.name, b.start_time, b.end_time
        FROM bookings b
        JOIN rooms r ON b.room_id = r.id
        WHERE b.id = ? AND b.status = 'active'
    """, (booking_id,))
    
    booking_data = cursor.fetchone()
    
    if not booking_data:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Check permissions (own booking or manager/admin)
    if booking_data[1] != current_employee.id and current_employee.role not in ["manager", "admin"]:
        log_audit_event("BOOKING_CANCEL_FAILED", current_employee.email, client_ip,
                       f"Unauthorized cancellation attempt for booking {booking_id}", False)
        raise HTTPException(status_code=403, detail="Can only cancel your own bookings")
    
    # Cancel booking
    cursor.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
    conn.commit()
    conn.close()
    
    log_audit_event("BOOKING_CANCELLED", current_employee.email, client_ip,
                   f"Cancelled booking for {booking_data[3]}: {booking_data[4]} - {booking_data[5]}")
    
    return {
        "message": "Booking cancelled successfully",
        "booking_id": booking_id,
        "room_name": booking_data[3]
    }

# Admin endpoints
@app.get("/admin/employees")
async def get_all_employees(current_employee: Employee = Depends(require_role("admin"))):
    """Get all employees (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, employee_id, email, full_name, department, role, is_active, 
               failed_attempts, locked_until, created_at
        FROM employees
        ORDER BY full_name
    """)
    
    employees = []
    for row in cursor.fetchall():
        employees.append({
            "id": row[0],
            "employee_id": row[1],
            "email": row[2],
            "full_name": row[3],
            "department": row[4],
            "role": row[5],
            "is_active": row[6],
            "failed_attempts": row[7],
            "locked_until": row[8],
            "created_at": row[9]
        })
    
    conn.close()
    return employees

@app.get("/admin/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    event_type: Optional[str] = None,
    current_employee: Employee = Depends(require_role("manager"))
):
    """Get audit logs (manager/admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM audit_logs"
    params = []
    
    if event_type:
        query += " WHERE event_type = ?"
        params.append(event_type)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    
    logs = []
    for row in cursor.fetchall():
        logs.append({
            "id": row[0],
            "event_type": row[1],
            "employee_email": row[2],
            "ip_address": row[3],
            "details": row[4],
            "timestamp": row[5],
            "success": row[6]
        })
    
    conn.close()
    return logs

# Health and status endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "database": "connected",
        "active_sessions": len(active_sessions)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)