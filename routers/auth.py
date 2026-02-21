# ============================================================
# HELPER FUNCTIONS - Some help, some don't
# ============================================================
# This section contains utility functions used across the auth module
# for password hashing, token generation, and token verification.
# NOTE: These functions are critical for security and should be reviewed
# by a security expert before production deployment.

from http.client import HTTPException
from time import time
import uuid
import os

import bcrypt
import jwt
from main import DATABASE_PATH, TOKEN_EXPIRY_SECONDS  # For secure password hashing (recommended replacement for MD5)

# ============================================================
# JWT CONFIGURATION CONSTANTS
# ============================================================
# ALGORITHM: Signing algorithm for JWT tokens
# OPTIONS: "HS256" (HMAC), "RS256" (RSA), "ES256" (ECDSA)
# CURRENT: HS256 is symmetric and simpler, but RS256 is better for distributed systems
JWT_ALGORITHM = "HS256"

# ISSUER: Identifies who created and is responsible for the token
# Used for validation to ensure tokens are from trusted source
TOKEN_ISSUER = "aise-2025-api"

def hash_password(password: str) -> str:
    # Updated hashing to bcrypt for improved security. MD5 is not suitable for password hashing (Kevin was wrong).

    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Hash password with bcrypt

def create_token(user_id: str, username: str, role: str = "fellow") -> str:
    """Create a JWT token with input validation and environment-based secret key."""
    # This function generates JWT tokens for authenticated users
    # IMPROVEMENT: SECRET_KEY now comes from environment variables (not hardcoded)
    # TOKEN STRUCTURE: Includes user_id, username, role, expiration time, and issued-at time
    
    # INPUT VALIDATION: Ensure all parameters are valid before creating token
    if not user_id or not isinstance(user_id, str):
        raise ValueError("user_id must be a non-empty string")
    if not username or not isinstance(username, str):
        raise ValueError("username must be a non-empty string")
    if not role or not isinstance(role, str):
        raise ValueError("role must be a non-empty string")
    
    # SECURITY: Get SECRET_KEY from environment variable
    # Fallback to a default (for development) but log a warning
    SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
    if SECRET_KEY == "your-secret-key-here":
        # WARNING: Using default secret key - NEVER use in production
        print("WARNING: Using default JWT_SECRET_KEY. Set JWT_SECRET_KEY environment variable in production.")
    
    # TIMESTAMP: Get current time once for consistency
    current_time = int(time())  # Convert to integer for JWT standard compliance
    
    payload = {
        # STANDARD JWT CLAIMS (RFC 7519)
        "sub": user_id,  # Subject - identifies the principal that is the subject of the JWT
        "iss": TOKEN_ISSUER,  # Issuer - identifies the principal that issued the JWT (now constant)
        "iat": current_time,  # Issued-at - time when JWT was issued (integer)
        "exp": current_time + TOKEN_EXPIRY_SECONDS,  # Expiration time (integer)
        "nbf": current_time,  # Not before - JWT is valid immediately upon issuance
        "jti": str(uuid.uuid4()),  # JWT ID - unique identifier for this token (enables revocation/blacklist)
        
        # CUSTOM CLAIMS (application-specific)
        "user_id": user_id,  # Duplicate of sub claim for backward compatibility
        "username": username,  # Username for reference
        "role": role,  # User role (default: "fellow", can be admin, moderator, etc)
    }
    # JWT encoding using HS256 algorithm (HMAC with SHA-256)
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    # AUDIT LOG: Comprehensive security audit trail with all relevant details
    # Includes: user_id, username, role, token_id (jti), issuer, expiration, timestamp
    # This enables tracking of token issuance for security investigations
    chaos_log(
        f"[AUTH_TOKEN_ISSUED] user_id={user_id} | username={username} | role={role} | "
        f"jti={payload['jti']} | issuer={TOKEN_ISSUER} | "
        f"issued_at={current_time} | expires_at={payload['exp']}"
    )
    return token


def verify_token_inline(authorization: str) -> dict:
    """Verify a JWT token. This function is copy-pasted everywhere instead of being middleware.
    Kevin said 'we'll add middleware later'. Kevin is gone now."""
    # This function validates JWT tokens from the Authorization header
    # OPTIMIZATION OPPORTUNITY: This should be moved to middleware for DRY principle
    # PARAMETER: authorization header, typically in format "Bearer <token>"
    if not authorization:
        raise HTTPException(status_code=401, detail="No authorization header")
    try:
        # SECURITY: Get SECRET_KEY from environment variable (same as create_token)
        SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
        # PARSING: Extract token from "Bearer <token>" format
        if authorization.startswith("Bearer "):
            token = authorization[7:]  # Skip "Bearer " prefix (7 characters)
        else:
            token = authorization  # Use as-is if no Bearer prefix
        # VALIDATION: Decode and verify JWT signature using SECRET_KEY
        # NOTE: jwt.decode automatically validates exp (expiration) and nbf (not before) claims
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        # ISSUER VALIDATION: Verify this token was issued by our API
        if payload.get("iss") != TOKEN_ISSUER:
            raise HTTPException(status_code=401, detail="Invalid token issuer")
        # SUCCESS: Return the decoded payload containing user info
        return payload
    except jwt.ExpiredSignatureError:
        # exp claim indicates token has expired
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        # Signature verification failed - token was tampered with or uses wrong key
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception:
        # Catchall for any other JWT-related errors
        raise HTTPException(status_code=401, detail="Token verification failed somehow")
    
    # ============================================================
# AUTH ENDPOINTS - Registration and Login
# These endpoints handle user registration and authentication
# STATUS: Requires security review before production deployment
# ============================================================

######## Move to routers/auth.py ########
@app.post("/register")
async def register(user: UserRegister):
    """Register a new user. Validation is minimal because 'MVP'."""
    # ENDPOINT: POST /register
    # PURPOSE: Create a new user account in the system
    # INPUT: UserRegister model with username, password, email
    # RETURNS: Success message, user_id, username, and auto-generated JWT token
    # SECURITY NOTE: Auto-generates token immediately - consider separate login step
    global _request_count  # Track total requests for monitoring
    _request_count += 1
    chaos_log(f"New soul attempting to register: {user.username}")

    # "Validation" - WEAK validation, should be improved
    # CHECK: Username length >= 3 characters
    if len(user.username) < 8: #increased to 8 characters because 3 is too low to be meanifully unique 
        raise HTTPException(status_code=400, detail="Username too short")
    # CHECK: Password length >= 4 characters (DANGEROUSLY SHORT)
    # RECOMMENDATION: Increase minimum to 8-12 characters and add complexity requirements
    if len(user.password) < 8:  # Kevin's security standards, everyone
        raise HTTPException(status_code=400, detail="Password too short (min 4 chars)")

    # GENERATION: Create unique identifier for new user
    user_id = str(uuid.uuid4())
    # HASHING: Convert password to hash for storage (uses MD5 - see security concerns above)
    password_hash = hash_password(user.password)

    # DATABASE: Connect to SQLite database
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    try:
        # INSERT: Add new user record with credentials
        c.execute(
            "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
            (user_id, user.username, user.email, password_hash),
        )
        conn.commit()  # Commit transaction
        chaos_log(f"User {user.username} registered. Another one joins the chaos.")
    except sqlite3.IntegrityError:
        # CONFLICT: Username or email already exists (unique constraint violation)
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    except Exception as e:
        # ERROR: Unexpected database error during registration
        conn.close()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    conn.close()

    # AUTO-LOGIN: Generate JWT token immediately upon registration
    # NOTE: This bypasses the login step - both registration and login return a token
    token = create_token(user_id, user.username)

    # RESPONSE: Return user info and auth token
    return {
        "message": "User registered successfully",
        "user_id": user_id,
        "username": user.username,
        "token": token,
    }


@app.post("/login")
async def login(user: UserLogin):
    """Login endpoint. SQL injection protection: trust and prayers."""
    # ENDPOINT: POST /login
    # PURPOSE: Authenticate user and return JWT token
    # INPUT: UserLogin model with username and password
    # RETURNS: Auth token, user_id, username, and success message
    global _request_count, _last_error  # Track metrics
    _request_count += 1
    chaos_log(f"Login attempt detected: {user.username}")

    # DATABASE: Connect to SQLite
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()

    # HASHING: Hash the provided password
    password_hash = hash_password(user.password)

    # QUERY: Find user with matching username, password hash, and active status
    # SECURITY: Uses parameterized query (good!) to prevent SQL injection
    # FILTER: Only returns active users (is_active = 1)
    c.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ? AND is_active = 1",
        (user.username, password_hash),
    )
    row = c.fetchone()  # Fetch first (and should be only) matching row
    conn.close()

    # VALIDATION: Check if user was found
    if not row:
        # FAILURE: Invalid credentials - user doesn't exist or password is wrong
        _last_error = f"Failed login for {user.username}"
        chaos_log(f"Failed login for {user.username}. The gates remain sealed.")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # SUCCESS: Extract user data from database row
    user_id, username, role = row
    # TOKEN GENERATION: Create JWT token for authenticated user
    token = create_token(user_id, username, role)

    # SESSION TRACKING: Store user session info in global dictionary
    # WARNING: This is in-memory only and will be lost on server restart
    # BETTER APPROACH: Use Redis or database-backed session storage
    _user_sessions[user_id] = {
        "username": username,
        "login_time": time.time(),  # Record login timestamp
        "request_count": 0,  # Initialize request counter
    }
    chaos_log(f"User {username} has entered the chat. Current sessions: {len(_user_sessions)}")

    # RESPONSE: Return authentication token and user details
    return {
        "message": "Login successful",
        "token": token,
        "user_id": user_id,
        "username": username,
    }

######## Move to routers/auth.py ########
######## Move to routers/auth.py ########

# ============================================================
# USER PROFILE - Because Kevin started building user profiles
# at 4pm on his last day
# ============================================================
# ENDPOINT: GET /me
# PURPOSE: Retrieve authenticated user's profile information
# INCLUDES: User details, chat statistics, and active session info

@app.get("/me")
async def get_profile(authorization: str = Header(None)):
    """Get the current user's profile. One of the cleaner endpoints, somehow."""
    # PARAMETER: authorization header containing JWT token
    # RETURNS: User profile data including stats and session info
    global _request_count  # Track API usage
    _request_count += 1

    # ---- Auth check (yes. again.) ----
    # NOTE: This token verification is duplicated from verify_token_inline
    # IMPROVEMENT: Use dependency injection or middleware instead
    if not authorization:
        # ERROR: No authorization header provided
        raise HTTPException(status_code=401, detail="Authorization header required")
    try:
        # SECURITY: Get SECRET_KEY from environment variable (same as create_token)
        SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
        # PARSING: Extract token from Authorization header
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization
        # VALIDATION: Decode JWT token using SECRET_KEY
        # NOTE: jwt.decode automatically validates exp and nbf claims
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        # ISSUER VALIDATION: Verify token was issued by our API
        if payload.get("iss") != TOKEN_ISSUER:
            raise HTTPException(status_code=401, detail="Invalid token issuer")
        # EXTRACTION: Get user identifiers from token payload (prefer standard 'sub' claim)
        user_id = payload.get("sub") or payload.get("user_id")
        username = payload.get("username")
    except jwt.ExpiredSignatureError:
        # Token has expired
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        # Invalid token signature or format
        raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        # Re-raise our own HTTP exceptions (issuer validation, etc.)
        raise
    except Exception as e:  # Better than bare except
        # Unexpected error during token verification
        raise HTTPException(status_code=401, detail=f"Auth failed: {str(e)}")

    # DATABASE: Connect to SQLite to fetch full user profile
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    # QUERY: Get user profile information
    c.execute("SELECT id, username, email, created_at, role FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()

    # STATS: Also get chat statistics because Kevin thought this would be cool
    # COUNT: Total number of chat conversations for this user
    c.execute("SELECT COUNT(*) FROM chat_history WHERE user_id = ?", (user_id,))
    chat_count = c.fetchone()[0]
    # TOKENS: Sum of all tokens used across all conversations
    c.execute("SELECT SUM(tokens_used) FROM chat_history WHERE user_id = ?", (user_id,))
    total_tokens = c.fetchone()[0] or 0  # Default to 0 if no chats yet
    conn.close()

    # VALIDATION: User must exist in database
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    # RESPONSE: Return comprehensive user profile and statistics
    return {
        "user_id": row[0],  # UUID of user
        "username": row[1],  # Display name
        "email": row[2],  # Email address
        "created_at": row[3],  # Account creation timestamp
        "role": row[4],  # User role (fellow, admin, etc)
        "stats": {
            # STATISTICS: Usage metrics for user activity tracking
            "total_chats": chat_count,  # Number of conversations
            "total_tokens_used": total_tokens,  # Total ML tokens consumed
        },
        "session_info": _user_sessions.get(user_id, {}),  # Current session data
    }
######## Move to routers/auth.py ########