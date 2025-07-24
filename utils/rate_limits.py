from flask import request


def get_remote_address():
    """Get the remote address for rate limiting.
    
    Considers X-Forwarded-For header for proxy scenarios.
    """
    # Check for X-Forwarded-For header (for proxied requests)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(',')[0].strip()
    
    # Check for X-Real-IP header (nginx proxy)
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fall back to remote_addr
    return request.remote_addr or '127.0.0.1'


# Rate limit configurations for different endpoint types
RATE_LIMITS = {
    # Authentication endpoints (most restrictive)
    'auth_strict': '5 per minute',  # Login, register
    'auth_moderate': '30 per minute',  # Refresh token (more lenient)
    
    # Password reset (very restrictive due to potential abuse)
    'password_reset_request': '3 per minute',  # Request reset
    'password_reset_confirm': '5 per minute',  # Confirm reset
    
    # Protected endpoints (moderate)
    'protected_moderate': '100 per minute',  # Profile, dashboard data
    
    # Public endpoints (lenient)
    'public': '200 per minute',  # Health check
    
    # Global rate limit (safety net)
    'global': '1000 per hour',
}