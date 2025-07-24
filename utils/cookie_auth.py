from flask import request, make_response
from datetime import datetime, timedelta
import logging


def get_request_info() -> dict:
    """Extract request information for session tracking."""
    return {
        'ip_address': get_client_ip(),
        'user_agent': request.headers.get('User-Agent', ''),
        'location': 'Unknown'  # Could integrate with IP geolocation service
    }


def get_client_ip() -> str:
    """Get the real client IP, considering proxy headers."""
    # Check for X-Forwarded-For header (for proxied requests)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    # Check for X-Real-IP header (nginx proxy)
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fall back to remote_addr
    return request.remote_addr or '127.0.0.1'


def set_auth_cookies(response, access_token: str, refresh_token: str):
    """Set secure httpOnly cookies for authentication."""
    
    # Determine if we're in development mode
    import os
    is_development = os.getenv('FLASK_ENV') == 'development' or os.getenv('FLASK_DEBUG') == '1'
    
    # Access token cookie (2 hours)
    response.set_cookie(
        'access_token',
        access_token,
        max_age=2 * 60 * 60,  # 2 hours in seconds
        httponly=True,
        secure=not is_development,  # False for development, True for production
        samesite='Lax' if is_development else 'Strict',  # More lenient for dev
        path='/api'  # Restrict to API endpoints
    )
    
    # Refresh token cookie (30 days)
    response.set_cookie(
        'refresh_token',
        refresh_token,
        max_age=30 * 24 * 60 * 60,  # 30 days in seconds
        httponly=True,
        secure=not is_development,  # False for development, True for production
        samesite='Lax' if is_development else 'Strict',  # More lenient for dev
        path='/api/auth'  # Restrict to auth endpoints
    )
    
    logging.info("Auth cookies set successfully")


def clear_auth_cookies(response):
    """Clear authentication cookies."""
    import os
    is_development = os.getenv('FLASK_ENV') == 'development' or os.getenv('FLASK_DEBUG') == '1'
    
    response.set_cookie(
        'access_token',
        '',
        expires=0,
        httponly=True,
        secure=not is_development,
        samesite='Lax' if is_development else 'Strict',
        path='/api'
    )
    
    response.set_cookie(
        'refresh_token',
        '',
        expires=0,
        httponly=True,
        secure=not is_development,
        samesite='Lax' if is_development else 'Strict',
        path='/api/auth'
    )
    
    logging.info("Auth cookies cleared")


def get_token_from_cookie(cookie_name: str) -> str:
    """Extract token from httpOnly cookie."""
    return request.cookies.get(cookie_name, '')


def create_cookie_response(response_data: dict, access_token: str, refresh_token: str):
    """Create response with auth cookies set."""
    response = make_response(response_data)
    set_auth_cookies(response, access_token, refresh_token)
    return response