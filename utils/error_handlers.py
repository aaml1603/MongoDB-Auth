import logging
from flask import jsonify, request


def handle_rate_limit_exceeded(error):
    """Enhanced rate limit error handler with detailed information."""
    
    # Log the rate limit violation
    endpoint = request.endpoint or 'unknown'
    remote_addr = getattr(request, 'remote_addr', 'unknown')
    user_agent = request.headers.get('User-Agent', 'unknown')
    
    logging.warning(
        f"Rate limit exceeded - IP: {remote_addr}, "
        f"Endpoint: {endpoint}, "
        f"User-Agent: {user_agent[:100]}..."
    )
    
    # Get rate limit details
    retry_after = getattr(error, 'retry_after', None)
    limit = getattr(error, 'limit', 'unknown')
    
    # Create detailed error response
    response_data = {
        "success": False,
        "error": "rate_limit_exceeded",
        "message": "Too many requests. Please slow down and try again later.",
        "details": {
            "limit": str(limit) if limit != 'unknown' else None,
            "retry_after_seconds": retry_after,
            "endpoint": endpoint
        }
    }
    
    # Add retry-after header if available
    response = jsonify(response_data)
    if retry_after:
        response.headers['Retry-After'] = str(retry_after)
    
    return response, 429


def setup_error_handlers(app):
    """Setup all error handlers for the application."""
    
    @app.errorhandler(429)
    def rate_limit_handler(error):
        return handle_rate_limit_exceeded(error)
    
    @app.errorhandler(500)
    def internal_error_handler(error):
        logging.error(f"Internal server error: {error}")
        return jsonify({
            "success": False,
            "error": "internal_server_error",
            "message": "An internal server error occurred"
        }), 500
    
    @app.errorhandler(404)
    def not_found_handler(error):
        return jsonify({
            "success": False,
            "error": "not_found", 
            "message": "The requested resource was not found"
        }), 404
    
    @app.errorhandler(400)
    def bad_request_handler(error):
        return jsonify({
            "success": False,
            "error": "bad_request",
            "message": "The request was invalid"
        }), 400