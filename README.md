# Flask Authentication API

A secure Flask-based REST API with JWT authentication, refresh tokens, and MongoDB integration. Features 2-hour access token expiration with 30-day refresh tokens for enhanced security.

## Features

- 🔐 **Secure Authentication**: JWT-based authentication with bcrypt password hashing
- 🔄 **Token Refresh**: Automatic token refresh with separate refresh tokens
- ⏰ **Token Expiration**: 2-hour access tokens, 30-day refresh tokens
- 📊 **MongoDB Integration**: User data stored in MongoDB
- 🏗️ **Modular Architecture**: Clean, organized codebase with separation of concerns
- 🛡️ **Security Best Practices**: Password validation, secure token handling

## Installation

### Prerequisites

- Python 3.7+
- MongoDB instance (local or cloud)
- pip (Python package manager)

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend-project
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Configuration**
   
   Create a `.env` file in the project root:
   ```env
   MONGODB_STRING=mongodb://localhost:27017/
   MONGODB_DATABASE=mascarga
   JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
   ```

4. **Start the application**
   ```bash
   python main.py
   ```

   The API will be available at `http://localhost:6969`

## Project Structure

```
backend project/
├── main.py                 # Application entry point
├── config.py              # Flask and JWT configuration
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (create this)
├── models/
│   ├── __init__.py
│   └── database.py        # MongoDB connection and management
├── auth/
│   ├── __init__.py
│   ├── authentication.py  # User authentication logic
│   └── middleware.py      # Authentication decorators
└── routes/
    ├── __init__.py
    ├── auth_routes.py      # Authentication endpoints
    └── user_routes.py      # User-related endpoints
```

## API Endpoints

### Authentication Endpoints

#### Register User
```http
POST /register
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user_id": "507f1f77bcf86cd799439011"
}
```

**Response (400):**
```json
{
  "success": false,
  "message": "User already exists"
}
```

#### Login
```http
POST /login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "user@example.com"
  }
}
```

#### Refresh Token
```http
POST /refresh
```

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response (200):**
```json
{
  "success": true,
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### User Endpoints

#### Get User Profile
```http
GET /profile
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "success": true,
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "user@example.com",
    "created_at": "2024-01-15T10:30:00Z",
    "is_active": true
  }
}
```

#### Health Check
```http
GET /health
```

**Response (200):**
```json
{
  "status": "healthy",
  "message": "API is running"
}
```

## Token Management

### Access Tokens
- **Expiration**: 2 hours
- **Usage**: Include in `Authorization: Bearer <token>` header for protected routes
- **Purpose**: Access to protected resources

### Refresh Tokens
- **Expiration**: 30 days
- **Usage**: Used to obtain new access tokens via `/refresh` endpoint
- **Purpose**: Long-term authentication without requiring re-login

### Authentication Flow

1. **Login**: User provides credentials → Receives both access and refresh tokens
2. **API Calls**: Use access token for protected endpoints
3. **Token Expiry**: When access token expires (2 hours), use refresh token to get new access token
4. **Refresh**: Call `/refresh` with refresh token → Receive new access token
5. **Re-authentication**: When refresh token expires (30 days), user must login again

## Security Features

- **Password Hashing**: bcrypt with salt
- **JWT Secret**: Configurable secret key for token signing
- **Input Validation**: Email format and password strength validation
- **Error Handling**: Comprehensive error handling with logging
- **Token Expiration**: Short-lived access tokens with refresh capability

## Development

### Running in Development Mode
```bash
python main.py
```

The application runs with `debug=True` in development mode.

### Database Schema

**Users Collection (`Usuarios`):**
```json
{
  "_id": "ObjectId",
  "email": "string (unique)",
  "password": "string (hashed)",
  "created_at": "datetime",
  "is_active": "boolean"
}
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `MONGODB_STRING` | MongoDB connection string | Yes | - |
| `MONGODB_DATABASE` | MongoDB database name | No | `mascarga` |
| `JWT_SECRET_KEY` | Secret key for JWT signing | Yes | `your-secret-key-change-this` |

## Error Responses

All error responses follow this format:
```json
{
  "success": false,
  "message": "Error description"
}
```

Common HTTP status codes:
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (authentication failed)
- `404`: Not Found (resource not found)
- `500`: Internal Server Error

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, create an issue in the repository.