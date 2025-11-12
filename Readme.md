# Authentication Microservice

A Node.js backend microservice providing comprehensive authentication and authorization functionality.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Features](#features)
- [API Endpoints](#api-endpoints)
- [Environment Variables](#environment-variables)
- [Setup & Installation](#setup--installation)
- [Known Issues & Bugs Fixed](#known-issues--bugs-fixed)
- [Suggested Improvements](#suggested-improvements)
- [Security Best Practices](#security-best-practices)
- [Development Guidelines](#development-guidelines)

## Project Overview

This authentication microservice provides a robust foundation for user authentication, including registration, login, email verification, password reset, and session management. The service is built following RESTful principles and implements industry-standard security practices.

## Architecture

### Current Architecture Pattern

The project follows a **Layered Architecture (N-Tier Architecture)** pattern, which is well-suited for Node.js microservices:

```
┌─────────────────────────────────────┐
│         Client Layer                │
│     (API Consumers)                 │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Route Layer (API Routes)       │
│  - Request routing                  │
│  - Route definitions                │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Middleware Layer                  │
│  - Authentication                    │
│  - Input validation                  │
│  - Error handling                    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Controller Layer                  │
│  - Business logic                    │
│  - Request/Response handling         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Model Layer                       │
│  - Data models (Mongoose)           │
│  - Database schema definitions      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Database Layer                    │
│  - MongoDB connection                │
│  - Data persistence                 │
└──────────────────────────────────────┘
```

### Architecture Components

#### 1. **Request Flow**
```
HTTP Request → Routes → Middleware → Controllers → Models → Database
                                           ↓
HTTP Response ← Routes ← Middleware ← Controllers
```

#### 2. **Middleware Chain**
- **CORS Middleware**: Handles cross-origin requests
- **Cookie Parser**: Parses cookies from requests
- **Body Parser**: Parses JSON and URL-encoded bodies
- **Validation Middleware**: Validates input using express-validator
- **Authentication Middleware**: Verifies JWT tokens
- **Error Handling Middleware**: Catches and formats errors

#### 3. **Security Layers**
- Password hashing (bcrypt)
- JWT token-based authentication
- Token expiry management
- Secure cookie handling
- Input validation and sanitization

## Technology Stack

### Core Technologies
- **Node.js**: Runtime environment
- **Express.js 5.x**: Web framework
- **MongoDB**: Database
- **Mongoose**: ODM (Object Document Mapper)

### Security & Authentication
- **jsonwebtoken**: JWT token generation and verification
- **bcryptjs**: Password hashing
- **crypto**: Cryptographic operations (token generation)

### Validation & Utilities
- **express-validator**: Request validation
- **dotenv**: Environment variable management
- **cookie-parser**: Cookie handling
- **cors**: Cross-origin resource sharing

### Email Services (Prepared)
- **nodemailer**: Email sending
- **mailgen**: Email template generation

## Project Structure

```
src/
├── app.js                    # Express app configuration
├── index.js                  # Application entry point
├── controllers/              # Business logic layer
│   ├── auth.controllers.js   # Authentication controllers
│   └── healthcheck.controllers.js
├── routes/                   # Route definitions
│   ├── auth.routes.js
│   └── healthcheck.routes.js
├── middlewares/              # Custom middlewares
│   ├── auth.middleware.js   # JWT authentication
│   └── validator.middleware.js # Input validation
├── models/                   # Database models
│   └── user.models.js       # User schema
├── validators/               # Validation rules
│   └── index.js
├── utils/                    # Utility functions
│   ├── api-error.js         # Custom error class
│   ├── api-response.js      # Standardized responses
│   ├── async-handler.js    # Async error handler
│   ├── constants.js         # Application constants
│   └── mail.js              # Email utilities
└── db/                      # Database configuration
    └── index.js            # MongoDB connection
```

## Features

### Implemented Features
- ✅ User registration with email validation
- ✅ User login with JWT authentication
- ✅ Email verification (token-based)
- ✅ Password reset functionality
- ✅ Protected routes with authentication middleware
- ✅ Secure password hashing (bcrypt)
- ✅ Refresh token support
- ✅ Input validation
- ✅ Error handling
- ✅ Health check endpoint

### Pending Features
- ⏳ Email sending (nodemailer integration)
- ⏳ Token refresh endpoint
- ⏳ Rate limiting
- ⏳ Logging system
- ⏳ API documentation (Swagger/OpenAPI)

## API Endpoints

### Authentication Routes (`/api/v1/auth`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/register` | Register new user | No |
| POST | `/login` | User login | No |
| GET | `/me` | Get current user profile | Yes |
| GET | `/verify/:token` | Verify email address | No |
| GET | `/logout` | Logout user | Yes |
| POST | `/forgot-password` | Request password reset | No |
| POST | `/reset-password/:token` | Reset password | No |

### Health Check Routes (`/api/v1/health`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/healthcheck` | Server health status |

## Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=8000
NODE_ENV=development

# Database
MONGO_URL=mongodb://localhost:27017/authentication

ACCESS_TOKEN_SECRET=your-access-token-secret-key-here
REFRESH_TOKEN_SECRET=your-refresh-token-secret-key-here
ACCESS_TOKEN_EXPIRY=1h
REFRESH_TOKEN_EXPIRY=7d

# CORS
CORS_ORIGIN=http://localhost:3000

# Email Configuration (for email verification)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
EMAIL_FROM=noreply@yourapp.com
```

**⚠️ Security Warning**: Never commit `.env` file to version control. Use different secrets for development and production.

## Setup & Installation

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (local or cloud instance)
- npm or yarn

### Installation Steps

1. **Clone the repository**
```bash
git clone <repository-url>
cd Authentication
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure environment variables**
```bash
# Create .env file and add required variables
cp .env.example .env  # If example exists
# Edit .env with your configuration
```

4. **Start MongoDB**
```bash
# If using local MongoDB
mongod
# Or use MongoDB Atlas cloud instance
```

5. **Start the server**
```bash
npm start
```

The server will start on `http://localhost:8000` (or the port specified in `.env`).

## Known Issues & Bugs Fixed

### Bugs Fixed During Code Review

1. **❌ Incorrect Import Path in `healthcheck.routes.js`**
   - **Issue**: Import path was `healthcheckcontrollers.js` instead of `healthcheck.controllers.js`
   - **Fix**: Corrected import path with proper file naming
   - **Impact**: Application would fail to start due to module not found error

2. **❌ Wrong Route Path in `app.js`**
   - **Issue**: Route registered as `/api/v1/healthcheckRoutes` instead of standard `/api/v1/health`
   - **Fix**: Changed to conventional `/api/v1/health` path
   - **Impact**: Non-standard API paths confuse API consumers

3. **❌ Dead Code in `index.js`**
   - **Issue**: `PORT` constant declared but never used (declared after usage)
   - **Fix**: Moved constant declaration to top, removed duplicate `dotenv.config()`
   - **Impact**: Code confusion and potential maintenance issues

4. **❌ Missing Dependencies**
   - **Issue**: `jsonwebtoken` and `bcryptjs` were used but not in `package.json`
   - **Fix**: Added missing dependencies
   - **Impact**: Application would crash on runtime when importing these modules

5. **❌ Inconsistent Parameter Naming**
   - **Issue**: `ApiResponse` used `statuscode` instead of `statusCode` (camelCase)
   - **Fix**: Standardized to `statusCode` throughout
   - **Impact**: Code inconsistency and potential bugs from typos

6. **❌ Inconsistent Enum Casing**
   - **Issue**: `UserRolesEnum.Support` used lowercase instead of `SUPPORT`
   - **Fix**: Changed to `SUPPORT` for consistency
   - **Impact**: Code inconsistency

7. **❌ Missing Error Handling Middleware**
   - **Issue**: No centralized error handling middleware
   - **Fix**: Added error handling middleware in `app.js`
   - **Impact**: Unhandled errors would crash the application

8. **❌ Missing CORS and Body Parser**
   - **Issue**: CORS and body parsing not configured
   - **Fix**: Added CORS middleware and body parsers
   - **Impact**: API wouldn't accept JSON requests or handle CORS properly

9. **❌ Missing Cookie Parser**
   - **Issue**: Cookie parsing not configured, but cookies used in auth
   - **Fix**: Added `cookie-parser` middleware
   - **Impact**: `req.cookies` would be undefined, breaking token-based auth

10. **❌ Missing Auth Routes Registration**
    - **Issue**: Auth routes imported but not registered in `app.js`
    - **Fix**: Added auth routes registration
    - **Impact**: Authentication endpoints would be inaccessible

11. **❌ Empty Controller and Middleware Files**
    - **Issue**: Several critical files were empty (auth controllers, middlewares)
    - **Fix**: Implemented all missing functionality
    - **Impact**: Application would fail when routes were accessed

12. **❌ Missing Environment Variable Validation**
    - **Issue**: Database connection didn't check if `MONGO_URL` exists
    - **Fix**: Added validation before connection attempt
    - **Impact**: Cryptic errors when env variables missing

13. **❌ Missing Input Validation**
    - **Issue**: Routes didn't use validation middleware
    - **Fix**: Added express-validator with validation middleware
    - **Impact**: Invalid data could reach controllers, causing errors

## Suggested Improvements

### High Priority Improvements

#### 1. **Add Email Service Implementation**
**Current State**: Email sending is prepared but not implemented
**Recommendation**: 
- Integrate nodemailer with mailgen for email templates
- Implement email verification sending
- Implement password reset email sending
- Add email queue system for production (e.g., Bull Queue with Redis)

**Impact**: Email verification and password reset features are non-functional

#### 2. **Implement Token Refresh Endpoint**
**Current State**: Refresh tokens are generated but no endpoint to refresh access tokens
**Recommendation**:
```javascript
// Add to auth.routes.js
router.post("/refresh-token", refreshAccessToken);

// Implement refresh logic that:
// 1. Validates refresh token
// 2. Checks if user exists
// 3. Generates new access token
// 4. Returns new tokens
```

**Impact**: Users must re-login when access token expires

#### 3. **Add Rate Limiting**
**Current State**: No rate limiting implemented
**Recommendation**:
- Use `express-rate-limit` middleware
- Different limits for different endpoints:
  - Login: 5 attempts per 15 minutes
  - Registration: 3 attempts per hour
  - Password reset: 3 attempts per hour
  - General API: 100 requests per 15 minutes

**Impact**: Vulnerable to brute force attacks and abuse

#### 4. **Implement Logging System**
**Current State**: Only console.log statements
**Recommendation**:
- Use `winston` or `pino` for structured logging
- Log levels: error, warn, info, debug
- Log to files in production
- Include request IDs for tracing
- Log security events (login attempts, failed auth)

**Impact**: Difficult to debug production issues and track security events

#### 5. **Add API Documentation**
**Current State**: No API documentation
**Recommendation**:
- Integrate Swagger/OpenAPI using `swagger-ui-express`
- Document all endpoints, request/response schemas
- Include authentication examples
- Generate interactive API docs

**Impact**: Difficult for frontend developers to integrate

### Medium Priority Improvements

#### 6. **Add Request Validation for Query Parameters**
**Current State**: Only body validation implemented
**Recommendation**: Validate query params and route params using express-validator

#### 7. **Implement Refresh Token Rotation**
**Current State**: Refresh tokens are static until expiry
**Recommendation**: Rotate refresh tokens on each use for better security

#### 8. **Add User Roles and Permissions**
**Current State**: Constants exist but not implemented
**Recommendation**: Implement RBAC (Role-Based Access Control) system

#### 9. **Add Database Indexes**
**Current State**: Some indexes defined in schema
**Recommendation**: 
- Review and optimize all indexes
- Add compound indexes for common queries
- Monitor query performance

#### 10. **Implement Health Check with Database Status**
**Current State**: Basic health check only
**Recommendation**: Check database connectivity, disk space, memory usage

#### 11. **Add Request ID Middleware**
**Current State**: No request tracking
**Recommendation**: Generate unique request IDs for better debugging and log correlation

#### 12. **Implement Graceful Shutdown**
**Current State**: No shutdown handling
**Recommendation**: Handle SIGTERM/SIGINT to close connections gracefully

### Low Priority Improvements

#### 13. **Add Unit and Integration Tests**
**Recommendation**: 
- Use Jest or Mocha for testing
- Test controllers, models, utilities
- Integration tests for API endpoints
- Mock external services (email, database)

#### 14. **Add Docker Support**
**Recommendation**: Create Dockerfile and docker-compose.yml for easy deployment

#### 15. **Implement Caching Layer**
**Recommendation**: Use Redis for caching frequently accessed data (user profiles, tokens)

#### 16. **Add Metrics and Monitoring**
**Recommendation**: 
- Add Prometheus metrics
- Monitor API response times
- Track error rates
- Set up alerts

#### 17. **Implement Two-Factor Authentication (2FA)**
**Recommendation**: Add optional 2FA using TOTP (Time-based One-Time Password)

#### 18. **Add Social Authentication**
**Recommendation**: OAuth integration for Google, GitHub, etc.

#### 19. **Implement Account Lockout**
**Recommendation**: Lock accounts after multiple failed login attempts

#### 20. **Add Session Management**
**Recommendation**: Track active sessions, allow users to revoke sessions

## Security Best Practices

### Currently Implemented
✅ Password hashing with bcrypt (10 salt rounds)
✅ JWT token-based authentication
✅ Token expiry management
✅ Secure cookie settings (HttpOnly, Secure in production)
✅ Input validation and sanitization
✅ Environment variable management
✅ Password strength requirements

### Recommended Additional Security Measures

1. **HTTPS Enforcement**: Ensure all production traffic uses HTTPS
2. **Security Headers**: Add Helmet.js middleware for security headers
3. **SQL Injection Prevention**: Use parameterized queries (Mongoose handles this)
4. **XSS Protection**: Sanitize all user inputs (express-validator helps)
5. **CSRF Protection**: Implement CSRF tokens for state-changing operations
6. **Password Policy**: Enforce strong password requirements (currently basic)
7. **Account Lockout**: Prevent brute force attacks
8. **Audit Logging**: Log all security-relevant events
9. **Secrets Management**: Use secret management services in production (AWS Secrets Manager, etc.)
10. **Regular Dependency Updates**: Keep all packages updated to patch vulnerabilities

## Development Guidelines

### Code Structure Guidelines

1. **File Naming Convention**
   - Use kebab-case for file names: `auth.controllers.js`
   - Use camelCase for variable/function names: `registerUser`
   - Use UPPER_CASE for constants: `ACCESS_TOKEN_SECRET`

2. **Import Order**
   ```javascript
   // 1. External dependencies
   import express from 'express';
   import jwt from 'jsonwebtoken';
   
   // 2. Internal utilities
   import { ApiError } from '../utils/api-error.js';
   
   // 3. Internal models/services
   import { User } from '../models/user.models.js';
   ```

3. **Error Handling**
   - Always use `asyncHandler` for async controllers
   - Throw `ApiError` instances for known errors
   - Let error middleware handle response formatting

4. **Response Format**
   - Always use `ApiResponse` class for successful responses
   - Consistent error format from error middleware
   - Include status codes appropriately

5. **Security Considerations**
   - Never log sensitive data (passwords, tokens)
   - Always hash sensitive data before storing
   - Validate all user inputs
   - Use parameterized queries (Mongoose handles this)

### Important Notes for Junior Developers

The codebase includes extensive `IMPORTANT:` comments highlighting critical concepts:

- **Async Error Handling**: Always wrap async functions with `asyncHandler`
- **Password Security**: Never store plain text passwords
- **Token Management**: Always hash tokens before storing in database
- **Environment Variables**: Always validate env vars before use
- **Middleware Order**: CORS and body parsers must be before routes
- **Error Middleware**: Must be after all routes
- **Validation**: Always validate input before processing

Read these comments throughout the codebase for detailed explanations.

## Contributing

1. Follow the code structure guidelines
2. Add comments for complex logic
3. Write tests for new features
4. Update this README for significant changes
5. Follow security best practices

## License

ISC

---

**Note**: This microservice is designed to be production-ready but requires the suggested improvements (especially email service and rate limiting) before deployment to production environments.

