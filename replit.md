# SecureTally - Secure Financial Ledger System

## Overview

SecureTally is a web application built with Flask that provides a secure financial ledger system with a unique dual-view functionality. The system allows users to maintain two different sets of financial data (real and dummy) that can be accessed with different passwords, providing plausible deniability for sensitive financial information.

The application features user authentication, ledger management, transaction tracking, and connection management between users. It also includes an admin interface for user administration.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

SecureTally follows a traditional Model-View-Controller (MVC) architecture implemented with Flask:

- **Models**: SQLAlchemy ORM models define the database schema
- **Views**: Jinja2 templates render the UI with Bootstrap for styling
- **Controllers**: Flask routes handle request processing and business logic

### Key Architectural Decisions

1. **Dual-View System**
   - Each user has two passwords (real and dummy)
   - System maintains two sets of data views that can be toggled
   - Provides plausible deniability for sensitive financial information

2. **Flask + SQLAlchemy Stack**
   - Flask provides a lightweight framework suitable for this application
   - SQLAlchemy offers robust ORM capabilities for database operations
   - Flask-Login handles authentication and session management

3. **Relational Database**
   - SQLite in development (configurable via DATABASE_URL)
   - Can be switched to PostgreSQL in production (supported in deployment)

4. **Security-First Design**
   - Password hashing using Werkzeug's security functions
   - Admin-only routes protected with custom decorators
   - User connections require explicit approval

## Key Components

### 1. Authentication System

- **User Model**: Stores user credentials including dual passwords (real/dummy)
- **LoginManager**: Manages user sessions and authentication
- **Admin Controls**: Special admin user with system management capabilities

### 2. Ledger Management

- **Ledger Model**: Represents financial ledgers owned by users
- **LedgerEntry Model**: Stores individual financial transactions
- **Dual-View Toggle**: Determines which data set (real/dummy) to display

### 3. User Connections

- **Connection Model**: Represents relationships between users
- **Request/Approval Flow**: Structured process for establishing connections
- **Connected Transactions**: Allows recording transactions between connected users

### 4. Admin Dashboard

- **User Management**: Create, view, and manage user accounts
- **System Monitoring**: View system statistics and activity
- **User Creation**: Special admin-only workflow for creating new users with dual passwords

### 5. UI Components

- **Bootstrap Framework**: Provides responsive design and consistent styling
- **Font Awesome**: Supplies iconography throughout the interface
- **Chart.js**: Generates data visualizations for financial information

## Data Flow

1. **Authentication Flow**
   - User submits login credentials
   - System checks against real or dummy password
   - Sets appropriate view mode based on which password was used
   - Redirects to dashboard with corresponding data view

2. **Ledger Management Flow**
   - User creates/edits ledgers
   - System stores ledger data in appropriate real/dummy tables
   - User adds transactions to ledgers
   - Balance calculations update based on transaction entries

3. **Connection Flow**
   - User sends connection request
   - Target user approves/rejects request
   - Upon approval, users can record transactions with each other

## External Dependencies

### Frontend
- **Bootstrap**: UI framework for responsive design
- **Chart.js**: JavaScript library for data visualization
- **Font Awesome**: Icon library

### Backend
- **Flask**: Web framework
- **Flask-SQLAlchemy**: ORM for database operations
- **Flask-Login**: Authentication management
- **Flask-WTF**: Form handling and validation
- **Werkzeug**: Utilities including password hashing
- **SQLAlchemy**: Database ORM
- **Gunicorn**: WSGI HTTP server for production

## Deployment Strategy

The application is configured for deployment on Replit with the following characteristics:

1. **Database**
   - Uses SQLite by default (configurable)
   - Supports PostgreSQL for production (configured in .replit)

2. **Web Server**
   - Gunicorn serves the application
   - Configured to bind to port 5000
   - Supports auto-scaling through Replit's deployment system

3. **Environment Variables**
   - `DATABASE_URL`: Database connection string
   - `SESSION_SECRET`: Secret key for session security

4. **Replit Configuration**
   - Python 3.11 runtime
   - Required packages installed through pyproject.toml
   - PostgreSQL support enabled through Nix packages

5. **Run Button Workflow**
   - Configured to start the application with Gunicorn
   - Includes options for development and production modes

The application can be started locally with `python main.py` for development or deployed on Replit with the configured workflows.