# Zearom QA Management System

A comprehensive Flask-based Quality Assurance management application for tracking projects, testing sessions, findings, and categories.

## Features

- **User Authentication**
  - Login with email/password
  - Google OAuth authentication
  - Pre-seeded admin account

- **Project Management**
  - Create and manage multiple projects
  - Track project descriptions and metadata
  - View project statistics

- **Testing Sessions**
  - Create testing sessions for each project
  - Track session status (Active, Completed, Archived)
  - Link multiple sessions to a project

- **Findings Management**
  - Document QA findings with title, description, and severity
  - Upload multiple screenshots per finding
  - Track finding status (Open, In Progress, Resolved, Closed)
  - Assign categories to findings

- **Category System**
  - Create reusable categories for projects
  - Color-coded categories for easy identification
  - Track who created each category

- **User Tracking**
  - Track who created each project, category, session, and finding
  - Display user information throughout the app

- **Modern UI**
  - Responsive design with Tailwind CSS
  - Sidebar navigation
  - Dashboard with statistics

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Install Dependencies

```bash
pip install flask flask-sqlalchemy flask-login authlib werkzeug pillow
```

### Step 2: Set Up Google OAuth (Optional)

To enable Google login, you need to:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:5000/callback`
6. Set environment variables:

```bash
export GOOGLE_CLIENT_ID="your-client-id-here"
export GOOGLE_CLIENT_SECRET="your-client-secret-here"
```

Or add them to your shell profile (~/.bashrc, ~/.zshrc, etc.)

### Step 3: File Structure

Create the following directory structure:

```
zearom-qa/
├── app.py                      # Main application file
├── static/
│   └── uploads/               # Screenshot uploads directory (auto-created)
└── templates/
    ├── base.html
    ├── login.html
    ├── dashboard.html
    ├── projects.html
    ├── project_form.html
    ├── project_detail.html
    ├── category_form.html
    ├── session_form.html
    ├── session_detail.html
    ├── finding_form.html
    └── finding_detail.html
```

### Step 4: Run the Application

```bash
python app.py
```

The application will:
1. Create the SQLite database (`zearom_qa.db`)
2. Create all necessary tables
3. Seed the admin user
4. Start the development server on `http://localhost:5000`

## Default Login Credentials

**Email:** Admin@Zearom.com  
**Password:** Success@Zearom

## Usage Guide

### 1. Login
- Use the default admin credentials or sign in with Google
- Google users will be automatically registered on first login

### 2. Create a Project
- Click "New Project" from the dashboard or projects page
- Enter project name and description
- Submit to create the project

### 3. Add Categories to Project
- Open a project
- Click "New Category"
- Enter category name, description, and choose a color
- Categories can be reused across all testing sessions in the project

### 4. Create Testing Session
- From the project detail page, click "New Session"
- Enter session name and description
- Sessions track specific testing periods or sprints

### 5. Add Findings
- Open a testing session
- Click "New Finding"
- Fill in finding details:
  - Title (required)
  - Description
  - Severity (Critical, High, Medium, Low)
  - Category (optional)
  - Screenshots (optional, multiple files)
- Submit to create the finding

### 6. Manage Findings
- View finding details
- Edit status and other information
- Upload additional screenshots
- Track who created the finding and when

## Database Schema

### Users
- Email, password, name
- Google OAuth flag
- Relationships: projects, categories, findings

### Projects
- Name, description
- Created by user
- Relationships: sessions, categories

### Categories
- Name, description, color
- Belongs to project
- Created by user
- Relationships: findings

### Testing Sessions
- Name, description, status
- Belongs to project
- Relationships: findings

### Findings
- Title, description, severity, status
- Belongs to session and optional category
- Created by user
- Relationships: screenshots

### Screenshots
- Filename, filepath
- Belongs to finding

## Features in Detail

### Severity Levels
- **Critical**: System-breaking issues
- **High**: Major functionality problems
- **Medium**: Moderate issues (default)
- **Low**: Minor issues or improvements

### Status Options
- **Open**: Newly reported (default)
- **In Progress**: Being worked on
- **Resolved**: Fixed but not verified
- **Closed**: Verified and closed

### Session Status
- **Active**: Currently testing
- **Completed**: Testing finished
- **Archived**: Historical record

## Security Notes

- Passwords are hashed using Werkzeug's security functions
- File uploads are limited to 16MB
- Uploaded files use secure filenames
- User sessions are managed securely with Flask-Login

## Troubleshooting

### Google OAuth Not Working
- Verify your Google Client ID and Secret are set correctly
- Ensure the callback URL matches exactly: `http://localhost:5000/callback`
- Check that the Google+ API is enabled in your project

### File Upload Issues
- Ensure the `static/uploads` directory exists and is writable
- Check file size limits (default: 16MB)
- Verify image file formats are supported

### Database Issues
- Delete `zearom_qa.db` and restart the app to reset the database
- Check write permissions in the application directory

## Contributing

This is a custom application for Zearom. For modifications or enhancements, please contact the development team.

## License

Proprietary - Zearom Internal Use Only# Zearom-QA
