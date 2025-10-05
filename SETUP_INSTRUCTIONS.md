# VoteHub - Setup and Run Instructions

## Quick Start

### 1. Install Dependencies
\`\`\`bash
pip install -r requirements.txt
\`\`\`

### 2. Run the Application
\`\`\`bash
python app.py
\`\`\`

### 3. Access the System

**Homepage:**
- URL: `http://localhost:5000`

**Admin Portal:**
- URL: `http://localhost:5000/admin/login`
- Username: `admin`
- Password: `Admin@2024`

**Voter Portal:**
- URL: `http://localhost:5000/voter/login`
- Use Voter IDs created by admin

## Important Notes

### If You Get Template Errors:

1. **Stop the Flask application** (Press Ctrl+C in terminal)
2. **Delete the database** (optional, for fresh start):
   \`\`\`bash
   rm votehub.db
   \`\`\`
3. **Restart the application**:
   \`\`\`bash
   python app.py
   \`\`\`

### Database Location
The SQLite database file `votehub.db` will be created automatically in the project root directory.

### First Time Setup

1. Login as admin using the default credentials
2. Create voter IDs from the admin dashboard
3. Distribute voter credentials to users
4. Create elections and add candidates
5. Voters can now login and vote

## Features

### Admin Features:
- Create individual or bulk voter IDs
- Manage elections (create, edit, view)
- Add candidates to elections
- View real-time results and analytics
- Access comprehensive audit logs
- Manage voter accounts

### Voter Features:
- Secure login with unique Voter ID
- View active, upcoming, and past elections
- Cast votes securely (one vote per election)
- View live results
- Change password
- Mobile-responsive interface

## Security Features

- Password hashing with Werkzeug
- Unique voter ID generation (VH-XXXXXX format)
- Session management
- IP address logging
- Comprehensive audit trail
- One vote per voter enforcement
- Election time controls

## Troubleshooting

### Template Not Found Error
This means Flask needs to be restarted. Stop the app (Ctrl+C) and run `python app.py` again.

### Database Locked Error
Close all connections to the database and restart the application.

### Port Already in Use
Change the port in app.py:
\`\`\`python
app.run(debug=True, host='0.0.0.0', port=5001)  # Change 5000 to 5001
\`\`\`

## Production Deployment

For production use:
1. Change the SECRET_KEY in app.py to a secure random value
2. Set `debug=False` in app.run()
3. Use a production WSGI server like Gunicorn
4. Use PostgreSQL instead of SQLite for better performance
5. Enable HTTPS
6. Set up proper backup procedures

## Support

For issues or questions, check the audit logs in the admin panel for detailed activity tracking.
