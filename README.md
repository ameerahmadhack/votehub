# VoteHub - Professional Voting System

A secure, enterprise-grade voting platform built with Flask and modern web technologies.

## Features

### Admin Features
- **Voter Management**: Create individual or bulk voter IDs with secure credentials
- **Election Management**: Create and manage elections with start/end times
- **Candidate Management**: Add candidates with detailed information and manifestos
- **Real-time Analytics**: View live voting results and comprehensive statistics
- **Audit Logs**: Complete activity trail for security and compliance
- **Dashboard**: Overview of all system metrics and recent activity

### Voter Features
- **Secure Login**: Unique Voter ID authentication system
- **Election Participation**: View active, upcoming, and past elections
- **Secure Voting**: One vote per election with confirmation
- **Live Results**: View real-time election results (if enabled)
- **Password Management**: Change password for security
- **Responsive Design**: Works perfectly on all devices

### Security Features
- Unique Voter ID generation (VH-XXXXXX format)
- Password hashing with Werkzeug
- Session management
- IP address logging
- Audit trail for all actions
- One vote per voter per election enforcement
- CSRF protection

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. Install dependencies:
\`\`\`bash
pip install flask flask-sqlalchemy werkzeug
\`\`\`

2. Run the application:
\`\`\`bash
python app.py
\`\`\`

3. Access the application:
- Homepage: http://localhost:5000
- Admin Login: http://localhost:5000/admin/login
- Voter Login: http://localhost:5000/voter/login

## Default Credentials

### Admin Access
- **URL**: http://localhost:5000/admin/login
- **Username**: admin
- **Password**: Admin@2024

## Usage Guide

### For Administrators

1. **Login** to the admin panel
2. **Create Voters**:
   - Single voter: Provide name, email, phone
   - Bulk creation: Generate multiple voter IDs at once
   - Download credentials CSV for distribution
3. **Create Elections**:
   - Set title, description, start and end times
   - Add candidates with party information and manifestos
4. **Monitor Results**:
   - View real-time voting statistics
   - Access detailed analytics and charts
   - Review audit logs for security

### For Voters

1. **Login** with your Voter ID (format: VH-123456) and password
2. **View Elections**:
   - Active elections you can vote in
   - Upcoming elections
   - Past elections with results
3. **Cast Vote**:
   - Review candidate information
   - Select your preferred candidate
   - Confirm your vote (cannot be changed)
4. **View Results**: Check live results for completed elections

## Database Schema

- **Admin**: Administrator accounts
- **Voter**: Registered voters with unique IDs
- **Election**: Voting elections with time constraints
- **Candidate**: Election candidates with details
- **Vote**: Cast votes with audit information
- **AuditLog**: Complete activity trail

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML5, TailwindCSS, JavaScript
- **Charts**: Chart.js for data visualization
- **Icons**: Font Awesome
- **Security**: Werkzeug password hashing

## API Endpoints

### Admin Routes
- `/admin/login` - Admin authentication
- `/admin/dashboard` - Admin overview
- `/admin/voters` - Voter management
- `/admin/voters/create` - Create single voter
- `/admin/voters/bulk-create` - Bulk voter creation
- `/admin/elections` - Election management
- `/admin/elections/create` - Create election
- `/admin/elections/<id>/candidates` - Manage candidates
- `/admin/elections/<id>/results` - View results
- `/admin/audit-logs` - Security audit trail

### Voter Routes
- `/voter/login` - Voter authentication
- `/voter/dashboard` - Voter home
- `/voter/election/<id>` - View election details
- `/voter/vote/<election_id>/<candidate_id>` - Cast vote
- `/voter/results/<id>` - View election results
- `/voter/change-password` - Update password

### API Routes
- `/api/election/<id>/results` - JSON results data

## Security Best Practices

1. **Change Default Admin Password** immediately after first login
2. **Distribute Voter Credentials Securely** via encrypted channels
3. **Set Appropriate Election Times** to prevent premature voting
4. **Monitor Audit Logs** regularly for suspicious activity
5. **Backup Database** regularly to prevent data loss
6. **Use HTTPS** in production environments

## Production Deployment

For production use:

1. Change the `SECRET_KEY` in app.py to a secure random value
2. Use a production database (PostgreSQL, MySQL)
3. Enable HTTPS/SSL
4. Set up proper logging
5. Configure firewall rules
6. Regular security audits
7. Implement rate limiting

## Support

For issues or questions:
- Check the audit logs for system activity
- Review the README for common solutions
- Contact your system administrator

## License

This is a professional voting system. Use responsibly and in compliance with local election laws.
# votehub
