# Department Work Tracker (Flask)

A minimal web app to assign work to departments, notify assignees, collect proof, and track completion with an audit trail.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000/setup to create the first admin user and a default department.

## Features
- Admin creates departments, users, and tasks
- Assignees get notified (console print by default — swap with SMTP or WhatsApp API)
- Assignees upload proof (files/images/PDF) and mark tasks as **IN_PROGRESS** or **COMPLETED**
- Audit trail via TaskUpdate entries
- Department and status filters
- Role-based access (admin vs. user)
- File uploads saved under `/uploads`

## Env Vars (optional)
- `SECRET_KEY`
- `DATABASE_URL` (e.g., `sqlite:///app.db` or Postgres URL)
