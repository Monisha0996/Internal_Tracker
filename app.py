import os
import csv
from io import StringIO
from datetime import datetime
from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, send_from_directory, abort, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, text

# ================== App & DB Config ==================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'app.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024  # 30MB

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ================== Models ==================
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user")  # 'admin', 'manager', 'user'
    department_id = db.Column(db.Integer, db.ForeignKey("department.id"), nullable=True)
    department = db.relationship("Department", backref="users")

    # Soft-activation + permission to create tasks (grantable by admin)
    is_active_flag = db.Column(db.Boolean, default=True, nullable=False)
    can_create_task = db.Column(db.Boolean, default=False, nullable=False)

    def is_active(self):
        return bool(self.is_active_flag)

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    department_id = db.Column(db.Integer, db.ForeignKey("department.id"), nullable=False)
    department = db.relationship("Department", backref="tasks")

    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assignee = db.relationship("User", foreign_keys=[assignee_id])

    assigner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assigner = db.relationship("User", foreign_keys=[assigner_id])

    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), default="OPEN")  # OPEN, IN_PROGRESS, COMPLETED, REJECTED
    is_hidden = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TaskUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    task = db.relationship(
        "Task",
        backref=db.backref("updates", order_by="TaskUpdate.created_at.desc()")
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User")

    status = db.Column(db.String(20), default="COMMENT")  # COMMENT, PROOF, COMPLETED, REJECTED
    comment = db.Column(db.Text, nullable=True)
    attachment_path = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ================== Utilities / Guards ==================
def require_admin():
    if not current_user.is_authenticated or current_user.role != "admin":
        abort(403)


def require_assign_permission():
    """
    Users allowed to create/assign tasks:
      - Admin
      - Manager
      - Any user with can_create_task=True (granted by admin)
    """
    if not current_user.is_authenticated:
        abort(403)
    if current_user.role in ("admin", "manager"):
        return
    if getattr(current_user, "can_create_task", False):
        return
    abort(403)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {
        "png", "jpg", "jpeg", "pdf", "doc", "docx", "xlsx",
        "ppt", "pptx", "txt", "csv", "zip"
    }


def _ensure_runtime_columns():
    """
    Safety helper for older SQLite DBs created before adding new columns.
    Adds columns if missing: user.is_active_flag, user.can_create_task, task.is_hidden
    Harmless if already present. Only runs on SQLite.
    """
    try:
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///"):
            info_user = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
            user_cols = {row[1] for row in info_user}
            if "is_active_flag" not in user_cols:
                db.session.execute(text(
                    "ALTER TABLE user ADD COLUMN is_active_flag INTEGER DEFAULT 1 NOT NULL"
                ))
            if "can_create_task" not in user_cols:
                db.session.execute(text(
                    "ALTER TABLE user ADD COLUMN can_create_task INTEGER DEFAULT 0 NOT NULL"
                ))

            info_task = db.session.execute(text("PRAGMA table_info(task)")).fetchall()
            task_cols = {row[1] for row in info_task}
            if "is_hidden" not in task_cols:
                db.session.execute(text(
                    "ALTER TABLE task ADD COLUMN is_hidden INTEGER DEFAULT 0 NOT NULL"
                ))

            db.session.commit()
    except Exception as e:
        print("[WARN] Column ensure failed:", e)


# ================== Auth & Setup ==================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(pw) and user.is_active():
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid credentials or inactive account.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if User.query.first():
        return redirect(url_for("login"))
    if request.method == "POST":
        dept_name = request.form.get("dept", "Operations").strip() or "Operations"
        d = Department(name=dept_name)
        db.session.add(d)

        admin_email = request.form["email"].strip().lower()
        admin_pw = request.form["password"]
        admin = User(name="Admin", email=admin_email, role="admin", department=d)
        admin.set_password(admin_pw)
        db.session.add(admin)
        db.session.commit()
        flash("Setup complete. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("setup.html")


# ================== Dashboard (Your / Assigned / Department View) ==================
@app.route("/")
@login_required
def index():
    show_hidden = request.args.get("show_hidden", "0") == "1"
    status = request.args.get("status")
    dept = request.args.get("dept", type=int)
    active_tab = request.args.get("tab", "yours")  # 'yours' | 'assigned' | 'dept'

    def base_query():
        q = Task.query
        if current_user.role != "admin" or not show_hidden:
            q = q.filter_by(is_hidden=False)
        if status and status != "ALL":
            q = q.filter_by(status=status)
        if active_tab == "dept" and dept:
            q = q.filter_by(department_id=dept)
        return q.order_by(Task.created_at.desc())

    your_tasks = base_query().filter(Task.assignee_id == current_user.id).all()
    assigned_tasks = base_query().filter(Task.assigner_id == current_user.id).all()
    dept_tasks = []
    if current_user.role == "admin" and active_tab == "dept" and dept:
        dept_tasks = base_query().all()

    departments = Department.query.order_by(Department.name).all()
    return render_template(
        "dashboard.html",
        your_tasks=your_tasks,
        assigned_tasks=assigned_tasks,
        dept_tasks=dept_tasks,             # for Department View tab
        departments=departments,
        selected_status=status or "ALL",
        selected_dept=dept or 0,
        show_hidden=show_hidden,
        active_tab=active_tab,
        dept_mode=False,
        current_department=None
    )


@app.route("/filter")
@login_required
def filter_tasks():
    return index()


# ================== Departments ==================
@app.route("/departments", methods=["GET", "POST"])
@login_required
def departments():
    require_admin()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Department name required.", "warning")
        elif Department.query.filter_by(name=name).first():
            flash("Department already exists.", "warning")
        else:
            db.session.add(Department(name=name))
            db.session.commit()
            flash("Department added.", "success")
        return redirect(url_for("departments"))
    return render_template(
        "departments.html",
        departments=Department.query.order_by(Department.name).all()
    )


@app.route("/departments/<int:dept_id>/rename", methods=["POST"])
@login_required
def rename_department(dept_id):
    require_admin()
    d = Department.query.get_or_404(dept_id)
    new_name = (request.form.get("name") or "").strip()
    if not new_name:
        flash("Department name cannot be empty.", "warning")
        return redirect(url_for("departments"))
    exists = Department.query.filter(Department.id != d.id, Department.name == new_name).first()
    if exists:
        flash("Another department already uses that name.", "danger")
        return redirect(url_for("departments"))
    d.name = new_name
    db.session.commit()
    flash("Department renamed.", "success")
    return redirect(url_for("departments"))


@app.route("/departments/<int:dept_id>/delete", methods=["POST"])
@login_required
def delete_department(dept_id):
    require_admin()
    d = Department.query.get_or_404(dept_id)
    has_users = User.query.filter_by(department_id=d.id).count()
    has_tasks = Task.query.filter_by(department_id=d.id).count()
    if has_users or has_tasks:
        flash("Cannot delete: department has users or tasks. Reassign or remove them first.", "danger")
        return redirect(url_for("departments"))
    db.session.delete(d)
    db.session.commit()
    flash("Department deleted.", "success")
    return redirect(url_for("departments"))


@app.route("/departments/<int:dept_id>/dashboard")
@login_required
def department_dashboard(dept_id):
    require_admin()
    d = Department.query.get_or_404(dept_id)

    status = request.args.get("status")
    show_hidden = request.args.get("show_hidden", "0") == "1"

    q = Task.query.filter(Task.department_id == d.id)
    if not show_hidden:
        q = q.filter_by(is_hidden=False)
    if status and status != "ALL":
        q = q.filter_by(status=status)

    tasks = q.order_by(Task.created_at.desc()).all()
    departments = Department.query.order_by(Department.name).all()

    return render_template(
        "dashboard.html",
        your_tasks=None,
        assigned_tasks=None,
        dept_tasks=tasks,
        departments=departments,
        selected_status=status or "ALL",
        selected_dept=d.id,
        show_hidden=show_hidden,
        active_tab="dept",
        dept_mode=True,
        current_department=d
    )


# ================== Users ==================
@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    require_admin()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        dept_id = request.form.get("department_id", type=int)
        role = request.form.get("role", "user")
        pw = request.form.get("password", "ChangeMe123!")

        if not name or not email or not dept_id:
            flash("Name, Email, and Department are required.", "warning")
            return redirect(url_for("users"))

        if User.query.filter_by(email=email).first():
            flash("Email already in use.", "warning")
        else:
            u = User(name=name, email=email, role=role, department_id=dept_id)
            u.set_password(pw)
            db.session.add(u)
            db.session.commit()
            flash("User created.", "success")
        return redirect(url_for("users"))

    users_list = User.query.order_by(User.name).all()
    departments = Department.query.order_by(Department.name).all()
    return render_template("users.html", users=users_list, departments=departments)


@app.route("/users/<int:user_id>/deactivate", methods=["POST"])
@login_required
def deactivate_user(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("users"))
    user.is_active_flag = False
    db.session.commit()
    flash("User deactivated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reactivate", methods=["POST"])
@login_required
def reactivate_user(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)
    user.is_active_flag = True
    db.session.commit()
    flash("User reactivated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("users"))

    related_tasks = Task.query.filter(
        or_(Task.assignee_id == user.id, Task.assigner_id == user.id)
    ).count()
    related_updates = TaskUpdate.query.filter(
        TaskUpdate.user_id == user.id
    ).count()

    if related_tasks or related_updates:
        flash("Cannot delete: user has linked tasks/updates. Deactivate instead.", "danger")
        return redirect(url_for("users"))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted permanently.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/toggle-create", methods=["POST"])
@login_required
def toggle_user_create(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id and u.role != "admin":
        flash("You cannot change your own permission here.", "warning")
        return redirect(url_for("users"))
    u.can_create_task = not bool(u.can_create_task)
    db.session.commit()
    flash(("Granted" if u.can_create_task else "Revoked") + " task creation permission.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
def change_user_role(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)

    new_role = (request.form.get("role") or "user").strip().lower()
    if new_role not in ("admin", "manager", "user"):
        flash("Invalid role.", "danger")
        return redirect(url_for("users"))

    if user.id == current_user.id:
        flash("Change your own role via a dedicated profile flow.", "warning")
        return redirect(url_for("users"))

    was_admin = (user.role == "admin")
    demoting_admin = was_admin and (new_role != "admin")
    if demoting_admin:
        remaining_admins = User.query.filter(
            User.role == "admin",
            User.is_active_flag == True,
            User.id != user.id
        ).count()
        if remaining_admins == 0:
            flash("Cannot demote: this is the last active admin.", "danger")
            return redirect(url_for("users"))

    user.role = new_role
    db.session.commit()
    flash(f"Role updated to '{new_role}' for {user.email}.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
@login_required
def admin_change_user_password(user_id):
    require_admin()
    user = User.query.get_or_404(user_id)

    new_pw = (request.form.get("new_password") or "").strip()
    confirm_pw = (request.form.get("confirm_password") or "").strip()

    if not new_pw or not confirm_pw:
        flash("New password and confirm password are required.", "warning")
        return redirect(url_for("users"))
    if new_pw != confirm_pw:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("users"))
    if len(new_pw) < 8:
        flash("Password must be at least 8 characters.", "warning")
        return redirect(url_for("users"))

    user.set_password(new_pw)
    db.session.commit()
    flash(f"Password updated for {user.email}.", "success")
    return redirect(url_for("users"))


# ---- Admin: view a user's profile with two tabs + CSV ----
@app.route("/users/<int:user_id>/profile")
@login_required
def user_profile(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)

    dept = request.args.get("dept", type=int)
    show_hidden = request.args.get("show_hidden", "0") == "1"
    active_tab = request.args.get("tab", "yours")  # 'yours' or 'assigned'

    def base_query():
        q = Task.query
        if not show_hidden:
            q = q.filter_by(is_hidden=False)
        if dept:
            q = q.filter_by(department_id=dept)
        return q.order_by(Task.created_at.desc())

    your_tasks = base_query().filter(Task.assignee_id == u.id).all()
    assigned_tasks = base_query().filter(Task.assigner_id == u.id).all()

    departments = Department.query.order_by(Department.name).all()
    return render_template(
        "user_profile.html",
        profile_user=u,
        your_tasks=your_tasks,
        assigned_tasks=assigned_tasks,
        departments=departments,
        selected_dept=dept or 0,
        show_hidden=show_hidden,
        active_tab=active_tab,
    )


@app.route("/users/<int:user_id>/tasks_export.csv")
@login_required
def user_tasks_export_csv(user_id):
    require_admin()
    u = User.query.get_or_404(user_id)

    which = (request.args.get("type") or "yours").lower()  # 'yours' or 'assigned'
    dept = request.args.get("dept", type=int)
    include_hidden = request.args.get("include_hidden", "0") == "1"

    q = Task.query
    if which == "yours":
        q = q.filter(Task.assignee_id == u.id)
    else:
        q = q.filter(Task.assigner_id == u.id)

    if not include_hidden:
        q = q.filter_by(is_hidden=False)
    if dept:
        q = q.filter_by(department_id=dept)

    tasks = q.order_by(Task.created_at.desc()).all()

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID","Title","Department","Assignee","Assigner","Status","Due Date","Created","Hidden"])
    for t in tasks:
        writer.writerow([
            t.id,
            t.title,
            t.department.name if t.department else "",
            t.assignee.name if t.assignee else "",
            t.assigner.name if t.assigner else "",
            t.status,
            t.due_date.isoformat() if t.due_date else "",
            t.created_at.strftime("%Y-%m-%d %H:%M"),
            "Yes" if t.is_hidden else "No"
        ])
    buf.seek(0)
    filename = f"user_{u.id}_{which}_tasks.csv"
    return Response(
        buf.read(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ================== Tasks ==================
@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def task_new():
    require_assign_permission()
    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description")
        department_id = int(request.form["department_id"])
        assignee_id = int(request.form["assignee_id"])
        due_raw = request.form.get("due_date")
        due_date = datetime.strptime(due_raw, "%Y-%m-%d").date() if due_raw else None

        t = Task(
            title=title,
            description=description,
            department_id=department_id,
            assignee_id=assignee_id,
            assigner_id=current_user.id,
            due_date=due_date,
            status="OPEN"
        )
        db.session.add(t)
        db.session.commit()

        flash("Task created & assignee notified (console).", "success")
        print(f"[NOTIFY] To:{t.assignee.email} • New Task: {t.title} • Due:{t.due_date}")
        return redirect(url_for("task_view", task_id=t.id))

    users = User.query.order_by(User.name).all()
    departments = Department.query.order_by(Department.name).all()
    return render_template("task_new.html", users=users, departments=departments)


@app.route("/tasks/<int:task_id>")
@login_required
def task_view(task_id):
    task = Task.query.get_or_404(task_id)
    if (current_user.role != "admin" and
        current_user.id not in (task.assignee_id, task.assigner_id) and
            current_user.department_id != task.department_id):
        abort(403)
    if task.is_hidden and current_user.role != "admin":
        abort(403)
    return render_template("task_view.html", task=task)


@app.route("/tasks/<int:task_id>/update", methods=["POST"])
@login_required
def task_update(task_id):
    task = Task.query.get_or_404(task_id)
    # Only admin or assignee can post updates/proofs
    if current_user.role != "admin" and current_user.id != task.assignee_id:
        abort(403)

    status = request.form.get("status", "COMMENT")
    comment = request.form.get("comment")

    attachment_path = None
    file = request.files.get("attachment")
    if file and file.filename:
        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            flash("File type not allowed.", "danger")
            return redirect(url_for("task_view", task_id=task.id))
        save_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], save_name)
        file.save(save_path)
        attachment_path = os.path.basename(save_path)

    tu = TaskUpdate(
        task_id=task.id,
        user_id=current_user.id,
        status=status,
        comment=comment,
        attachment_path=attachment_path
    )
    db.session.add(tu)

    if status == "COMPLETED":
        task.status = "COMPLETED"
    elif status == "REJECTED":
        task.status = "REJECTED"
    elif status == "PROOF":
        task.status = "IN_PROGRESS"

    db.session.commit()
    flash("Update posted.", "success")
    return redirect(url_for("task_view", task_id=task.id))


# ---- Task Admin Actions ----
@app.route("/tasks/<int:task_id>/hide", methods=["POST"])
@login_required
def task_hide(task_id):
    require_admin()
    t = Task.query.get_or_404(task_id)
    t.is_hidden = True
    db.session.commit()
    flash("Task hidden.", "success")
    return redirect(url_for('index'))


@app.route("/tasks/<int:task_id>/unhide", methods=["POST"])
@login_required
def task_unhide(task_id):
    require_admin()
    t = Task.query.get_or_404(task_id)
    t.is_hidden = False
    db.session.commit()
    flash("Task unhidden.", "success")
    return redirect(url_for('index'))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def task_delete(task_id):
    require_admin()
    t = Task.query.get_or_404(task_id)
    for u in list(t.updates):
        db.session.delete(u)
    db.session.delete(t)
    db.session.commit()
    flash("Task deleted permanently.", "success")
    return redirect(url_for('index'))


# ---- Export all tasks (admin; respects filters) ----
@app.route("/tasks/export.csv")
@login_required
def tasks_export_csv():
    require_admin()
    status = request.args.get("status")
    dept = request.args.get("dept", type=int)
    include_hidden = request.args.get("include_hidden", "0") == "1"

    q = Task.query
    if not include_hidden:
        q = q.filter_by(is_hidden=False)
    if status and status != "ALL":
        q = q.filter_by(status=status)
    if dept:
        q = q.filter_by(department_id=dept)
    tasks = q.order_by(Task.created_at.desc()).all()

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Title", "Department", "Assignee", "Assigner",
                     "Status", "Due Date", "Created", "Hidden"])
    for t in tasks:
        writer.writerow([
            t.id,
            t.title,
            t.department.name if t.department else "",
            t.assignee.name if t.assignee else "",
            t.assigner.name if t.assigner else "",
            t.status,
            t.due_date.isoformat() if t.due_date else "",
            t.created_at.strftime("%Y-%m-%d %H:%M"),
            "Yes" if t.is_hidden else "No"
        ])
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=tasks_export.csv"}
    )


# ================== File serving ==================
@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


# ================== App bootstrap ==================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        _ensure_runtime_columns()
    app.run(debug=True)
