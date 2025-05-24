import asyncio
import datetime
import pathlib
import time
import yaml
from threading import Thread
from flask import Flask, jsonify, request, send_file
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_sqlalchemy import SQLAlchemy
from gsheets import Sheets
from google.oauth2 import service_account

app = Flask(__name__)
CORS(app)

def load_config():
    p = pathlib.Path(__file__).parent / "config.yml"
    with open(p, "r") as fh:
        return yaml.safe_load(fh)

config = load_config()

db_cfg = config["Database"]
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{db_cfg['USER']}:{db_cfg['PASSWORD']}@{db_cfg['HOST']}/{db_cfg['NAME']}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = config["General"]["JWT_SECRET_KEY"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@jwt.unauthorized_loader
def handle_no_token(msg):
    header = request.headers.get("Authorization")
    print(f"🚫 JWT missing. Authorization header = {header!r}")
    return jsonify(msg=msg), 422

@jwt.invalid_token_loader
def handle_invalid_token(msg):
    header = request.headers.get("Authorization")
    print(f"🚫 JWT invalid ({msg}). Authorization header = {header!r}")
    return jsonify(msg=msg), 422

@jwt.expired_token_loader
def handle_expired_token(jwt_header, jwt_payload):
    header = request.headers.get("Authorization")
    print(f"🚫 JWT expired. Authorization header = {header!r}")
    return jsonify(msg="Token expired"), 401

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class CallLog(db.Model):
    __tablename__ = "call_logs"
    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    number = db.Column(db.String(32), nullable=False)
    date_millis = db.Column(db.BigInteger, nullable=False)
    duration_seconds = db.Column(db.BigInteger, nullable=False)
    type = db.Column(db.Integer, nullable=False)
    presentation = db.Column(db.Integer, nullable=False)
    user = db.relationship("User", backref="calls")

@app.post("/api/register")
def register():
    d = request.get_json()
    if User.query.filter((User.username==d["username"])|(User.email==d["email"])).first():
        return jsonify(success=False, message="User/email exists"), 400
    pw = bcrypt.generate_password_hash(d["password"]).decode()
    db.session.add(User(username=d["username"], email=d["email"], password_hash=pw))
    db.session.commit()
    return jsonify(success=True, message="Registered"), 201

@app.post("/api/login")
def login():
    d = request.get_json()
    u = User.query.filter_by(email=d["email"]).first()
    if not u or not bcrypt.check_password_hash(u.password_hash, d["password"]):
        return jsonify(success=False, message="Bad credentials"), 401
    token = create_access_token(identity=str(u.id))
    return jsonify(success=True, token=token, isAdmin=u.is_admin)

@app.get("/api/me")
@jwt_required()
def me():
    raw = get_jwt_identity()
    try:
        uid = int(raw)
    except:
        return jsonify(message="Invalid identity"), 422
    u = db.session.get(User, uid)
    if u is None:
        return jsonify(message="User not found"), 404
    return jsonify(id=u.id, username=u.username, email=u.email, isAdmin=u.is_admin)

@app.post("/api/call")
@jwt_required()
def post_call():
    raw = get_jwt_identity()
    try:
        uid = int(raw)
    except:
        return jsonify(message="Invalid identity"), 422
    d = request.get_json()
    db.session.add(CallLog(
        user_id=uid,
        number=d["number"],
        date_millis=d["dateMillis"],
        duration_seconds=d["durationSecs"],
        type=d["type"],
        presentation=d["presentation"]
    ))
    db.session.commit()
    return jsonify(success=True)

@app.get("/api/stats")
@jwt_required()
def stats():
    raw = get_jwt_identity()
    try:
        uid = int(raw)
    except:
        return jsonify(message="Invalid identity"), 422
    start = request.args.get("start", type=int, default=0)
    end = request.args.get("end", type=int, default=2**63-1)
    calls = CallLog.query.filter(CallLog.user_id==uid, CallLog.date_millis.between(start, end)).all()
    total = len(calls)
    connected = sum(c.duration_seconds > 25 for c in calls)
    no_answer = [c for c in calls if c.type == 3]
    no_service = [c for c in calls if c.presentation == 3]
    return jsonify(
        total=total,
        connected=connected,
        noAnswer=len(no_answer),
        noService=len(no_service),
        noAnswerEntries=[{"number":c.number,"dateMillis":c.date_millis,"durationSecs":c.duration_seconds} for c in no_answer],
        noServiceEntries=[{"number":c.number,"dateMillis":c.date_millis,"durationSecs":c.duration_seconds} for c in no_service]
    )

@app.get("/api/admin/users")
@jwt_required()
def list_users():
    raw = get_jwt_identity()
    try:
        uid = int(raw)
    except:
        return jsonify(message="Invalid identity"), 422
    cur = db.session.get(User, uid)
    if not cur or not cur.is_admin:
        return jsonify(message="Forbidden"), 403
    return jsonify([{"id":u.id,"username":u.username,"email":u.email,"isAdmin":u.is_admin} for u in User.query.all()])

@app.post("/api/export")
@jwt_required()
def export_call_logs():
    raw = get_jwt_identity()
    try:
        uid = int(raw)
    except:
        return jsonify(message="Invalid identity"), 422
    payload = request.get_json() or []
    for d in payload:
        db.session.add(CallLog(
            user_id=uid,
            number=d["number"],
            date_millis=d["date_millis"],
            duration_seconds=d["duration_seconds"],
            type=d["type"],
            presentation=d["presentation"]
        ))
    db.session.commit()
    return jsonify(success=True)

@app.post("/api/admin/export")
@jwt_required()
def admin_export_all():
    raw = get_jwt_identity()
    try:
        uid = int(raw)
    except:
        return jsonify(message="Invalid identity"), 422
    cur = db.session.get(User, uid)
    if not cur or not cur.is_admin:
        return jsonify(message="Forbidden"), 403
    for u in User.query.all():
        for c in u.calls:
            db.session.add(CallLog(
                user_id=u.id,
                number=c.number,
                date_millis=c.date_millis,
                duration_seconds=c.duration_seconds,
                type=c.type,
                presentation=c.presentation
            ))
    db.session.commit()
    return jsonify(success=True)

def run_hourly_exports_db():
    with app.app_context():
        while True:
            for u in User.query.all():
                for c in u.calls:
                    db.session.add(CallLog(
                        user_id=u.id,
                        number=c.number,
                        date_millis=c.date_millis,
                        duration_seconds=c.duration_seconds,
                        type=c.type,
                        presentation=c.presentation
                    ))
            db.session.commit()
            time.sleep(30 * 60)

Thread(target=run_hourly_exports_db, daemon=True).start()

def get_credentials():
    creds_path = pathlib.Path(__file__).parent / config["Google"]["GOOGLE_SERVICE_ACCOUNT_FILE"]
    return service_account.Credentials.from_service_account_file(
        str(creds_path),
        scopes=['https://www.googleapis.com/auth/spreadsheets.readonly','https://www.googleapis.com/auth/drive.readonly']
    )

async def export_spreadsheet(spreadsheet_id, export_mode, column_name, txt_file_name, export_format, file_name):
    credentials = get_credentials()
    sheets = Sheets(credentials)
    spreadsheet = sheets.get(spreadsheet_id)
    sheet = spreadsheet.sheets[0]
    df = sheet.to_frame(header=None).reset_index(drop=True)
    df.columns = [str(i+1) for i in range(df.shape[1])]
    if export_mode == "single_column":
        file_path = str(pathlib.Path(__file__).parent / txt_file_name)
        if column_name in df.columns:
            df[column_name].astype(str).to_csv(file_path, index=False, header=False)
        else:
            return None
    else:
        file_path = str(pathlib.Path(__file__).parent / file_name)
        if export_format == "csv":
            df.to_csv(file_path, sep='\t', index=False)
        elif export_format == "xlsx":
            df.to_excel(file_path, index=False)
        else:
            return None
    return file_path

async def initial_export():
    for sc in config["Spreadsheets"]:
        await export_spreadsheet(
            sc["GOOGLE_SPREADSHEET_ID"],
            sc["ExportMode"],
            sc.get("ColumnName",""),
            sc["TXT_FILE_NAME"],
            sc.get("ExportFormat","csv"),
            sc["FILE_NAME"]
        )

async def run_every_hour():
    while True:
        for sc in config["Spreadsheets"]:
            await export_spreadsheet(
                sc["GOOGLE_SPREADSHEET_ID"],
                sc["ExportMode"],
                sc.get("ColumnName",""),
                sc["TXT_FILE_NAME"],
                sc.get("ExportFormat","csv"),
                sc["FILE_NAME"]
            )
        await asyncio.sleep(3600)

def start_asyncio_loop():
    asyncio.run(run_every_hour())

Thread(target=start_asyncio_loop, daemon=True).start()

@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    p = pathlib.Path(__file__).parent / filename
    return send_file(str(p), as_attachment=True) if p.exists() else ("No file yet", 404)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=config["General"]["WEBSERVER_PORT"], threaded=True)