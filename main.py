import asyncio
import pathlib
import yaml
import os
from gsheets import Sheets
from flask import Flask, send_file, request, jsonify
from threading import Thread
from google.oauth2 import service_account

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import datetime

app = Flask(__name__)
CORS(app)

def load_config():
    config_path = f'{pathlib.Path(__file__).parent.absolute()}/config.yml'
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

config = load_config()

db_cfg = config["Database"]
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{db_cfg['USER']}:{db_cfg['PASSWORD']}"
    f"@{db_cfg['HOST']}/{db_cfg['NAME']}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = config["General"]["JWT_SECRET_KEY"]

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class CallLog(db.Model):
    __tablename__ = 'call_logs'
    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    number = db.Column(db.String(32), nullable=False)
    date_millis = db.Column(db.BigInteger, nullable=False)
    duration_secs = db.Column(db.BigInteger, nullable=False)
    type = db.Column(db.Integer, nullable=False)
    presentation = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref='calls')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
        return jsonify(success=False, message="User/email exists"), 400
    pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    u = User(username=data['username'], email=data['email'], password_hash=pw_hash)
    db.session.add(u); db.session.commit()
    return jsonify(success=True, message="Registered"), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, data['password']):
        return jsonify(success=False, message="Bad credentials"), 401
    token = create_access_token(identity=user.id)
    return jsonify(success=True, token=token, isAdmin=user.is_admin)

@app.route('/api/call', methods=['POST'])
@jwt_required()
def post_call():
    uid = get_jwt_identity()
    d = request.get_json()
    c = CallLog(
        user_id=uid,
        number=d['number'],
        date_millis=d['dateMillis'],
        duration_secs=d['durationSecs'],
        type=d['type'],
        presentation=d['presentation']
    )
    db.session.add(c); db.session.commit()
    return jsonify(success=True)

@app.route('/api/stats', methods=['GET'])
@jwt_required()
def stats():
    uid = get_jwt_identity()
    start = request.args.get('start', type=int, default=0)
    end = request.args.get('end', type=int, default=2**63-1)
    calls = CallLog.query.filter(
        CallLog.user_id == uid,
        CallLog.date_millis >= start,
        CallLog.date_millis <= end
    ).all()
    total = len(calls)
    connected = sum(1 for c in calls if c.duration_secs > 25)
    noAnswer = sum(1 for c in calls if c.type == 3)
    noService = sum(1 for c in calls if c.presentation == 3)
    noA = [
        {"number": c.number, "dateMillis": c.date_millis, "durationSecs": c.duration_secs}
        for c in calls if c.type == 3
    ]
    noS = [
        {"number": c.number, "dateMillis": c.date_millis, "durationSecs": c.duration_secs}
        for c in calls if c.presentation == 3
    ]
    return jsonify(
        total=total, connected=connected,
        noAnswer=noAnswer, noService=noService,
        noAnswerEntries=noA, noServiceEntries=noS
    )

@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def list_users():
    uid = get_jwt_identity()
    current = User.query.get(uid)
    if not current or not current.is_admin:
        return jsonify(message="Forbidden"), 403
    users = User.query.all()
    data = [
        {"id": u.id, "username": u.username, "email": u.email, "isAdmin": u.is_admin}
        for u in users
    ]
    return jsonify(data)

@app.route('/api/admin/users/<int:user_id>/promote', methods=['POST'])
@jwt_required()
def promote_user(user_id):
    uid = get_jwt_identity()
    current = User.query.get(uid)
    if not current or not current.is_admin:
        return jsonify(message="Forbidden"), 403
    target = User.query.get(user_id)
    if not target:
        return jsonify(success=False, message="User not found"), 404
    target.is_admin = True
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/admin/users/<int:user_id>/demote', methods=['POST'])
@jwt_required()
def demote_user(user_id):
    uid = get_jwt_identity()
    current = User.query.get(uid)
    if not current or not current.is_admin:
        return jsonify(message="Forbidden"), 403
    target = User.query.get(user_id)
    if not target:
        return jsonify(success=False, message="User not found"), 404
    target.is_admin = False
    db.session.commit()
    return jsonify(success=True)

def get_credentials():
    creds_path = os.path.join(
        pathlib.Path(__file__).parent.absolute(),
        config["Google"]["GOOGLE_SERVICE_ACCOUNT_FILE"]
    )
    return service_account.Credentials.from_service_account_file(
        creds_path,
        scopes=[
            'https://www.googleapis.com/auth/spreadsheets.readonly',
            'https://www.googleapis.com/auth/drive.readonly'
        ]
    )

async def export_spreadsheet(spreadsheet_id, export_mode, column_name, txt_file_name, export_format, file_name):
    creds = get_credentials()
    sheets = Sheets(creds)
    sheet = sheets.get(spreadsheet_id).sheets[0]
    df = sheet.to_frame(header=None).reset_index(drop=True)
    df.columns = [str(i+1) for i in range(df.shape[1])]
    if export_mode == "single_column":
        path = f'{pathlib.Path(__file__).parent}/{txt_file_name}'
        if column_name in df.columns:
            df[column_name].astype(str).to_csv(path, index=False, header=False)
        else:
            return None
    else:
        path = f'{pathlib.Path(__file__).parent}/{file_name}'
        if export_format == "csv":
            df.to_csv(path, sep='\t', index=False)
        elif export_format == "xlsx":
            df.to_excel(path, index=False)
    return path if os.path.exists(path) else None

async def run_every_hour():
    while True:
        try:
            for cfg in config["Spreadsheets"]:
                await export_spreadsheet(
                    cfg["GOOGLE_SPREADSHEET_ID"],
                    cfg["ExportMode"],
                    cfg.get("ColumnName", ""),
                    cfg["TXT_FILE_NAME"],
                    cfg.get("ExportFormat", "csv"),
                    cfg["FILE_NAME"]
                )
            await asyncio.sleep(3600)
        except Exception as e:
            print("Error in export:", e)

Thread(target=lambda: asyncio.run(run_every_hour()), daemon=True).start()

@app.route('/download/<filename>', methods=['GET'])
def download_latest_file(filename):
    path = f'{pathlib.Path(__file__).parent}/{filename}'
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "No file yet", 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(
        host='0.0.0.0',
        port=config["General"]["WEBSERVER_PORT"],
        threaded=True
    )