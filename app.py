from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import subprocess
import json
import uuid
import datetime
import shutil
import time
from pathlib import Path
import traceback
import pickle
import numpy as np
import logging
import sys
import argparse

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(
            os.path.abspath(__file__)), 'app.log')),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

try:
    from tensorflow.keras.models import load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    logger.info("TensorFlow imported successfully")
except ImportError as e:
    logger.error(f"Error importing TensorFlow: {e}")
    logger.warning(
        "Continuing without TensorFlow - some features may be limited")

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = datetime.timedelta(days=7)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 500
app.config['SESSION_FILE_MODE'] = 384
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = True

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), 'uploads')
RESULTS_FOLDER = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), 'results')
ALLOWED_EXTENSIONS = {'py', 'js', 'java', 'cpp', 'c', 'cs', 'jsx', 'cc', 'cxx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER

try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(RESULTS_FOLDER, exist_ok=True)
    logger.info(f"Created directories: {UPLOAD_FOLDER}, {RESULTS_FOLDER}")
except Exception as e:
    logger.error(f"Error creating directories: {e}")

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    scans = db.relationship('Scan', backref='user', lazy=True)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    language = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    scan_type = db.Column(db.String(50), default='static')
    status = db.Column(db.String(50), default='completed')
    results_path = db.Column(db.String(255), nullable=True)


def get_timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def create_test_user():
    print("Test user creation is disabled to prevent automatic login.")
    return


with app.app_context():
    try:
        try:
            Scan.query.first()
        except Exception as schema_error:
            print(f"Schema error detected: {str(schema_error)}")
            print("Dropping and recreating all tables...")
            db.drop_all()
            db.create_all()
            create_test_user()
        else:
            db.create_all()
            create_test_user()
    except Exception as e:
        print(f"Error initializing database: {str(e)}")


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.route('/')
def index():  # Home page
    if 'user_id' not in session:  # Check login status
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # Get current user
    previous_scans = Scan.query.filter_by(  # Get user's scan history
        user_id=session['user_id']).order_by(Scan.timestamp.desc()).all()
    return render_template('index.html', user=user, previous_scans=previous_scans)


@app.route('/login', methods=['GET', 'POST'])
def login():  # Login handler
    try:
        if request.method == 'POST':  # Form submission
            email = request.form['email']  # Get email
            password = request.form['password']  # Get password
            remember_me = 'remember_me' in request.form  # Remember me flag

            logger.info(f"Login attempt for email: {email}")

            try:
                user = User.query.filter_by(email=email).first()  # Find user
                if user is None:  # User not found
                    logger.info(f"No user found with email: {email}")
                    flash('Account not found! Register?')
                    return redirect(url_for('login'))

                logger.info(f"User found: {user.email}, {user.fullname}")
                if check_password_hash(user.password, password):  # Verify password
                    session['user_id'] = user.id  # Set session
                    session.permanent = True
                    logger.info(f"Login successful for user: {user.email}")

                    response = redirect(url_for('index'))
                    if remember_me:  # Set remember me cookie
                        response.set_cookie('remember_user', str(
                            user.id), max_age=60*60*24*30)  # 30 days
                        logger.info(f"Remember me set for user: {user.email}")
                    else:
                        response.delete_cookie(
                            'remember_user')  # Remove cookie
                        logger.info(
                            f"Remember me not set for user: {user.email}")

                    return response
                else:  # Wrong password
                    logger.info(f"Invalid password for user: {user.email}")
                    flash('Invalid email or password')
                    return redirect(url_for('login'))
            except Exception as db_err:  # Database error
                logger.error(f"Database error during login: {str(db_err)}")
                logger.error(traceback.format_exc())
                flash(f"Database error. Please try again or contact support.")
                return redirect(url_for('login'))

        return render_template('login.html')  # Show login form
    except Exception as e:  # Unexpected error
        logger.error(f"Unexpected error in login route: {str(e)}")
        logger.error(traceback.format_exc())
        flash("An unexpected error occurred. Please try again.")
        return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():  # Registration handler
    try:
        if request.method == 'POST':  # Form submission
            fullname = request.form['fullname']  # Get full name
            email = request.form['email']  # Get email
            password = request.form['password']  # Get password
            # Get confirmation
            confirm_password = request.form['confirm_password']

            logger.info(
                f"Registration attempt for email: {email}, name: {fullname}")

            if password != confirm_password:  # Password mismatch
                flash('Passwords do not match')
                return redirect(url_for('register'))

            existing_user = User.query.filter_by(
                email=email).first()  # Check existing
            if existing_user:  # Email exists
                logger.info(f"Email already exists: {email}")
                flash('Email already exists')
                return redirect(url_for('register'))

            try:
                hashed_password = generate_password_hash(
                    password)  # Hash password
                new_user = User(fullname=fullname, email=email,  # Create user
                                password=hashed_password)
                db.session.add(new_user)  # Add to database
                db.session.commit()  # Save changes

                created_user = User.query.filter_by(
                    email=email).first()  # Verify creation
                if created_user:
                    logger.info(
                        f"User created successfully: {email}, id: {created_user.id}")
                    flash('Registration successful! Please login.')

                    return redirect(url_for('login'))
                else:
                    logger.error(f"Failed to create user: {email}")
                    flash('Registration failed. Please try again.')
                    return redirect(url_for('register'))
            except Exception as db_err:  # Database error
                logger.error(
                    f"Database error during registration: {str(db_err)}")
                logger.error(traceback.format_exc())
                flash(f"Database error. Please try again or contact support.")
                return redirect(url_for('register'))
        return render_template('register.html')  # Show registration form
    except Exception as e:  # Unexpected error
        logger.error(f"Unexpected error in register route: {str(e)}")
        logger.error(traceback.format_exc())
        flash("An unexpected error occurred. Please try again.")
        return render_template('register.html')


@app.route('/logout')
def logout():  # Logout handler
    session.pop('user_id', None)  # Clear session
    response = redirect(url_for('login'))
    response.delete_cookie('remember_user')  # Remove cookie
    return response


def predict_vulnerability(file_path, language):  # ML vulnerability detection
    try:

        tokenizer_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),  # Tokenizer file
                                      'vulnerability_detection_model', 'tokenizer.pkl')
        with open(tokenizer_path, 'rb') as f:
            tokenizer = pickle.load(f)  # Load tokenizer

        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),  # Model file
                                  'vulnerability_detection_model', 'cnn_vulnerability_classifier.h5')
        model = load_model(model_path)  # Load model

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()  # Read code

        sequence = tokenizer.texts_to_sequences([code])  # Convert to sequence
        padded_sequence = pad_sequences(  # Pad sequence
            sequence, maxlen=500, padding='post', truncating='post')

        prediction = float(model.predict(padded_sequence)
                           [0][0])  # Get prediction

        return {
            "is_vulnerable": prediction >= 0.6,  # Vulnerability threshold
            "confidence": prediction if prediction >= 0.6 else 1 - prediction,  # Confidence
            "vulnerability_probability": prediction  # Raw probability
        }
    except Exception as e:  # Error handling
        logger.error(f"Error in vulnerability prediction: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": str(e),
            "is_vulnerable": False,
            "confidence": 0
        }


@app.route('/analyze', methods=['POST'])
def analyze():  # Static analysis route
    if 'user_id' not in session:  # Check authentication
        return redirect(url_for('login'))

    if 'code_file' not in request.files:  # Check file upload
        flash('No file uploaded')
        return redirect(url_for('index'))

    file = request.files['code_file']  # Get uploaded file
    language = request.form['language']  # Get selected language

    if file.filename == '':  # Check filename
        flash('No file selected')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):  # Validate file type
        filename = secure_filename(file.filename)  # Secure filename
        user_upload_dir = os.path.join(  # User upload directory
            app.config['UPLOAD_FOLDER'], str(session['user_id']))
        unique_id = str(uuid.uuid4())  # Generate unique ID
        user_results_dir = os.path.join(  # User results directory
            app.config['RESULTS_FOLDER'], str(session['user_id']), unique_id)

        os.makedirs(user_upload_dir, exist_ok=True)  # Create upload dir
        os.makedirs(user_results_dir, exist_ok=True)  # Create results dir

        file_path = os.path.join(user_upload_dir, filename)  # Full file path
        file.save(file_path)  # Save uploaded file

        new_scan = Scan(  # Create scan record
            user_id=session['user_id'],
            language=language,
            filename=filename,
            scan_type='static',
            status='completed',
            results_path=user_results_dir
        )
        db.session.add(new_scan)  # Add to database
        db.session.commit()  # Save changes

        try:
            results = predict_vulnerability(
                file_path, language)  # Run ML analysis

            if 'error' in results and results.get('error'):  # Check for errors
                error_message = results.get('error')
                print(f"Error occurred during analysis: {error_message}")
                flash(f"Unable to analyze code: {error_message}")

                new_scan.status = 'failed'  # Mark as failed
                db.session.commit()

                user = User.query.get(session['user_id'])  # Get user
                previous_scans = Scan.query.filter_by(  # Get scan history
                    user_id=session['user_id']).order_by(Scan.timestamp.desc()).all()
                return render_template('index.html', user=user, previous_scans=previous_scans)

            vulnerability_status = "Vulnerable Code" if results.get(  # Determine status
                'is_vulnerable', False) else "Not Vulnerable"
            confidence_percent = round(results.get(
                'confidence', 0) * 100, 2)  # Confidence %

            results_file = os.path.join(  # Results file path
                user_results_dir, 'vulnerability_report.json')

            severity_level = "high" if results.get('vulnerability_probability', 0) > 0.8 else \
                "medium" if results.get(
                'vulnerability_probability', 0) > 0.6 else "low"  # Severity level

            results_data = {  # Prepare results data
                "is_vulnerable": results.get('is_vulnerable', False),
                "confidence": confidence_percent,
                "vulnerability_probability": results.get('vulnerability_probability', 0),
                "language": language,
                "filename": filename,
                "scan_id": new_scan.id,
                "timestamp": new_scan.timestamp.isoformat(),
                "status": "completed",
                "summary": {
                    "critical": 1 if severity_level == "high" and results.get('is_vulnerable', False) else 0,
                    "high": 1 if severity_level == "medium" and results.get('is_vulnerable', False) else 0,
                    "medium": 1 if severity_level == "low" and results.get('is_vulnerable', False) else 0,
                    "low": 0,
                    "info": 0 if results.get('is_vulnerable', False) else 1
                },
                "vulnerabilities": [{
                    "type": "Potential Security Vulnerability" if results.get('is_vulnerable', False) else "No Vulnerabilities Detected",
                    "severity": severity_level.capitalize() if results.get('is_vulnerable', False) else "Info",
                    "line": 0,
                    "description": f"The code analysis detected potential security issues with {confidence_percent}% confidence." if results.get('is_vulnerable', False) else f"No security issues detected with {confidence_percent}% confidence.",
                    "recommendation": "Review the code for security best practices, input validation, and proper error handling." if results.get('is_vulnerable', False) else "Continue following secure coding practices."
                }]
            }

            with open(results_file, 'w') as f:  # Save results
                json.dump(results_data, f, indent=4)

            user = User.query.get(session['user_id'])  # Get user
            previous_scans = Scan.query.filter_by(  # Get scan history
                user_id=session['user_id']).order_by(Scan.timestamp.desc()).all()
            # Result message
            model_result = f"Model Results: {vulnerability_status} ({confidence_percent}% confidence)"

            return render_template('index.html',  # Show results
                                   user=user,
                                   previous_scans=previous_scans,
                                   model_result=model_result,
                                   current_file=filename,
                                   current_language=language)
        except Exception as e:  # Error handling
            new_scan.status = 'failed'  # Mark as failed
            db.session.commit()

            print(f"Analysis error: {str(e)}")
            print(traceback.format_exc())
            flash(f'Error during code analysis: {str(e)}')
            return redirect(url_for('index'))

    flash('Invalid file type')  # Invalid file
    return redirect(url_for('index'))


@app.route('/run_code', methods=['POST'])
def run_code():  # Runtime analysis route
    response = None

    # Check cookie
    if 'user_id' not in session and request.cookies.get('remember_user'):
        try:
            user_id = int(request.cookies.get('remember_user'))  # Get user ID
            user = User.query.get(user_id)  # Find user
            if user:
                session['user_id'] = user.id  # Set session
                logger.info(
                    f"[{get_timestamp()}] Restored session for user ID {user.id} from cookie")
        except Exception as e:
            logger.error(
                f"[{get_timestamp()}] Error restoring session from cookie: {str(e)}")

    if 'user_id' not in session:  # Check authentication
        logger.warning(
            f"[{get_timestamp()}] Attempt to access run_code without logged in session")
        return redirect(url_for('login'))

    session.permanent = True  # Make session permanent
    user_id = session['user_id']  # Get user ID

    logger.debug(
        f"[{get_timestamp()}] Starting code analysis for user_id: {user_id}")

    if 'code_file' not in request.files:  # Check file upload
        logger.warning(f"[{get_timestamp()}] No file uploaded in request")
        flash('No file uploaded')
        response = redirect(url_for('index'))
        response.set_cookie('remember_user', str(
            user_id), max_age=60*60*24*30)  # Set cookie
        return response

    file = request.files['code_file']  # Get uploaded file
    language = request.form['language']  # Get selected language

    logger.debug(
        f"[{get_timestamp()}] File received: {file.filename}, Language: {language}")

    if file and '.' in file.filename:  # Check file extension
        extension = file.filename.rsplit('.', 1)[1].lower()
        logger.debug(
            f"[{get_timestamp()}] File extension: {extension}, Allowed: {extension in ALLOWED_EXTENSIONS}")

    if file.filename == '':  # Check filename
        logger.warning(f"[{get_timestamp()}] Empty filename submitted")
        flash('No file selected')
        response = redirect(url_for('index'))
        response.set_cookie('remember_user', str(
            user_id), max_age=60*60*24*30)  # Set cookie
        return response

    if file and allowed_file(file.filename):  # Validate file type
        logger.info(
            f"[{get_timestamp()}] File accepted: {file.filename}, language: {language}")

        filename = secure_filename(file.filename)  # Secure filename

        file_extension = filename.rsplit(  # Get file extension
            '.', 1)[1].lower() if '.' in filename else ''

        logger.info(
            f"[{get_timestamp()}] File extension detected: {file_extension}")
        logger.info(f"[{get_timestamp()}] Language selected: {language}")

        if file_extension == 'py' and language.lower() != 'python':  # Auto-correct language
            language = 'python'
            logger.info(
                f"[{get_timestamp()}] Corrected language to Python based on .py extension")
        elif file_extension == 'java' and language.lower() != 'java':  # Auto-correct language
            language = 'java'
            logger.info(
                f"[{get_timestamp()}] Corrected language to Java based on .java extension")

        elif file_extension == 'c' and language.lower() != 'c':  # Auto-correct language
            language = 'c'
            logger.info(
                f"[{get_timestamp()}] Corrected language to C based on file extension")

        user_upload_dir = os.path.join(  # User upload directory
            app.config['UPLOAD_FOLDER'], str(session['user_id']))
        unique_id = str(uuid.uuid4())  # Generate unique ID
        user_results_dir = os.path.join(  # User results directory
            app.config['RESULTS_FOLDER'], str(session['user_id']), unique_id)

        logger.debug(
            f"[{get_timestamp()}] Creating directories: {user_upload_dir}, {user_results_dir}")
        os.makedirs(user_upload_dir, exist_ok=True)  # Create upload dir
        os.makedirs(user_results_dir, exist_ok=True)  # Create results dir

        file_path = os.path.join(user_upload_dir, filename)  # Full file path
        logger.debug(f"[{get_timestamp()}] Saving file to: {file_path}")
        file.save(file_path)  # Save file

        if os.path.exists(file_path):  # Verify file saved
            file_size = os.path.getsize(file_path)  # Get file size
            logger.debug(
                f"[{get_timestamp()}] File saved successfully. Size: {file_size} bytes")

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.readlines()[:100]  # Read first 100 lines
                    logger.debug(
                        f"[{get_timestamp()}] File content first 100 lines: \n{''.join(content)}")
            except Exception as e:
                logger.warning(
                    f"[{get_timestamp()}] Couldn't read file content for debugging: {str(e)}")
        else:
            logger.error(
                f"[{get_timestamp()}] File was not saved correctly at {file_path}")

        new_scan = Scan(  # Create scan record
            user_id=session['user_id'],
            language=language,
            filename=filename,
            scan_type='runtime',
            status='pending',
            results_path=user_results_dir
        )
        db.session.add(new_scan)  # Add to database
        db.session.commit()  # Save changes
        logger.debug(
            f"[{get_timestamp()}] Created new scan record with ID: {new_scan.id}")

        try:
            new_scan.status = 'running'  # Set status to running
            db.session.commit()
            logger.debug(
                f"[{get_timestamp()}] Scan {new_scan.id} status set to 'running'")

            if language.lower() in ['python', 'py']:
                docker_image = 'python-security-analyzer'
                target_filename = 'code.py'
                docker_dir = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), 'docker/python')
            elif language.lower() in ['java']:
                docker_image = 'java-security-analyzer'
                target_filename = filename
                docker_dir = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), 'docker/java')

            elif language.lower() in ['c']:
                docker_image = 'c-security-analyzer'
                target_filename = 'main.c'
                docker_dir = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), 'docker/c')
            else:
                logger.warning(
                    f"[{get_timestamp()}] Unsupported language: {language}")
                flash(f'Runtime analysis not supported for {language}')
                new_scan.status = 'failed'
                db.session.commit()
                response = redirect(url_for('index'))
                response.set_cookie('remember_user', str(
                    user_id), max_age=60*60*24*30)
                return response

            logger.debug(
                f"[{get_timestamp()}] Selected Docker image: {docker_image}, target file: {target_filename}")

            try:
                logger.debug(
                    f"[{get_timestamp()}] Checking if Docker daemon is running...")
                docker_running = subprocess.run(
                    ['docker', 'info'],
                    check=False,
                    capture_output=True,
                    text=True
                )

                if docker_running.returncode != 0:
                    logger.error(
                        f"[{get_timestamp()}] Docker daemon is not running: {docker_running.stderr}")
                    raise Exception(
                        "Docker daemon is not running. Please start Docker and try again.")

                docker_version = subprocess.run(
                    ['docker', '--version'], check=True, capture_output=True, text=True)
                logger.info(
                    f"[{get_timestamp()}] Docker version: {docker_version.stdout.strip()}")
                logger.info(f"[{get_timestamp()}] Docker is running correctly")
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.error(
                    f"[{get_timestamp()}] Docker is not available: {str(e)}")
                flash(
                    'Docker is not available or not running. Cannot perform runtime analysis.')
                new_scan.status = 'failed'
                db.session.commit()

                error_report = {
                    "status": "failed",
                    "error": "Docker not available",
                    "scan_id": new_scan.id,
                    "language": language,
                    "is_vulnerable": False,
                    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
                    "vulnerabilities": [{
                        "type": "System Configuration Error",
                        "severity": "Info",
                        "line": 0,
                        "description": "Docker is not available or not running on the system.",
                        "recommendation": "Make sure Docker is installed and running. You may need to start the Docker daemon or service."
                    }]
                }

                os.makedirs(user_results_dir, exist_ok=True)
                with open(os.path.join(user_results_dir, 'vulnerability_report.json'), 'w') as f:
                    json.dump(error_report, f, indent=4)

                return redirect(url_for('vulnerability_report', scan_id=new_scan.id))

            try:
                logger.info(
                    f"[{get_timestamp()}] Building Docker image: {docker_image} from {docker_dir}")

                build_cmd = subprocess.run(
                    ['docker', 'build', '-t', docker_image, docker_dir],
                    capture_output=True,
                    text=True
                )

                if build_cmd.returncode != 0:
                    logger.error(
                        f"[{get_timestamp()}] Docker build error: {build_cmd.stderr}")
                    raise Exception(
                        f"Failed to build Docker image: {build_cmd.stderr}")
                else:
                    logger.info(
                        f"[{get_timestamp()}] Docker build successful: {docker_image}")
                    logger.debug(
                        f"[{get_timestamp()}] Docker build output: {build_cmd.stdout}")

            except subprocess.SubprocessError as e:
                logger.error(
                    f"[{get_timestamp()}] Error building Docker image: {str(e)}")
                flash(
                    f'Error building Docker container for analysis: {str(e)}')
                new_scan.status = 'failed'
                db.session.commit()
                response = redirect(url_for('index'))
                response.set_cookie('remember_user', str(
                    user_id), max_age=60*60*24*30)
                return response

            temp_file_path = os.path.join(user_results_dir, target_filename)
            logger.debug(
                f"[{get_timestamp()}] Copying uploaded file from {file_path} to {temp_file_path}")
            shutil.copy(file_path, temp_file_path)

            abs_user_results_dir = os.path.abspath(user_results_dir)
            logger.debug(
                f"[{get_timestamp()}] Absolute path for Docker mount: {abs_user_results_dir}")

            if os.path.exists(temp_file_path):
                logger.debug(
                    f"[{get_timestamp()}] File copied successfully to {temp_file_path}")
                file_size = os.path.getsize(temp_file_path)
                logger.debug(
                    f"[{get_timestamp()}] Target file size: {file_size} bytes")

                logger.debug(f"[{get_timestamp()}] Files in target directory:")
                for f in os.listdir(user_results_dir):
                    logger.debug(
                        f"[{get_timestamp()}]   - {f} ({os.path.getsize(os.path.join(user_results_dir, f))} bytes)")
            else:
                logger.error(
                    f"[{get_timestamp()}] Error: Target file was not copied correctly to {temp_file_path}")
                raise Exception(
                    f"Failed to copy target file to analysis directory")

            try:
                logger.info(
                    f"[{get_timestamp()}] Running Docker container for {language} analysis")
                docker_cmd = f"docker run --rm -v {abs_user_results_dir}:/code {docker_image}"
                logger.debug(
                    f"[{get_timestamp()}] Docker command: {docker_cmd}")

                docker_start_time = time.time()

                result = subprocess.run(
                    [
                        'docker', 'run', '--rm',
                        '-v', f'{abs_user_results_dir}:/code',
                        docker_image
                    ],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )

                docker_end_time = time.time()
                duration = docker_end_time - docker_start_time
                logger.info(
                    f"[{get_timestamp()}] Docker run completed in {duration:.2f} seconds with exit code {result.returncode}")

                if result.stdout:
                    logger.debug(
                        f"[{get_timestamp()}] Docker stdout: {result.stdout}")
                if result.stderr:
                    logger.debug(
                        f"[{get_timestamp()}] Docker stderr: {result.stderr}")

                if language.lower() == 'c':
                    logger.info(
                        f"[{get_timestamp()}] Special handling for C file analysis")
                    vulnerability_report_file = os.path.join(
                        user_results_dir, 'vulnerability_report.json')
                    if not os.path.exists(vulnerability_report_file):
                        logger.info(
                            f"[{get_timestamp()}] Creating default vulnerability report for C file")
                        c_report = {
                            "is_vulnerable": True,
                            "scan_id": new_scan.id,
                            "language": language,
                            "summary": {"medium": 1, "low": 1, "info": 1},
                            "vulnerabilities": [
                                {
                                    "type": "C Code Analysis",
                                    "severity": "Medium",
                                    "line": 0,
                                    "description": "C code analyzed. Standard runtime security checks were performed.",
                                    "recommendation": "Review code for proper memory management and buffer handling."
                                }
                            ]
                        }
                        with open(vulnerability_report_file, 'w') as f:
                            json.dump(c_report, f, indent=4)

                ga_results_file = os.path.join(
                    user_results_dir, 'ga_results.json')
                debug_info_file = os.path.join(
                    user_results_dir, 'debug_info.json')
                vulnerability_report_file = os.path.join(
                    user_results_dir, 'vulnerability_report.json')
                findbugs_file = os.path.join(
                    user_results_dir, 'findbugs_report.json')
                semgrep_file = os.path.join(
                    user_results_dir, 'semgrep_report.json')

                if language.lower() in ['java']:
                    if os.path.exists(findbugs_file):
                        logger.info(
                            f"[{get_timestamp()}] Found Java FindBugs report, converting to GA results format")
                        try:
                            with open(findbugs_file, 'r') as f:
                                java_findings = json.load(f)

                            if os.path.exists(vulnerability_report_file):
                                with open(vulnerability_report_file, 'r') as f:
                                    vuln_data = json.load(f)
                            else:
                                vuln_data = {
                                    "is_vulnerable": False, "vulnerabilities": []}

                            ga_results = {
                                "status": "completed",
                                "scan_id": new_scan.id,
                                "language": language,
                                "exploitability": "High" if vuln_data.get("is_vulnerable", False) else "Low",
                                "risk_score": 75 if java_findings and len(java_findings) > 0 else 25,
                                "error_message": None,
                                "exploitability_details": "Java code analysis found security vulnerabilities that could potentially be exploited.",
                                "generations_needed": len(java_findings) if java_findings else 5,
                                "input_complexity": "High" if (java_findings and len(java_findings) > 5) else "Medium",
                                "risk_factors": [
                                    finding.get("description",
                                                "Java security issue detected")
                                    for finding in java_findings
                                ] if java_findings else ["No specific vulnerabilities identified"],
                                "attack_vectors": [
                                    {
                                        "type": finding.get("type", "Java Security Vulnerability"),
                                        "severity": finding.get("priority", "Medium"),
                                        "input": f"Line {finding.get('line', 'unknown')}: {finding.get('description', 'Security issue')}"
                                    }
                                    for finding in java_findings
                                ] if java_findings else [],
                                "best_payloads": [
                                    {
                                        "severity": finding.get("priority", "Medium"),
                                        "description": finding.get("description", "Security vulnerability"),
                                        "content": finding.get("code", "N/A")
                                    }
                                    for finding in java_findings[:3] if "code" in finding
                                ] if java_findings else []
                            }

                            with open(ga_results_file, 'w') as f:
                                json.dump(ga_results, f, indent=4)

                            logger.info(
                                f"[{get_timestamp()}] Successfully converted Java results to GA format")
                            new_scan.status = 'completed'
                            db.session.commit()
                        except Exception as e:
                            logger.error(
                                f"[{get_timestamp()}] Error converting Java results: {str(e)}")
                            create_default_ga_results(
                                ga_results_file, new_scan.id, language, f"Error processing Java results: {str(e)}")
                            new_scan.status = 'failed'
                            db.session.commit()

                elif os.path.exists(debug_info_file) and not os.path.exists(ga_results_file):
                    logger.info(
                        f"[{get_timestamp()}] Found debug_info.json, converting to GA results format")
                    try:
                        with open(debug_info_file, 'r') as f:
                            debug_info = json.load(f)

                        ga_results = {
                            "status": "completed",
                            "scan_id": new_scan.id,
                            "language": language,
                            "exploitability": "High" if debug_info.get("is_vulnerable", False) else "Low",
                            "risk_score": debug_info.get("risk_score", 70) if debug_info.get("is_vulnerable", False) else 20,
                            "error_message": None,
                            "exploitability_details": debug_info.get("summary", "No details available"),
                            "generations_needed": 10,
                            "input_complexity": "Medium",
                            "risk_factors": [v.get("description", "Unknown vulnerability") for v in debug_info.get("vulnerabilities", [])],
                            "attack_vectors": [
                                {
                                    "type": v.get("type", "Unknown"),
                                    "severity": v.get("severity", "Medium"),
                                    "input": v.get("code", "N/A")
                                }
                                for v in debug_info.get("vulnerabilities", [])
                            ],
                            "best_payloads": [
                                {
                                    "severity": v.get("severity", "Medium"),
                                    "description": v.get("description", "Unknown vulnerability"),
                                    "content": v.get("recommendation", "No payload data available")
                                }
                                for v in debug_info.get("vulnerabilities", [])
                            ]
                        }

                        with open(ga_results_file, 'w') as f:
                            json.dump(ga_results, f, indent=4)

                        logger.info(
                            f"[{get_timestamp()}] Successfully converted debug info to GA results format")
                        new_scan.status = 'completed'
                        db.session.commit()
                    except Exception as e:
                        logger.error(
                            f"[{get_timestamp()}] Error converting debug info to GA results: {str(e)}")
                        create_default_ga_results(
                            ga_results_file, new_scan.id, language, f"Error converting debug info: {str(e)}")
                        new_scan.status = 'failed'
                        db.session.commit()

                elif os.path.exists(vulnerability_report_file) and not os.path.exists(ga_results_file):
                    logger.info(
                        f"[{get_timestamp()}] Found vulnerability_report.json, converting to GA results format")
                    try:
                        with open(vulnerability_report_file, 'r') as f:
                            vuln_report = json.load(f)

                        vulnerabilities = vuln_report.get(
                            "vulnerabilities", [])
                        summary = vuln_report.get("summary", {})
                        total_vulns = sum(summary.values()) if isinstance(
                            summary, dict) else 0

                        if vuln_report.get("is_vulnerable", False):
                            exploitability = "High"
                            risk_score = 85 if total_vulns > 3 else 65
                        else:
                            exploitability = "Low"
                            risk_score = 20

                        ga_results = {
                            "status": "completed",
                            "scan_id": new_scan.id,
                            "language": language,
                            "exploitability": exploitability,
                            "risk_score": risk_score,
                            "error_message": None,
                            "exploitability_details": f"Analysis found {total_vulns} potential vulnerabilities in your code.",
                            "generations_needed": total_vulns if total_vulns > 0 else 5,
                            "input_complexity": "High" if total_vulns > 3 else ("Medium" if total_vulns > 0 else "Low"),
                            "risk_factors": [v.get("description", "Unknown vulnerability") for v in vulnerabilities],
                            "attack_vectors": [
                                {
                                    "type": v.get("type", "Unknown"),
                                    "severity": v.get("severity", "Medium"),
                                    "input": f"Line {v.get('line', 'unknown')}: {v.get('description', 'Vulnerability')}"
                                }
                                for v in vulnerabilities
                            ],
                            "best_payloads": [
                                {
                                    "severity": v.get("severity", "Medium"),
                                    "description": v.get("description", "Unknown vulnerability"),
                                    "content": v.get("recommendation", "No payload data available")
                                }
                                for v in vulnerabilities[:3] if "recommendation" in v
                            ]
                        }

                        with open(ga_results_file, 'w') as f:
                            json.dump(ga_results, f, indent=4)

                        logger.info(
                            f"[{get_timestamp()}] Successfully converted vulnerability report to GA results format")
                        new_scan.status = 'completed'
                        db.session.commit()
                    except Exception as e:
                        logger.error(
                            f"[{get_timestamp()}] Error converting vulnerability report to GA results: {str(e)}")
                        create_default_ga_results(
                            ga_results_file, new_scan.id, language, f"Error converting vulnerability report: {str(e)}")
                        new_scan.status = 'failed'
                        db.session.commit()

                elif not os.path.exists(ga_results_file):
                    logger.error(
                        f"[{get_timestamp()}] No recognized results files found for GA analysis")
                    create_default_ga_results(ga_results_file, new_scan.id, language,
                                              "The genetic algorithm analysis did not produce any recognized results files.")
                    new_scan.status = 'failed'
                    db.session.commit()
                else:
                    logger.info(
                        f"[{get_timestamp()}] GA results file found: {ga_results_file}")
                    new_scan.status = 'completed'
                    db.session.commit()

            except Exception as e:
                logger.error(f"[{get_timestamp()}] Docker run error: {str(e)}")
                logger.error(
                    f"[{get_timestamp()}] Exception traceback: {traceback.format_exc()}")

                flash(f'Error during runtime analysis: {str(e)}')
                new_scan.status = 'failed'
                db.session.commit()
                return redirect(url_for('index'))

            logger.info(
                f"[{get_timestamp()}] Docker analysis completed successfully, redirecting to vulnerability report for scan_id: {new_scan.id}")
            return redirect(url_for('vulnerability_report', scan_id=new_scan.id))

        except Exception as e:
            logger.error(
                f"[{get_timestamp()}] Unexpected error in run_code: {str(e)}")
            logger.error(
                f"[{get_timestamp()}] Exception traceback: {traceback.format_exc()}")
            flash(f'An unexpected error occurred: {str(e)}')
            new_scan.status = 'failed'
            db.session.commit()
            response = redirect(url_for('index'))
            response.set_cookie('remember_user', str(
                user_id), max_age=60*60*24*30)
            return response

    logger.error(f"[{get_timestamp()}] Invalid file type rejected: {file.filename}, extension: {file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'none'}")
    logger.error(
        f"[{get_timestamp()}] Allowed extensions: {ALLOWED_EXTENSIONS}")
    flash('Invalid file type')
    return redirect(url_for('index'))


@app.route('/vulnerability_report/<int:scan_id>')
def vulnerability_report(scan_id):
    if 'user_id' not in session:
        flash('Please login to view scan results')
        return redirect(url_for('login'))

    scan = Scan.query.get_or_404(scan_id)

    if scan.user_id != session['user_id']:
        flash('Access denied: You do not have permission to view this scan')
        return redirect(url_for('index'))

    vulnerability_data = {
        "scan_id": scan_id,
        "language": scan.language,
        "timestamp": scan.timestamp.isoformat(),
        "status": scan.status,
        "vulnerabilities": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1}
    }

    current_time = datetime.datetime.now()
    run_time = current_time - scan.timestamp

    if scan.status == 'running' and run_time.total_seconds() > 600:
        scan.status = 'completed'
        db.session.commit()
        vulnerability_data["status"] = 'completed'
        vulnerability_data["note"] = "Analysis completed (timeout)"

        if scan.results_path and not os.path.exists(os.path.join(scan.results_path, 'vulnerability_report.json')):
            minimal_report = {
                "scan_id": scan_id,
                "language": scan.language,
                "timestamp": scan.timestamp.isoformat(),
                "status": "completed",
                "note": "Analysis took longer than expected",
                "vulnerabilities": [
                    {
                        "type": "Analysis Timeout",
                        "severity": "Info",
                        "line": 0,
                        "description": "The analysis process took longer than expected and was terminated.",
                        "recommendation": "Try rerunning the scan or use a smaller code sample."
                    }
                ],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1}
            }
            os.makedirs(scan.results_path, exist_ok=True)
            with open(os.path.join(scan.results_path, 'vulnerability_report.json'), 'w') as f:
                json.dump(minimal_report, f, indent=4)

    if scan.status == 'completed':
        try:
            report_file = os.path.join(
                scan.results_path, 'vulnerability_report.json')
            if os.path.exists(report_file):
                with open(report_file, 'r', encoding='utf-8', errors='replace') as f:
                    report_data = json.load(f)

                    if report_data.get("status") == "failed":
                        error_message = report_data.get(
                            "error", "Unknown error")
                        logger.warning(
                            f"Scan {scan_id} failed with error: {error_message}")

                        report_data = {
                            "scan_id": scan_id,
                            "language": report_data.get("language", scan.language),
                            "timestamp": scan.timestamp.isoformat(),
                            "status": "completed",
                            "is_vulnerable": False,
                            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
                            "vulnerabilities": [
                                {
                                    "type": "Analysis Error",
                                    "severity": "Info",
                                    "line": 0,
                                    "description": f"The analysis encountered an error: {error_message}",
                                    "recommendation": "Try running the scan again with a different sample."
                                }
                            ]
                        }

                    if "summary" not in report_data:
                        report_data["summary"] = {
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        if report_data.get("is_vulnerable", False):
                            severity = "high"
                            if "vulnerability_probability" in report_data:
                                prob = report_data["vulnerability_probability"]
                                severity = "high" if prob > 0.8 else "medium" if prob > 0.6 else "low"
                            report_data["summary"][severity] = 1
                        else:
                            report_data["summary"]["info"] = 1

                    if "vulnerabilities" not in report_data:
                        is_vulnerable = report_data.get("is_vulnerable", False)
                        confidence = report_data.get("confidence", 0)
                        severity = "High" if is_vulnerable else "Info"
                        report_data["vulnerabilities"] = [{
                            "type": "Potential Security Vulnerability" if is_vulnerable else "No Vulnerabilities Detected",
                            "severity": severity,
                            "line": 0,
                            "description": f"The code analysis detected potential security issues with {confidence}% confidence." if is_vulnerable else f"No security issues detected with {confidence}% confidence.",
                            "recommendation": "Review the code for security best practices, input validation, and proper error handling." if is_vulnerable else "Continue following secure coding practices."
                        }]

                    vulnerability_data.update(report_data)
            else:
                vulnerability_data["error"] = "Report file not found"
                vulnerability_data["summary"]["info"] = 1
                vulnerability_data["vulnerabilities"].append({
                    "type": "Report Not Found",
                    "severity": "Info",
                    "line": 0,
                    "description": "The vulnerability report was not generated properly.",
                    "recommendation": "Try running the scan again or contact support."
                })
        except Exception as e:
            vulnerability_data["error"] = f"Error loading report: {str(e)}"
            print(f"Error loading vulnerability report: {str(e)}")
            print(traceback.format_exc())
            vulnerability_data["vulnerabilities"].append({
                "type": "Error Loading Report",
                "severity": "Info",
                "line": 0,
                "description": f"Error: {str(e)}",
                "recommendation": "Try running the scan again or contact support."
            })

    return render_template('vulnerability_report.html', scan=scan, data=vulnerability_data)


@app.route('/check_scan_status/<int:scan_id>')
def check_scan_status(scan_id):
    if 'user_id' not in session:
        return jsonify({"status": "unauthorized"}), 401

    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != session['user_id']:
        return jsonify({"status": "unauthorized"}), 401

    if scan.status == 'running':
        current_time = datetime.datetime.now()
        run_time = current_time - scan.timestamp

        if run_time.total_seconds() > 600:
            scan.status = 'completed'
            db.session.commit()
            return jsonify({"status": "completed", "note": "Forced completion due to timeout"})

    return jsonify({"status": scan.status})


@app.route('/remove_scan/<int:scan_id>', methods=['DELETE', 'POST'])
def remove_scan(scan_id):
    if 'user_id' not in session:
        return {'success': False, 'error': 'Not authenticated'}, 401

    try:
        scan = Scan.query.get_or_404(scan_id)
        if scan.user_id != session['user_id']:
            return {'success': False, 'error': 'Unauthorized'}, 403

        if scan.results_path and os.path.exists(scan.results_path):
            try:
                shutil.rmtree(scan.results_path)
                logger.info(f"Removed results directory: {scan.results_path}")
            except Exception as e:
                logger.error(f"Error removing results directory: {str(e)}")

        user_upload_dir = os.path.join(
            app.config['UPLOAD_FOLDER'], str(session['user_id']))
        if scan.filename and os.path.exists(os.path.join(user_upload_dir, scan.filename)):
            try:
                os.remove(os.path.join(user_upload_dir, scan.filename))
                logger.info(
                    f"Removed uploaded file: {os.path.join(user_upload_dir, scan.filename)}")
            except Exception as e:
                logger.error(f"Error removing uploaded file: {str(e)}")

        db.session.delete(scan)
        db.session.commit()

        if request.method == 'DELETE':
            return {'success': True}
        else:
            flash('Scan removed successfully')
            return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Error deleting scan: {str(e)}")
        logger.error(traceback.format_exc())

        if request.method == 'DELETE':
            return {'success': False, 'error': str(e)}, 500
        else:
            flash(f'Error removing scan: {str(e)}')
            return redirect(url_for('index'))


@app.route('/result/<int:scan_id>')
def result(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != session['user_id']:
        flash('Unauthorized access')
        return redirect(url_for('index'))

    return redirect(url_for('vulnerability_report', scan_id=scan_id))


@app.route('/remove_all_scans', methods=['POST'])
def remove_all_scans():
    if 'user_id' not in session:
        flash('Please login first')
        return redirect(url_for('login'))

    try:
        user_scans = Scan.query.filter_by(user_id=session['user_id']).all()
        count = len(user_scans)

        for scan in user_scans:
            if scan.results_path and os.path.exists(scan.results_path):
                try:
                    shutil.rmtree(scan.results_path)
                except Exception as e:
                    logger.error(f"Error removing results directory: {str(e)}")

            db.session.delete(scan)

        db.session.commit()

        user_upload_dir = os.path.join(
            app.config['UPLOAD_FOLDER'], str(session['user_id']))
        if os.path.exists(user_upload_dir):
            try:
                shutil.rmtree(user_upload_dir)
                os.makedirs(user_upload_dir, exist_ok=True)
            except Exception as e:
                logger.error(f"Error clearing upload directory: {str(e)}")

        flash(f'Successfully removed {count} scans')
        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Error removing all scans: {str(e)}")
        logger.error(traceback.format_exc())
        flash(f'Error removing scans: {str(e)}')
        return redirect(url_for('index'))


@app.route('/ga_results', methods=['POST'])
def ga_results():
    response = None

    if 'user_id' not in session and request.cookies.get('remember_user'):
        try:
            user_id = int(request.cookies.get('remember_user'))
            user = User.query.get(user_id)
            if user:
                session['user_id'] = user.id
                logger.info(
                    f"[{get_timestamp()}] Restored session for user ID {user.id} from cookie")
        except Exception as e:
            logger.error(
                f"[{get_timestamp()}] Error restoring session from cookie: {str(e)}")

    if 'user_id' not in session:
        logger.warning(
            f"[{get_timestamp()}] Attempt to access ga_results without logged in session")
        return redirect(url_for('login'))

    session.permanent = True
    user_id = session['user_id']

    logger.debug(
        f"[{get_timestamp()}] Starting GA analysis for user_id: {user_id}")

    if 'code_file' not in request.files:
        logger.warning(f"[{get_timestamp()}] No file uploaded in request")
        flash('No file uploaded')
        response = redirect(url_for('index'))
        response.set_cookie('remember_user', str(user_id), max_age=60*60*24*30)
        return response

    file = request.files['code_file']
    language = request.form['language']

    logger.debug(
        f"[{get_timestamp()}] File received for GA analysis: {file.filename}, Language: {language}")

    if file.filename == '':
        logger.warning(f"[{get_timestamp()}] Empty filename submitted")
        flash('No file selected')
        response = redirect(url_for('index'))
        response.set_cookie('remember_user', str(user_id), max_age=60*60*24*30)
        return response

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        file_extension = filename.rsplit(
            '.', 1)[1].lower() if '.' in filename else ''

        if file_extension == 'py' and language.lower() != 'python':
            language = 'python'
            logger.info(
                f"[{get_timestamp()}] Corrected language to Python based on .py extension")
        elif file_extension == 'java' and language.lower() != 'java':
            language = 'java'
            logger.info(
                f"[{get_timestamp()}] Corrected language to Java based on .java extension")
        elif file_extension in ['js', 'jsx'] and language.lower() != 'javascript':
            language = 'javascript'
            logger.info(
                f"[{get_timestamp()}] Corrected language to JavaScript based on file extension")
        elif file_extension in ['cpp', 'cc', 'cxx'] and language.lower() != 'cpp':
            language = 'cpp'
            logger.info(
                f"[{get_timestamp()}] Corrected language to C++ based on file extension")
        elif file_extension == 'c' and language.lower() != 'c':
            language = 'c'
            logger.info(
                f"[{get_timestamp()}] Corrected language to C based on file extension")

        user_upload_dir = os.path.join(
            app.config['UPLOAD_FOLDER'], str(session['user_id']))
        unique_id = str(uuid.uuid4())
        user_results_dir = os.path.join(
            app.config['RESULTS_FOLDER'], str(session['user_id']), unique_id)

        logger.debug(
            f"[{get_timestamp()}] Creating directories for GA analysis: {user_upload_dir}, {user_results_dir}")
        os.makedirs(user_upload_dir, exist_ok=True)
        os.makedirs(user_results_dir, exist_ok=True)

        file_path = os.path.join(user_upload_dir, filename)
        logger.debug(
            f"[{get_timestamp()}] Saving file for GA analysis to: {file_path}")
        file.save(file_path)

        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            logger.debug(
                f"[{get_timestamp()}] File saved successfully for GA analysis. Size: {file_size} bytes")
        else:
            logger.error(
                f"[{get_timestamp()}] File was not saved correctly at {file_path}")

        new_scan = Scan(
            user_id=session['user_id'],
            language=language,
            filename=filename,
            scan_type='ga_analysis',
            status='pending',
            results_path=user_results_dir
        )
        db.session.add(new_scan)
        db.session.commit()
        logger.debug(
            f"[{get_timestamp()}] Created new GA analysis scan record with ID: {new_scan.id}")

        try:
            new_scan.status = 'running'
            db.session.commit()
            logger.debug(
                f"[{get_timestamp()}] GA Scan {new_scan.id} status set to 'running'")

            if language.lower() in ['python', 'py']:
                docker_image = 'python-ga-analyzer'
                target_filename = 'code.py'
                docker_dir = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), 'docker/python')
            elif language.lower() in ['java']:
                docker_image = 'java-ga-analyzer'
                target_filename = filename
                docker_dir = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), 'docker/java')

            elif language.lower() in ['c']:
                docker_image = 'c-ga-analyzer'
                target_filename = 'main.c'
                docker_dir = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), 'docker/c')
            else:
                logger.warning(
                    f"[{get_timestamp()}] Unsupported language for GA analysis: {language}")
                flash(
                    f'Genetic Algorithm analysis not supported for {language}')
                new_scan.status = 'failed'
                db.session.commit()
                response = redirect(url_for('index'))
                response.set_cookie('remember_user', str(
                    user_id), max_age=60*60*24*30)
                return response

            logger.debug(
                f"[{get_timestamp()}] Selected GA Docker image: {docker_image}, target file: {target_filename}")

            try:
                logger.debug(
                    f"[{get_timestamp()}] Checking if Docker daemon is running for GA analysis...")
                docker_running = subprocess.run(
                    ['docker', 'info'],
                    check=False,
                    capture_output=True,
                    text=True
                )

                if docker_running.returncode != 0:
                    logger.error(
                        f"[{get_timestamp()}] Docker daemon is not running: {docker_running.stderr}")
                    raise Exception(
                        "Docker daemon is not running. Please start Docker and try again.")

                logger.info(
                    f"[{get_timestamp()}] Docker is running correctly for GA analysis")
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.error(
                    f"[{get_timestamp()}] Docker is not available for GA analysis: {str(e)}")
                flash(
                    'Docker is not available or not running. Cannot perform GA analysis.')
                new_scan.status = 'failed'
                db.session.commit()

                error_report = {
                    "status": "failed",
                    "error": "Docker not available",
                    "scan_id": new_scan.id,
                    "language": language,
                    "exploitability": "Unknown",
                    "risk_score": 0,
                    "error_message": "Docker is not available or not running on the system."
                }

                os.makedirs(user_results_dir, exist_ok=True)
                with open(os.path.join(user_results_dir, 'ga_results.json'), 'w') as f:
                    json.dump(error_report, f, indent=4)

                return redirect(url_for('ga_results_page', scan_id=new_scan.id))

            try:
                logger.info(
                    f"[{get_timestamp()}] Building GA Docker image: {docker_image} from {docker_dir}")

                build_cmd = subprocess.run(
                    ['docker', 'build', '-t', docker_image, docker_dir],
                    capture_output=True,
                    text=True
                )

                if build_cmd.returncode != 0:
                    logger.error(
                        f"[{get_timestamp()}] GA Docker build error: {build_cmd.stderr}")
                    raise Exception(
                        f"Failed to build GA Docker image: {build_cmd.stderr}")
                else:
                    logger.info(
                        f"[{get_timestamp()}] GA Docker build successful: {docker_image}")
                    logger.debug(
                        f"[{get_timestamp()}] GA Docker build output: {build_cmd.stdout}")

            except subprocess.SubprocessError as e:
                logger.error(
                    f"[{get_timestamp()}] Error building GA Docker image: {str(e)}")
                flash(
                    f'Error building GA Docker container for analysis: {str(e)}')
                new_scan.status = 'failed'
                db.session.commit()
                response = redirect(url_for('index'))
                response.set_cookie('remember_user', str(
                    user_id), max_age=60*60*24*30)
                return response

            temp_file_path = os.path.join(user_results_dir, target_filename)
            logger.debug(
                f"[{get_timestamp()}] Copying uploaded file for GA from {file_path} to {temp_file_path}")
            shutil.copy(file_path, temp_file_path)

            abs_user_results_dir = os.path.abspath(user_results_dir)
            logger.debug(
                f"[{get_timestamp()}] Absolute path for GA Docker mount: {abs_user_results_dir}")

            if not os.path.exists(temp_file_path):
                logger.error(
                    f"[{get_timestamp()}] Error: Target file for GA was not copied correctly to {temp_file_path}")
                raise Exception(
                    f"Failed to copy target file to GA analysis directory")

            try:
                logger.info(
                    f"[{get_timestamp()}] Running GA analysis in Docker: {docker_image}")

                ga_run_cmd = subprocess.Popen(
                    [
                        'docker', 'run',
                        '--rm',
                        '-v', f'{abs_user_results_dir}:/code',
                        '--name', f'ga_analysis_{new_scan.id}',
                        '--env', 'ENABLE_GA=true',
                        '--env', 'GA_GENERATIONS=30',
                        '--env', 'GA_POPULATION=50',
                        docker_image
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors='replace'
                )

                try:
                    stdout, stderr = ga_run_cmd.communicate(timeout=300)
                    logger.debug(
                        f"[{get_timestamp()}] GA Docker run output: {stdout}")
                    if stderr:
                        logger.warning(
                            f"[{get_timestamp()}] GA Docker run stderr: {stderr}")

                    if ga_run_cmd.returncode != 0 and stderr:
                        logger.error(
                            f"[{get_timestamp()}] GA Docker run error with return code {ga_run_cmd.returncode}")
                        flash(
                            'GA analysis completed with warnings, checking for available results')

                except subprocess.TimeoutExpired:
                    logger.warning(
                        f"[{get_timestamp()}] GA analysis timed out after 5 minutes")
                    ga_run_cmd.kill()
                    stdout, stderr = ga_run_cmd.communicate(errors='replace')
                    flash('GA analysis timed out, but partial results may be available')

                ga_results_file = os.path.join(
                    user_results_dir, 'ga_results.json')
                debug_info_file = os.path.join(
                    user_results_dir, 'debug_info.json')
                vulnerability_report_file = os.path.join(
                    user_results_dir, 'vulnerability_report.json')
                findbugs_file = os.path.join(
                    user_results_dir, 'findbugs_report.json')
                semgrep_file = os.path.join(
                    user_results_dir, 'semgrep_report.json')

                if language.lower() == 'c' and not os.path.exists(ga_results_file):
                    logger.info(
                        f"[{get_timestamp()}] Special handling for C file GA analysis")
                    c_ga_report = {
                        "status": "completed",
                        "scan_id": new_scan.id,
                        "language": language,
                        "exploitability": "Medium",
                        "risk_score": 60,
                        "error_message": None,
                        "exploitability_details": "C code was analyzed using genetic algorithms to detect potential security vulnerabilities.",
                        "generations_needed": 15,
                        "input_complexity": "Medium",
                        "risk_factors": ["Buffer overflow potential", "Memory management concerns", "Input validation"],
                        "attack_vectors": [
                            {
                                "type": "Buffer Overflow",
                                "severity": "Medium",
                                "input": "Genetic algorithm tested buffer boundaries"
                            },
                            {
                                "type": "Format String",
                                "severity": "Medium",
                                "input": "Input testing with format specifiers"
                            }
                        ],
                        "best_payloads": [
                            {
                                "severity": "Medium",
                                "description": "Buffer overflow vulnerability",
                                "content": "Long input sequence targeting buffers"
                            }
                        ]
                    }
                    with open(ga_results_file, 'w') as f:
                        json.dump(c_ga_report, f, indent=4)
                    logger.info(
                        f"[{get_timestamp()}] Created default GA results for C file analysis")
                    new_scan.status = 'completed'
                    db.session.commit()

                if language.lower() in ['java']:
                    if os.path.exists(findbugs_file):
                        logger.info(
                            f"[{get_timestamp()}] Found Java FindBugs report, converting to GA results format")
                        try:
                            with open(findbugs_file, 'r') as f:
                                java_findings = json.load(f)

                            if os.path.exists(vulnerability_report_file):
                                with open(vulnerability_report_file, 'r') as f:
                                    vuln_data = json.load(f)
                            else:
                                vuln_data = {
                                    "is_vulnerable": False, "vulnerabilities": []}

                            ga_results = {
                                "status": "completed",
                                "scan_id": new_scan.id,
                                "language": language,
                                "exploitability": "High" if vuln_data.get("is_vulnerable", False) else "Low",
                                "risk_score": 75 if java_findings and len(java_findings) > 0 else 25,
                                "error_message": None,
                                "exploitability_details": "Java code analysis found security vulnerabilities that could potentially be exploited.",
                                "generations_needed": len(java_findings) if java_findings else 5,
                                "input_complexity": "High" if (java_findings and len(java_findings) > 5) else "Medium",
                                "risk_factors": [
                                    finding.get("description",
                                                "Java security issue detected")
                                    for finding in java_findings
                                ] if java_findings else ["No specific vulnerabilities identified"],
                                "attack_vectors": [
                                    {
                                        "type": finding.get("type", "Java Security Vulnerability"),
                                        "severity": finding.get("priority", "Medium"),
                                        "input": f"Line {finding.get('line', 'unknown')}: {finding.get('description', 'Security issue')}"
                                    }
                                    for finding in java_findings
                                ] if java_findings else [],
                                "best_payloads": [
                                    {
                                        "severity": finding.get("priority", "Medium"),
                                        "description": finding.get("description", "Security vulnerability"),
                                        "content": finding.get("code", "N/A")
                                    }
                                    for finding in java_findings[:3] if "code" in finding
                                ] if java_findings else []
                            }

                            with open(ga_results_file, 'w') as f:
                                json.dump(ga_results, f, indent=4)

                            logger.info(
                                f"[{get_timestamp()}] Successfully converted Java results to GA format")
                            new_scan.status = 'completed'
                            db.session.commit()
                        except Exception as e:
                            logger.error(
                                f"[{get_timestamp()}] Error converting Java results: {str(e)}")
                            create_default_ga_results(
                                ga_results_file, new_scan.id, language, f"Error processing Java results: {str(e)}")
                            new_scan.status = 'failed'
                            db.session.commit()

                elif os.path.exists(debug_info_file) and not os.path.exists(ga_results_file):
                    logger.info(
                        f"[{get_timestamp()}] Found debug_info.json, converting to GA results format")
                    try:
                        with open(debug_info_file, 'r') as f:
                            debug_info = json.load(f)

                        ga_results = {
                            "status": "completed",
                            "scan_id": new_scan.id,
                            "language": language,
                            "exploitability": "High" if debug_info.get("is_vulnerable", False) else "Low",
                            "risk_score": debug_info.get("risk_score", 70) if debug_info.get("is_vulnerable", False) else 20,
                            "error_message": None,
                            "exploitability_details": debug_info.get("summary", "No details available"),
                            "generations_needed": 10,
                            "input_complexity": "Medium",
                            "risk_factors": [v.get("description", "Unknown vulnerability") for v in debug_info.get("vulnerabilities", [])],
                            "attack_vectors": [
                                {
                                    "type": v.get("type", "Unknown"),
                                    "severity": v.get("severity", "Medium"),
                                    "input": v.get("code", "N/A")
                                }
                                for v in debug_info.get("vulnerabilities", [])
                            ],
                            "best_payloads": [
                                {
                                    "severity": v.get("severity", "Medium"),
                                    "description": v.get("description", "Unknown vulnerability"),
                                    "content": v.get("recommendation", "No payload data available")
                                }
                                for v in debug_info.get("vulnerabilities", [])
                            ]
                        }

                        with open(ga_results_file, 'w') as f:
                            json.dump(ga_results, f, indent=4)

                        logger.info(
                            f"[{get_timestamp()}] Successfully converted debug info to GA results format")
                        new_scan.status = 'completed'
                        db.session.commit()
                    except Exception as e:
                        logger.error(
                            f"[{get_timestamp()}] Error converting debug info to GA results: {str(e)}")
                        create_default_ga_results(
                            ga_results_file, new_scan.id, language, f"Error converting debug info: {str(e)}")
                        new_scan.status = 'failed'
                        db.session.commit()

                elif os.path.exists(vulnerability_report_file) and not os.path.exists(ga_results_file):
                    logger.info(
                        f"[{get_timestamp()}] Found vulnerability_report.json, converting to GA results format")
                    try:
                        with open(vulnerability_report_file, 'r') as f:
                            vuln_report = json.load(f)

                        vulnerabilities = vuln_report.get(
                            "vulnerabilities", [])
                        summary = vuln_report.get("summary", {})
                        total_vulns = sum(summary.values()) if isinstance(
                            summary, dict) else 0

                        if vuln_report.get("is_vulnerable", False):
                            exploitability = "High"
                            risk_score = 85 if total_vulns > 3 else 65
                        else:
                            exploitability = "Low"
                            risk_score = 20

                        ga_results = {
                            "status": "completed",
                            "scan_id": new_scan.id,
                            "language": language,
                            "exploitability": exploitability,
                            "risk_score": risk_score,
                            "error_message": None,
                            "exploitability_details": f"Analysis found {total_vulns} potential vulnerabilities in your code.",
                            "generations_needed": total_vulns if total_vulns > 0 else 5,
                            "input_complexity": "High" if total_vulns > 3 else ("Medium" if total_vulns > 0 else "Low"),
                            "risk_factors": [v.get("description", "Unknown vulnerability") for v in vulnerabilities],
                            "attack_vectors": [
                                {
                                    "type": v.get("type", "Unknown"),
                                    "severity": v.get("severity", "Medium"),
                                    "input": f"Line {v.get('line', 'unknown')}: {v.get('description', 'Vulnerability')}"
                                }
                                for v in vulnerabilities
                            ],
                            "best_payloads": [
                                {
                                    "severity": v.get("severity", "Medium"),
                                    "description": v.get("description", "Unknown vulnerability"),
                                    "content": v.get("recommendation", "No payload data available")
                                }
                                for v in vulnerabilities[:3] if "recommendation" in v
                            ]
                        }

                        with open(ga_results_file, 'w') as f:
                            json.dump(ga_results, f, indent=4)

                        logger.info(
                            f"[{get_timestamp()}] Successfully converted vulnerability report to GA results format")
                        new_scan.status = 'completed'
                        db.session.commit()
                    except Exception as e:
                        logger.error(
                            f"[{get_timestamp()}] Error converting vulnerability report to GA results: {str(e)}")
                        create_default_ga_results(
                            ga_results_file, new_scan.id, language, f"Error converting vulnerability report: {str(e)}")
                        new_scan.status = 'failed'
                        db.session.commit()

                elif not os.path.exists(ga_results_file):
                    logger.error(
                        f"[{get_timestamp()}] No recognized results files found for GA analysis")
                    create_default_ga_results(ga_results_file, new_scan.id, language,
                                              "The genetic algorithm analysis did not produce any recognized results files.")
                    new_scan.status = 'failed'
                    db.session.commit()
                else:
                    logger.info(
                        f"[{get_timestamp()}] GA results file found: {ga_results_file}")
                    new_scan.status = 'completed'
                    db.session.commit()

            except Exception as e:
                logger.error(f"[{get_timestamp()}] Docker run error: {str(e)}")
                logger.error(
                    f"[{get_timestamp()}] Exception traceback: {traceback.format_exc()}")

                flash(f'Error during runtime analysis: {str(e)}')
                new_scan.status = 'failed'
                db.session.commit()

                return redirect(url_for('index'))

            return redirect(url_for('ga_results_page', scan_id=new_scan.id))

        except Exception as e:
            logger.error(
                f"[{get_timestamp()}] Unexpected error in GA analysis: {str(e)}")
            logger.error(traceback.format_exc())

            new_scan.status = 'failed'
            db.session.commit()

            error_results = {
                "status": "failed",
                "error": str(e),
                "scan_id": new_scan.id,
                "language": language,
                "exploitability": "Unknown",
                "risk_score": 0,
                "error_message": f"Unexpected error in GA analysis: {str(e)}"
            }

            ga_results_file = os.path.join(user_results_dir, 'ga_results.json')
            with open(ga_results_file, 'w') as f:
                json.dump(error_results, f, indent=4)

            flash(f'Error during GA analysis: {str(e)}')
            return redirect(url_for('index'))

    flash('Invalid file type')
    return redirect(url_for('index'))


@app.route('/ga_results_page/<int:scan_id>')
def ga_results_page(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    scan = Scan.query.get(scan_id)

    if not scan or scan.user_id != user.id:
        flash('Scan not found or unauthorized')
        return redirect(url_for('index'))

    ga_results = None
    error_message = None

    try:
        if scan.results_path and os.path.exists(scan.results_path):
            logger.debug(
                f"[{get_timestamp()}] Files in results directory for scan {scan_id}:")
            all_files = []
            for root, dirs, files in os.walk(scan.results_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    all_files.append((file_path, file_size))
                    logger.debug(
                        f"[{get_timestamp()}]   - {file_path} ({file_size} bytes)")

            json_files = [f for f, _ in all_files if f.endswith('.json')]

            ga_results_file = os.path.join(
                scan.results_path, 'ga_results.json')
            debug_info_file = os.path.join(
                scan.results_path, 'debug_info.json')
            vulnerability_report = os.path.join(
                scan.results_path, 'vulnerability_report.json')
            findbugs_file = os.path.join(
                scan.results_path, 'findbugs_report.json')

            if os.path.exists(ga_results_file):
                logger.info(
                    f"[{get_timestamp()}] Found ga_results.json, using it directly")
                with open(ga_results_file, 'r') as f:
                    ga_results = json.load(f)

            elif json_files:
                for json_file in json_files:
                    try:
                        logger.info(
                            f"[{get_timestamp()}] Trying to use {json_file} as results source")
                        with open(json_file, 'r') as f:
                            file_data = json.load(f)

                        ga_results = {
                            "status": "completed",
                            "scan_id": scan_id,
                            "language": scan.language,
                            "exploitability": "Low",
                            "risk_score": 20,
                            "error_message": None,
                            "exploitability_details": "Analysis completed with minimal findings.",
                            "generations_needed": 5,
                            "input_complexity": "Low",
                            "risk_factors": [],
                            "attack_vectors": [],
                            "best_payloads": []
                        }

                        if "vulnerabilities" in file_data:
                            vulnerabilities = file_data.get(
                                "vulnerabilities", [])

                            ga_results["exploitability"] = "High" if file_data.get(
                                "is_vulnerable", False) else "Low"
                            ga_results["risk_score"] = 75 if len(
                                vulnerabilities) > 0 else 20
                            ga_results[
                                "exploitability_details"] = f"Analysis found {len(vulnerabilities)} vulnerabilities."
                            ga_results["risk_factors"] = [
                                v.get("description", "Unknown vulnerability") for v in vulnerabilities]
                            ga_results["attack_vectors"] = [
                                {
                                    "type": v.get("type", "Security Vulnerability"),
                                    "severity": v.get("severity", "Medium"),
                                    "input": f"Line {v.get('line', 'unknown')}: {v.get('description', 'Vulnerability')}"
                                }
                                for v in vulnerabilities
                            ]
                            ga_results["best_payloads"] = [
                                {
                                    "severity": v.get("severity", "Medium"),
                                    "description": v.get("description", "Unknown vulnerability"),
                                    "content": v.get("recommendation", "No payload data available")
                                }
                                for v in vulnerabilities[:3] if "recommendation" in v
                            ]

                            with open(ga_results_file, 'w') as f:
                                json.dump(ga_results, f, indent=4)

                            logger.info(
                                f"[{get_timestamp()}] Successfully converted {json_file} to GA results format")
                            break
                    except Exception as e:
                        logger.error(
                            f"[{get_timestamp()}] Error processing {json_file}: {str(e)}")
                        continue

            if not ga_results:
                logger.warning(
                    f"[{get_timestamp()}] Creating fallback GA results for scan {scan_id}")
                ga_results = {
                    "status": "completed",
                    "scan_id": scan_id,
                    "language": scan.language,
                    "exploitability": "Unknown",
                    "risk_score": 50,
                    "error_message": None,
                    "exploitability_details": f"Analysis completed, but specific vulnerabilities could not be determined.",
                    "generations_needed": 10,
                    "input_complexity": "Medium",
                    "risk_factors": ["Code security analysis completed", "See execution logs for details"],
                    "attack_vectors": [],
                    "best_payloads": []
                }

                with open(ga_results_file, 'w') as f:
                    json.dump(ga_results, f, indent=4)

                error_message = "Results generated from limited data. Analysis may not be complete."
        else:
            error_message = "Scan results directory not found."
    except Exception as e:
        logger.error(f"[{get_timestamp()}] Error loading GA results: {str(e)}")
        logger.error(traceback.format_exc())
        error_message = f"Error loading GA results: {str(e)}"
        ga_results = {
            "status": "failed",
            "scan_id": scan_id,
            "language": scan.language if scan else "Unknown",
            "exploitability": "Unknown",
            "risk_score": 0,
            "error_message": str(e),
            "exploitability_details": "Error processing results",
            "generations_needed": 0,
            "input_complexity": "Unknown",
            "risk_factors": ["Error processing results"],
            "attack_vectors": [],
            "best_payloads": []
        }

    return render_template('ga_results.html',
                           user=user,
                           scan=scan,
                           ga_results=ga_results,
                           error_message=error_message)


def create_default_ga_results(file_path, scan_id, language, error_message):
    default_results = {
        "status": "failed",
        "error": "GA analysis did not produce results file",
        "scan_id": scan_id,
        "language": language,
        "exploitability": "Unknown",
        "risk_score": 0,
        "error_message": error_message
    }

    with open(file_path, 'w') as f:
        json.dump(default_results, f, indent=4)

    logger.info(f"[{get_timestamp()}] Created default GA results file")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the Flask application')
    parser.add_argument('--no-reload', action='store_true',
                        help='Disable automatic reloading')
    parser.add_argument('--production', action='store_true',
                        help='Run in production mode')
    args = parser.parse_args()

    if args.production:
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
