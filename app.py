import os
from flask import Flask, render_template, request, redirect, url_for
import boto3
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Configurations ---
S3_BUCKET = 'sarthakdasstorage1'
AWS_REGION = 'eu-north-1'
PLACEHOLDER_THUMBNAIL = 'https://via.placeholder.com/400x225.png?text=Video'
DB_USER = 'admin'
DB_PASSWORD = 'SarthakRoot123'
DB_ENDPOINT = 'mydbinstance.czu6gy4qghjk.eu-north-1.rds.amazonaws.com'
DB_NAME = 'CCD3'
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_ENDPOINT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'

# --- Initializations ---
db = SQLAlchemy(app)
s3_client = boto3.client('s3', region_name=AWS_REGION)

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Forms ---
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# --- Routes ---
@app.route('/')
def home():
    videos = []
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET)
        
        if 'Contents' in response:
            files = response['Contents']
            content_map = {}
            for file in files:
                filename = file['Key']
                base_name, extension = os.path.splitext(filename)
                
                if base_name not in content_map:
                    content_map[base_name] = {}
                
                if extension.lower() in ['.mp4', '.mov', '.avi']:
                    content_map[base_name]['video'] = filename
                elif extension.lower() in ['.jpg', '.jpeg', '.png']:
                    content_map[base_name]['thumbnail'] = filename

            for base_name, assets in content_map.items():
                if 'video' in assets:
                    thumbnail_url = PLACEHOLDER_THUMBNAIL
                    if 'thumbnail' in assets:
                        thumbnail_url = s3_client.generate_presigned_url(
                            'get_object',
                            Params={'Bucket': S3_BUCKET, 'Key': assets['thumbnail']},
                            ExpiresIn=3600
                        )
                    
                    videos.append({
                        'key': assets['video'],
                        'thumbnail_url': thumbnail_url
                    })
    except Exception as e:
        print(f"Error fetching from S3: {e}")
        pass
        
    return render_template('index.html', videos=videos)

@app.route('/watch')
def watch_video():
    video_key = request.args.get('video_id')
    video_url = ""
    if video_key:
        try:
            video_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': S3_BUCKET, 'Key': video_key},
                ExpiresIn=3600
            )
        except Exception as e:
            print(f"Error generating URL for {video_key}: {e}")
            pass
    return render_template('watch.html', video_url=video_url)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)