# main.py
# --- Imports ---
import os
import bcrypt
import jwt
import mysql.connector # Import the base connector library
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from mysql.connector import pooling

# --- Initialization ---
load_dotenv()
app = Flask(__name__, template_folder='templates')
CORS(app)

# --- Secret Key for JWT ---
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "your-fallback-super-secret-key")

# --- Database Connection Pool Setup ---
try:
    db_config = {
        "host": os.getenv("DB_HOST"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "database": os.getenv("DB_NAME"),
    }
    cnx_pool = pooling.MySQLConnectionPool(pool_name="api_pool",
                                           pool_size=5,
                                           **db_config)
    print("Database connection pool created successfully.")
# --- CORRECTED ERROR HANDLING ---
except mysql.connector.Error as err:
    print(f"FATAL: A MySQL error occurred: {err}")
    exit(1)
# --- END CORRECTION ---
except Exception as e:
    print(f"FATAL: A generic error occurred: {e}")
    exit(1)

# --- Routes to Serve Frontend Pages ---
@app.route('/')
def serve_index():
    return render_template('index.html')

@app.route('/login')
def serve_login():
    return render_template('login.html')

@app.route('/register')
def serve_register():
    return render_template('register.html')

# --- Authentication Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            connection = cnx_pool.get_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT id, email FROM users WHERE id = %s", (data['user_id'],))
            current_user = cursor.fetchone()
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 401
        finally:
            if 'connection' in locals() and connection.is_connected():
                cursor.close()
                connection.close()
        if not current_user:
             return jsonify({'message': 'User not found!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Authentication API Routes ---
@app.route('/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        connection = cnx_pool.get_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({'message': 'User with this email already exists!'}), 409
        cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hashed_password.decode('utf-8')))
        connection.commit()
        return jsonify({'message': 'New user created successfully!'}), 201
    except Exception as e:
        return jsonify({'message': f'Could not create user. Error: {e}'}), 500
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/auth/login', methods=['POST'])
def login_user():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401
    try:
        connection = cnx_pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, email, password_hash FROM users WHERE email = %s", (auth['email'],))
        user = cursor.fetchone()
        if not user or not bcrypt.checkpw(auth['password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'message': 'Invalid email or password!'}), 401
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    except Exception as e:
        return jsonify({'message': f'Login failed. Error: {e}'}), 500
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

# --- Task CRUD API Routes (Protected) ---
@app.route('/api/tasks', methods=['GET'])
@token_required
def get_all_tasks(current_user):
    try:
        connection = cnx_pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, title, is_completed FROM tasks WHERE user_id = %s", (current_user['id'],))
        tasks = cursor.fetchall()
        return jsonify(tasks)
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.get_json()
    title = data.get('title')
    if not title:
        return jsonify({'message': 'Title is required!'}), 400
    try:
        connection = cnx_pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("INSERT INTO tasks (title, user_id) VALUES (%s, %s)", (title, current_user['id']))
        new_task_id = cursor.lastrowid
        connection.commit()
        cursor.execute("SELECT id, title, is_completed FROM tasks WHERE id = %s", (new_task_id,))
        new_task = cursor.fetchone()
        return jsonify(new_task), 201
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    data = request.get_json()
    update_fields, params = [], []
    if 'title' in data:
        update_fields.append("title = %s")
        params.append(data['title'])
    if 'is_completed' in data:
        update_fields.append("is_completed = %s")
        params.append(data['is_completed'])
    if not update_fields:
        return jsonify({'message': 'No update data provided!'}), 400
    query = f"UPDATE tasks SET {', '.join(update_fields)} WHERE id = %s AND user_id = %s"
    params.extend([task_id, current_user['id']])
    try:
        connection = cnx_pool.get_connection()
        cursor = connection.cursor()
        cursor.execute(query, tuple(params))
        connection.commit()
        if cursor.rowcount == 0:
            return jsonify({'message': 'Task not found or unauthorized.'}), 404
        return jsonify({'message': 'Task updated successfully!'})
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    try:
        connection = cnx_pool.get_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM tasks WHERE id = %s AND user_id = %s", (task_id, current_user['id']))
        connection.commit()
        if cursor.rowcount == 0:
            return jsonify({'message': 'Task not found or unauthorized.'}), 404
        return jsonify({'message': 'Task deleted successfully!'})
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

# --- Main Execution ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
