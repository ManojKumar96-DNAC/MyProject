from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import csv

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# List of users (normally this would be stored securely in a database)
users = []

devices = [
    {'id': 1, 'name': 'Device1', 'assigned_to': None},
    {'id': 2, 'name': 'Device2', 'assigned_to': None},
    {'id': 3, 'name': 'Device3', 'assigned_to': None},
]

def assign_device(device_id, user_id):
    for device in devices:
        if device['id'] == device_id:
            device['assigned_to'] = user_id
            break

def save_assignments_to_csv(file_path):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Device Name', 'Assigned To'])
        for device in devices:
            user_name = next((user['username'] for user in users if user['id'] == device['assigned_to']), 'None')
            writer.writerow([device['name'], user_name])

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', devices=devices, users=users)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('index'))
        return 'Invalid username or password'
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = {'id': len(users) + 1, 'username': username, 'password': hashed_password}
            users.append(new_user)
            print(f"New user added: {new_user}")  # Debugging statement
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during signup: {e}")  # Debugging statement
            return f"An error occurred during signup: {e}"
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/assign', methods=['POST'])
def assign():
    if 'username' not in session:
        return redirect(url_for('login'))
    device_id = int(request.form['device_id'])
    user_id = int(request.form['user_id'])
    assign_device(device_id, user_id)
    save_assignments_to_csv('assignments.csv')
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
