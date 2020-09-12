from flask import Flask, render_template, jsonify, request, session, redirect
from flask_pymongo import PyMongo
from functools import wraps
from passlib.hash import sha256_crypt, pbkdf2_sha256
import uuid


app = Flask(__name__)
app.secret_key = b'\x17y<a\xac\x85i\xcby\x1b[\x86\xba\x13E\x80'

#Database
app.config["MONGO_URI"] = "mongodb://localhost:27017/flaskApp"
mongo = PyMongo(app) 

#Decorators
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return wrap

#Classes
class User:
    def start_session(self, user):
        del user['password']
        session['logged_in'] = True
        session['user'] = user
        return jsonify(user), 200 

    def signup(self):
        
        #Create the user object
        user = {
             "_id": uuid.uuid4().hex,
             "name": request.form.get('name'),
             "email": request.form.get('email'),
             "password": request.form.get('password')
        }

        #Encrypt the password
        user['password']  = pbkdf2_sha256.encrypt(user['password'])
        
        # Check for existing email address 
        if mongo.db.users.find_one({ "email": user['email']}):
           return jsonify({ "error": "Email address already exists" }), 400 

        mongo.db.users.insert(user)
        return self.start_session(user)

    def signout(self):
        session.clear()
        return redirect('/')
    
    def login(self):
        user = mongo.db.users.find_one({
            "email": request.form.get('email')
        })

        if  not user:
            return  jsonify({"error": "Invalid email"}), 401

        elif not pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return  jsonify({"error": "Invalid password"}), 401
        
        return self.start_session(user) #jsonify({"error": "Invalid credentials"}), 401
   

#Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register')
def register(): 
    return render_template('register.html')

@app.route('/user/signup', methods=['POST'])
def signup():
    return User().signup()

@app.route('/dashboard/')
@login_required
def dashboard():
  return render_template('dashboard.html')

@app.route('/user/signout')
def signout():
    return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
    return User().login()

if __name__ == '__main__':
    app.run(debug=True)