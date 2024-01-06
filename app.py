import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, FloatField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo


load_dotenv() 


app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration for SQLAlchemy with MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    energy_data = db.relationship('EnergyData', back_populates='user')
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        # Flask-Login integration
    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class EnergyData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False)
    consumption = db.Column(db.Float, nullable=False)  
    energy_type = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  

    user = db.relationship('User', back_populates='energy_data')

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'EnergyData': EnergyData}


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EnergyDataForm(FlaskForm):
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    energy_usage = FloatField('Energy Usage', validators=[DataRequired()])
    energy_type = SelectField(
        'Energy Type', 
        choices=[('electricity', 'Electricity'), ('gas', 'Gas'), ('water', 'Water')],
        validators=[DataRequired()]
    )
    submit = SubmitField('Submit')



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print("Form submitted successfully")
        print("Username:", form.username.data)
        print("Email:", form.email.data)
        user = User(username=form.username.data, 
                    email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        print("Form Data:", form.data)
        print("Form Errors:", form.errors)
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'error') 
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/profile')
@login_required
def profile():

    return render_template('profile.html', user=current_user)
    

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/add-data', methods=['GET', 'POST'])
@login_required
def add_data():
    form = EnergyDataForm()
    if form.validate_on_submit():
        energy_data = EnergyData(
            date=form.date.data,
            consumption=form.energy_usage.data,
            energy_type=form.energy_type.data,
            user_id=current_user.id 
        )
        db.session.add(energy_data)
        db.session.commit()
        flash('Energy data added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_data.html', form=form)




@app.route('/view-data')
@login_required
def view_data():
    # Data retrieval and presentation logic will go here
    return render_template('view_data.html')

if __name__ == '__main__':
    app.run(debug=True)


