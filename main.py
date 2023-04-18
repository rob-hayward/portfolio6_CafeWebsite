from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms.validators import DataRequired, URL, ValidationError, Length, EqualTo
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, BooleanField, SubmitField, PasswordField
from flask_migrate import Migrate
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecretkey123'  # Add this line
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # This is the function name for the login route


class AddCafeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    img_url = StringField('Image URL', validators=[DataRequired(), URL()])
    has_sockets = BooleanField('Power Sockets')
    has_toilet = BooleanField('Toilet Facilities')
    has_wifi = BooleanField('Wi-Fi')
    can_take_calls = BooleanField('Can Take Calls')
    seats = IntegerField('Number of Seats', validators=[DataRequired()])
    coffee_price = StringField('Coffee Price', validators=[DataRequired()])
    map_url = StringField('Map URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Add Cafe')


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.Integer, nullable=False)
    coffee_price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", name="fk_cafe_user"), nullable=False)
    user = db.relationship("User", backref="user_cafes")


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    cafes = db.relationship('Cafe', lazy='dynamic')

    def check_password(self, password):
        return check_password_hash(self.password, password)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    cafes = Cafe.query.all()
    print(cafes)
    return render_template('home.html', cafes=cafes)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # You should hash the password before storing it
        hashed_password = generate_password_hash(password, method='sha256')
        # Check if a user with the same email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists', 'danger')
            return redirect(url_for('register'))
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Thank you for registering!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/add-cafe', methods=['GET', 'POST'])
@login_required
def add_cafe():
    form = AddCafeForm()
    if form.validate_on_submit():
        with app.app_context():
            cafe = Cafe(name=form.name.data, location=form.location.data, img_url=form.img_url.data, has_sockets=form.has_sockets.data, has_toilet=form.has_toilet.data, has_wifi=form.has_wifi.data, can_take_calls=form.can_take_calls.data, seats=form.seats.data, coffee_price=form.coffee_price.data, map_url=form.map_url.data, user_id=current_user.id)
            db.session.add(cafe)
            db.session.commit()
            flash('Cafe added successfully', 'success')
            return redirect(url_for('home'))
    return render_template('add-cafe.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
