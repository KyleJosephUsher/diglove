import os
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_migrate import Migrate
from  flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_
print("Current working directory:", os.getcwd())
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # CHANGE THIS to a real secret in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///date_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/profile_pics')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Max 5MB upload
socketio = SocketIO(app)
FERNET_KEY = os.getenv("FERNET_KEY")

app.secret_key = os.getenv("SECRET_KEY")
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_age(born):
    today = date.today()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


def get_matches_count(user_id):
    return Match.query.filter(
        or_(Match.user1_id == user_id, Match.user2_id == user_id)
    ).count()

def get_meetups_count(user_id):
    return Meetup.query.filter(
        or_(Meetup.user1_id == user_id, Meetup.user2_id == user_id)
    ).count()

def get_recent_matches(user_id, limit=5):
    matches = Match.query.filter(
        or_(Match.user1_id == user_id, Match.user2_id == user_id)
    ).order_by(Match.created_at.desc()).limit(limit).all()

    recent_users = []
    for match in matches:
        if match.user1_id == user_id:
            recent_users.append(User.query.get(match.user2_id))
        else:
            recent_users.append(User.query.get(match.user1_id))
    return recent_users

def get_upcoming_meetups(user_id, limit=5):
    now = datetime.utcnow()
    meetups = Meetup.query.filter(
        and_(
            or_(Meetup.user1_id == user_id, Meetup.user2_id == user_id),
            Meetup.date > now
        )
    ).order_by(Meetup.date.asc()).limit(limit).all()

    for meetup in meetups:
        meetup.with_user = User.query.get(meetup.user2_id if meetup.user1_id == user_id else meetup.user1_id)
    return meetups

# MODELS

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    gender = db.Column(db.String(20))
    interests = db.Column(db.String(200))
    location = db.Column(db.String(100))
    profile_pic = db.Column(db.String(200))  # e.g., "profile_pics/filename.jpg"

    one_night = db.Column(db.Boolean, default=False)
    threesome_interest = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    coins = db.Column(db.Integer, default=0)
    dob = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    sexual_orientation = db.Column(db.String(100))
    verified = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20))

    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

    rewards_received = db.relationship('Reward', foreign_keys='Reward.receiver_id', backref='rewarded_user', lazy=True)
    rewards_sent = db.relationship('Reward', foreign_keys='Reward.sender_id', backref='reward_sender', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
    
class CoinTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # + for purchase, - for usage
    type = db.Column(db.String(20), nullable=False)  # 'purchase', 'like', 'video_chat', etc.
    method = db.Column(db.String(50))  # mpesa, stripe, paypal, internal
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='coin_transactions')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} to {self.receiver_id}>'
class Hookup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<Hookup {self.id} from user {self.user_id} to user {self.target_user_id}>'
    
class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f'<Story {self.id} by User {self.user_id}>'

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

    def __repr__(self):
        return f'<Match between User {self.user1_id} and User {self.user2_id}>'
    
class Threesome(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user3_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])
    user3 = db.relationship('User', foreign_keys=[user3_id])

    def __repr__(self):
        return f'<Threesome between Users {self.user1_id}, {self.user2_id}, and {self.user3_id}>'

class Meetup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(150))
    date_time = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    organizer = db.relationship('User', backref='organized_meetups', lazy=True)

    def __repr__(self):
        return f'<Meetup "{self.title}" organized by User {self.organizer_id} on {self.date_time}>'
class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reward_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_rewards', lazy=True)
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_rewards', lazy=True)

    def __repr__(self):
        return f'<Reward {self.reward_type} from User {self.sender_id} to User {self.receiver_id}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

LIKE_COST = 5
MEETUP_COST = 10
VIDEOCHAT_COST = 15

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# ROUTES


@app.route('/')
@login_required
def home():
    matches_count = get_matches_count(current_user.id)
    meetups_count = get_meetups_count(current_user.id)
    recent_matches = get_recent_matches(current_user.id)
    upcoming_meetups = get_upcoming_meetups(current_user.id)

    return render_template(
        'home.html',
        matches_count=matches_count,
        meetups_count=meetups_count,
        recent_matches=recent_matches,
        upcoming_meetups=upcoming_meetups,
    )

def get_matches_count(user_id):
    # Count the number of matches where user is either user1 or user2
    return Match.query.filter(
        (Match.user1_id == user_id) | (Match.user2_id == user_id)
    ).count()

def get_meetups_count(user_id):
    # Count upcoming meetups organized by the user (future dates only)
    return Meetup.query.filter(
        Meetup.organizer_id == user_id,
        Meetup.date_time >= datetime.utcnow()
    ).count()

def get_recent_matches(user_id, limit=6):
    # Get the most recent matches involving the user, limit to 'limit'
    matches = Match.query.filter(
        (Match.user1_id == user_id) | (Match.user2_id == user_id)
    ).order_by(Match.timestamp.desc()).limit(limit).all()

    # Extract the other user from each match
    users = []
    for match in matches:
        other_user = match.user2 if match.user1_id == user_id else match.user1
        users.append(other_user)
    return users

def get_upcoming_meetups(user_id, limit=5):
    # Get upcoming meetups organized by the user, ordered by date
    return Meetup.query.filter(
        Meetup.organizer_id == user_id,
        Meetup.date_time >= datetime.utcnow()
    ).order_by(Meetup.date_time.asc()).limit(limit).all()

@app.route('/coin-history')
@login_required
def coin_history():
    transactions = CoinTransaction.query.filter_by(user_id=current_user.id).order_by(CoinTransaction.timestamp.desc()).all()
    return render_template('coin_history.html', transactions=transactions)

@app.route('/request_meetup/<int:user_id>', methods=['POST'])
@login_required
def request_meetup(user_id):
    if 'safe_sex' not in request.form:
        flash("You must agree to practice safe sex before requesting a meetup.", "danger")
        return redirect(url_for('meetups'))

    # Your existing meetup request logic here
    # e.g., create meetup request record, send notifications, etc.

    flash("Meetup request sent successfully!", "success")
    return redirect(url_for('meetups'))

@app.route('/some_route')
def some_route():
    now = datetime.utcnow()
    # pass 'now' explicitly
    return render_template('your_template.html', now=now,)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        gender = request.form.get('gender')
        age = request.form.get('age')
        location = request.form.get('location')
        interests_list = request.form.getlist('interests')
        profile_pic = request.files.get('profile_pic')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('signup'))

        interests = ",".join(interests_list)

        user = User(
            username=name,
            email=email,
            gender=gender,
            age=int(age) if age else None,
            location=location,
            interests=interests,
            coins=10  # default coins
        )

        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            unique_filename = f"{email}_{int(datetime.utcnow().timestamp())}_{filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            profile_pic.save(save_path)
            user.profile_pic = unique_filename

        user.password_hash = generate_password_hash(password)

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/videochat/<int:user_id>')
@login_required
def video_chat(user_id):
    target_user = User.query.get_or_404(user_id)
    # Generate a unique room id (could be a combination of user ids or a UUID)
    room_id = f"room_{min(current_user.id, user_id)}_{max(current_user.id, user_id)}"
    return render_template('video_chat.html', target_user=target_user, room_id=room_id)

@app.route('/buy_coins', methods=['GET', 'POST'])
@login_required
def buy_coins():
    if request.method == 'POST':
        amount = request.form.get('amount')
        payment_method = request.form.get('payment_method')

        # Validate amount
        try:
            coins_to_add = int(amount)
            if coins_to_add <= 0:
                raise ValueError("Amount must be positive")
        except (ValueError, TypeError):
            flash('❌ Invalid amount selected. Please choose a valid coin package.', 'danger')
            return redirect(url_for('buy_coins'))

        # Validate payment method
        valid_methods = ['mpesa', 'paypal', 'stripe']
        if payment_method not in valid_methods:
            flash('❌ Invalid payment method selected.', 'danger')
            return redirect(url_for('buy_coins'))

        # TODO: Integrate actual payment gateway here (M-Pesa, PayPal, Stripe)

        # Simulate successful payment
        current_user.coins = (current_user.coins or 0) + coins_to_add

        # Create transaction record
        new_tx = CoinTransaction(
            user_id=current_user.id,
            amount=coins_to_add,
            method=payment_method,
            type='purchase',
            timestamp=datetime.utcnow()
        )
        db.session.add(new_tx)
        db.session.commit()

        flash(f'🎉 Successfully purchased {coins_to_add} coins using {payment_method.title()}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('buy_coins.html')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        gender = request.form.get('gender')
        interests = request.form.get('interests')
        location = request.form.get('location')
        one_night = bool(request.form.get('one_night'))
        threesome_interest = bool(request.form.get('threesome_interest'))
        protection = request.form.get('protection')
        dob = request.form.get('dob')

        # Unique user checks
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        # Validate DOB & Age
        try:
            dob_date = datetime.strptime(dob, '%Y-%m-%d')
            today = datetime.today()
            age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))

            if age < 18:
                flash("You must be 18 or older to register.", "danger")
                return redirect(url_for('register'))
        except Exception:
            flash("Invalid date of birth.", "danger")
            return redirect(url_for('register'))

        # Protection agreement
        if protection != "on":
            flash("Please agree to use protection and follow safety guidelines.", "warning")
            return redirect(url_for('register'))

        # Profile picture upload
        profile_pic = None
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            profile_pic_path = os.path.join('profile_pics', filename)
            file.save(os.path.join(app.static_folder, profile_pic_path))
            profile_pic = profile_pic_path

        # Create and store new user
        user = User(
            username=username,
            email=email,
            gender=gender,
            interests=interests,
            location=location,
            one_night=one_night,
            threesome_interest=threesome_interest,
            profile_pic=profile_pic,
            dob=dob_date
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')
# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        identifier = request.form.get('email_or_username')  # Matches your form
        password = request.form.get('password')

        # Query user by email or username
        user = User.query.filter(
            (User.email == identifier) | (User.username == identifier)
        ).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email/username or password.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have logged out.", "info")
    return redirect(url_for('home'))


# DASHBOARD
@app.route('/dashboard')
@login_required
def dashboard():
    # Query all users except the current logged-in user
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('dashboard.html', users=users)

@app.route('/like/<int:user_id>', methods=['POST'])
@login_required
def send_like(user_id):
    user_to_like = User.query.get_or_404(user_id)

    # Prevent liking self or duplicate likes
    if user_to_like == current_user or user_to_like in current_user.liked_users:
        flash("You've already liked this user.", "info")
        return redirect(url_for('dashboard'))

    # Check if user has enough coins
    if (current_user.coins or 0) < LIKE_COST:
        coin_word = "coin" if LIKE_COST == 1 else "coins"
        flash(f"You need at least {LIKE_COST} {coin_word} to like someone.", "danger")
        return redirect(url_for('buy_coins'))

    # Deduct coins
    current_user.coins -= LIKE_COST

    # Add like relationship
    current_user.liked_users.append(user_to_like)

    # Log coin spend transaction
    spend_tx = CoinTransaction(
        user_id=current_user.id,
        amount=-LIKE_COST,
        method='like',
        type='spend'
    )
    db.session.add(spend_tx)

    # Add reward record
    reward = Reward(sender_id=current_user.id, receiver_id=user_to_like.id, type='like')
    db.session.add(reward)

    # Commit all changes in one go
    db.session.commit()

    coin_word = "coin" if LIKE_COST == 1 else "coins"
    flash(f"You liked {user_to_like.username} and spent {LIKE_COST} {coin_word}.", "success")
    return redirect(url_for('dashboard'))

# PROFILE VIEW & EDIT with file upload
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update user profile fields
        current_user.username = request.form.get('username') or current_user.username
        current_user.gender = request.form.get('gender') or current_user.gender
        current_user.interests = request.form.get('interests') or current_user.interests
        current_user.location = request.form.get('location') or current_user.location

        # Handle profile picture upload
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = int(datetime.utcnow().timestamp())
            unique_filename = f"{current_user.id}_{timestamp}_{filename}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(upload_path)
            current_user.profile_pic = f"profile_pics/{unique_filename}"

        db.session.commit()
        flash("✅ Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html')

# CHAT route 
@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    chat_user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        content = request.form.get('message')
        if content:
            msg = Message(sender_id=current_user.id, receiver_id=user_id, content=content)
            db.session.add(msg)
            db.session.commit()
            flash("Message sent!", "success")
            return redirect(url_for('chat', user_id=user_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

@app.route('/unlike_user/<int:user_id>', methods=['POST'])
@login_required
def unlike_user(user_id):
    user_to_unlike = User.query.get_or_404(user_id)

    if user_to_unlike not in current_user.liked_users:
        flash("You haven't liked this user.", "warning")
        return redirect(url_for('likes'))

    # Remove like
    current_user.liked_users.remove(user_to_unlike)

    # Optional: remove reward too
    reward = Reward.query.filter_by(
        sender_id=current_user.id,
        receiver_id=user_to_unlike.id,
        type='like'
    ).first()
    if reward:
        db.session.delete(reward)

    # Optional: refund coin
    current_user.coins += 1
    db.session.commit()

    flash(f"You unliked {user_to_unlike.username}. 1 coin refunded.", "info")
    return redirect(url_for('likes'))

    return render_template('chat.html', chat_user=chat_user, messages=messages)


# HOOKUPS route
@app.route('/hookups')
@login_required
def hookups():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('hookups.html', users=users)


# SEND REWARD route (example for 'like')
@app.route('/send_reward/<int:user_id>/<reward_type>')
@login_required
def send_reward(user_id, reward_type):
    receiver = User.query.get_or_404(user_id)
    reward = Reward(sender_id=current_user.id, receiver_id=receiver.id, reward_type=reward_type)
    db.session.add(reward)
    db.session.commit()
    flash(f"{reward_type.capitalize()} sent to {receiver.username}!", "success")
    return redirect(url_for('hookups'))


# MATCHES route
@app.route('/matches')
@login_required
def matches():
    # Simple example: matches where current_user is user1 or user2
    matches = Match.query.filter(
        (Match.user1_id == current_user.id) | (Match.user2_id == current_user.id)
    ).all()
    return render_template('matches.html', matches=matches)


# THREESOMES route
@app.route('/threesomes')
@login_required
def threesomes():
    # Simple example: threesomes where current_user is one of the users
    threesomes = Threesome.query.filter(
        (Threesome.user1_id == current_user.id) |
        (Threesome.user2_id == current_user.id) |
        (Threesome.user3_id == current_user.id)
    ).all()
    return render_template('threesomes.html', threesomes=threesomes)


# MEETUPS routes
@app.route('/meetups')
@login_required
def meetups():
    meetups = Meetup.query.order_by(Meetup.date_time.asc()).all()
    return render_template('meetups.html', meetups=meetups)

@app.route('/browse')
@login_required
def browse():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('browse.html', users=users)
@app.route('/stories')
@login_required
def stories():
    stories = Story.query.order_by(Story.timestamp.desc()).all()
    return render_template('stories.html', stories=stories)

@app.route('/story/new', methods=['GET', 'POST'])
@login_required
def create_story():
    if request.method == 'POST':
        caption = request.form.get('caption')
        media_file = request.files.get('media')

        media_filename = None
        if media_file and media_file.filename != "":
            filename = secure_filename(media_file.filename)
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            media_file.save(media_path)
            media_filename = filename

        new_story = Story(
            user_id=current_user.id,
            caption=caption,
            media=media_filename,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_story)
        db.session.commit()
        flash('✅ Story posted successfully!', 'success')
        return redirect(url_for('stories'))

    return render_template('new_story.html')

@app.route('/meetup/create', methods=['GET', 'POST'])
@login_required
def create_meetup():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location')
        date_time_str = request.form.get('date_time')

        try:
            date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Invalid date/time format.", "danger")
            return redirect(url_for('create_meetup'))

        meetup = Meetup(
            organizer_id=current_user.id,
            title=title,
            description=description,
            location=location,
            date_time=date_time
        )
        db.session.add(meetup)
        db.session.commit()
        flash("Meetup created successfully!", "success")
        return redirect(url_for('meetups'))

    return render_template('create_meetup.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('message', {'data': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('chat_message')
def handle_chat_message(data):
    # data is a dict sent from client, e.g. {'msg': 'Hello!'}
    print('Received message:', data['msg'])
    emit('chat_response', {'msg': data['msg']}, broadcast=True)  # broadcast to all clients

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'User has joined room {room}'}, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'User has left room {room}'}, room=room)

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
    