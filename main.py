import os

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get("DB_URI", "sqlite:///blog.db")
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    first_name = db.Column(db.String(250), nullable=False)
    last_name = db.Column(db.String(250), nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
    posts = relationship("BlogPost", back_populates="author")

    def __repr__(self):
        return f"{self.email} {self.first_name}"


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return f"{self.title}"


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            print("not authenticated")
        if not current_user.is_authenticated or current_user.id != 8:
            print("not authenticated")
            abort(403, description="Authorization not allowed for this page")
        else:
            print("not authenticated")
            return function(*args, **kwargs)
    return wrapper


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    print(user_id)
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        return render_template("index.html", all_posts=posts, name=f"{current_user.first_name}'s")
    else:
        return render_template("index.html", all_posts=posts, name="Home of the")


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        first_name = form.first_name.data
        last_name = form.last_name.data
        birthdate = form.birthday.data
        user = User.query.filter_by(email=email).first()
        if user:
            flash("We already have an email registered with you. Log in instead!")
            return redirect(url_for('login'))
        else:
            new_user = User(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                birthdate=birthdate
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            # User already exists
            if check_password_hash(user.password, password):
                login_user(user)
                flash("Logged in successfully.")
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password incorrect, please try again.")
                return render_template("login.html", form=form)
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    print("add new post")
    if form.validate_on_submit():
        print("added new post")
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    else:
        print("Didn't work")
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=False)
