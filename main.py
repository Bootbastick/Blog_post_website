from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy import URL
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI", 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Base = declarative_base()


# CONFIGURE TABLES
class User(db.Model, UserMixin, Base):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False, unique=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

    @property
    def is_admin(self):
        return self.id == 1


class BlogPost(db.Model, Base):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(view):
    @wraps(view)
    def inner_function(*args, **kwargs):
        if current_user.is_admin:
            return view(*args, **kwargs)
        else:
            abort(403)

    return inner_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm
    if request.method == "POST" and form.validate_on_submit():
        user_email = request.form["email"]

        if User.query.filter_by(email=user_email).first():
            flash("This email is already registered, log in!", "email_exists")
            return redirect(url_for("login"))

        new_user = User(
            email=user_email,
            password=generate_password_hash(request.form["password"]),
            name=request.form["name"]
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=RegisterForm(request.form))


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm
    if request.method == "POST" and form.validate_on_submit():
        user = User.query.filter_by(email=request.form["email"]).first()

        if not user:
            flash("Given email doesn't exist in the database, please try again!", "email_doesnt_exist")
            return redirect(url_for("login"))

        hashed_user_password = user.password

        if not check_password_hash(hashed_user_password, request.form["password"]):
            flash("The password is incorrect, please try again!", "wrong_password")
            return redirect(url_for("login"))

        login_user(user)

        return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=LoginForm(request.form))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm(request.form)
    comments = Comment.query.all()
    author = User.query.filter_by(id=current_user.get_id()).first()
    parent_post = BlogPost.query.filter_by(id=post_id).first()

    if form.validate_on_submit():
        if not current_user.is_active:
            flash("You have to be logged in to post comments!", "login_required")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=request.form["comment"],
            author=author,
            parent_post=parent_post
        )

        db.session.add(new_comment)
        db.session.commit()

        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        author = User.query.filter_by(id=current_user.get_id()).first()
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=author,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
