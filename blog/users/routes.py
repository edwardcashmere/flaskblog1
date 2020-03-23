from flask import Blueprint, url_for, redirect, render_template, flash, request
from flask_login import current_user,login_required, login_user, logout_user
from blog import db, bcrypt
from blog.models import User, Post
from blog.users.forms import RegistrationForm, LoginForm, UpdateAccount, RequestResetForm, ResetPasswordForm
from blog.users.utils import save_picture,send_reset_email

users=Blueprint('users',__name__)

@users.route("/register",methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_pw=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user=User(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created. Login now !', 'success')
        return redirect(url_for('users.login'))
    return render_template("register.html",form=form,title='register', legend='Join Today')
@users.route("/login",methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page=request.args.get('next')
            return redirect(next_page) if next_page else  redirect(url_for('main.home'))

        else:
            flash('Login unsucessful, check email or password','danger')
    return render_template("login.html",form=form,title='login', legend='Login')

@users.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@users.route('/account', methods=['GET','POST'])
@login_required
def account():
    form=UpdateAccount()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file=save_picture(form.picture.data)
            current_user.image_file=picture_file
        current_user.username=form.username.data
        current_user.email=form.email.data
        db.session.commit()
        flash('Your account has been updated','success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data=current_user.username
        form.email.data=current_user.email
    image_file=url_for('static',filename='profile/' + current_user.image_file)
    return render_template('account.html', title='account', image_file=image_file, form=form)


@users.route('/post/<string:username>/')
@login_required
def user_post(username):
    page=request.args.get('page', 1, type=int)
    user=User.query.filter_by(username=username).first_or_404()
    posts=Post.query.filter_by(user=user)\
    .order_by(Post.date_posted.desc())\
    .paginate(page=page, per_page=5)
    return render_template('user_post.html', user=user, posts=posts, legend='')

@users.route('/reset_password', methods=['GET','POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form=RequestResetForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent to your account with instructions on how to reset your password','info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html', form=form, title='Reset Password',legend='Reset Password')

@users.route('/reset_password/<token>',methods=['GET','POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user=User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token','warning')
        return redirect(url_for('users.reset_request'))
    form=ResetPasswordForm()
    if form.validate_on_submit():
        hashed_pw=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password=hashed_pw
        db.session.commit()
        flash('Your password has been updated please log in!,success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html',form=form, title='reset password',legend='Reset Password')
