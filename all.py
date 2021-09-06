from flask import Flask,render_template, url_for,flash,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_manager,UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
from flask_login.utils import login_user, logout_user,current_user
from werkzeug.utils import redirect



app = Flask(__name__)
app.config['SECRET_KEY']='804e28ec72d04aac00960038'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///mytask.db'
db=SQLAlchemy(app)
# extend_existing=True

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
# login_manager=LoginManager(app)
login_manager.login_view="login_page"
login_manager.login_message_category="Info"

# **********************************************************models*************************************

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,UserMixin):
    id=db.Column(db.Integer(),primary_key=True)
    username=db.Column(db.String(length=50),nullable=False,unique=True)
    email_address=db.Column(db.String(length=50),nullable=False,unique=True)
    password_hash=db.Column(db.String(length=50),nullable=True)
    tasks = db.relationship('Task', backref='owner',lazy=True)
    # __table_args__ = {'extend_existing': True}

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self,plan_text_password):
        self.password_hash=bcrypt.generate_password_hash(plan_text_password).decode('utf-8')

    def password_to_check(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    def __repr__(self):
        return f"{self.username} {self.email_address} {self.password_hash}"


class Task(db.Model,UserMixin):
    id=db.Column(db.Integer(), primary_key=True)
    title=db.Column(db.String(length=80), nullable=False)
    desc=db.Column(db.String(length=150), nullable=False)
    date=db.Column(db.String(50), default=datetime.now().strftime("%d/%m/%y  %H:%M:%S"))
    oner_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    # __table_args__ = {'extend_existing': True}

    
    def __repr__(self):
        return f"{self.title} {self.desc} {self.owner}"


db.create_all()

    


# ****************************************************************************forms***********************

class LoginForm(FlaskForm):
    username=StringField(label='User Name', validators=[DataRequired()])
    password=PasswordField(label='Password',validators=[DataRequired()])
    submit=SubmitField(label='Sign In')

class RegisterForm(FlaskForm):

    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    confirm_password = PasswordField(label='Confirm Password:', validators=[EqualTo('password'), DataRequired()])
    submit = SubmitField(label='Create Account')

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')

    

class TaskForm(FlaskForm):
    title=StringField(label='Title',validators=[DataRequired()])
    desc=StringField(label='Description',validators=[DataRequired()])
    submit=SubmitField('Add Task')

class UpdateForm(FlaskForm):
    title=StringField(label='Update Title',validators=[DataRequired()])
    desc=StringField(label='Update Description',validators=[DataRequired()])
    submit=SubmitField('Update Task')

class DeleteForm(FlaskForm):
    submit=SubmitField('Delete Task')

class ClearAll(FlaskForm):
    submit=SubmitField('Clear All')

# *************************************************************routes*************************************


@app.route('/')
def home_page():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form=LoginForm()
    if form.validate_on_submit():
        attempted_user=User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.password_to_check(attempted_password=form.password.data):
            login_user(attempted_user)
            flash('You have successfully loged in', category='success')
            return redirect(url_for('task_page'))
        else:
            flash('User name or password not matched',category='danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register_page():
    form=RegisterForm()
    if form.validate_on_submit():
        create_user=User(username=form.username.data, email_address=form.email_address.data, password=form.password.data)
        db.session.add(create_user)
        db.session.commit()
        login_user(create_user)
        flash(f"Account created successfully!",category='success')
        return redirect(url_for('task_page'))
    if form.errors !={}:
        for err_msg in form.errors.values():
            flash(f"There was an error with creating an user :{err_msg}", category='danger') 
        
    return render_template('register.html',form=form)

@app.route('/task', methods=['GET','POST'])
def task_page():
    delete_form=DeleteForm()
    task_form=TaskForm()
    clearall_form=ClearAll()
    update_form=UpdateForm()

    if request.method=='POST':
        if request.form.get('delete_task')!=None:
            delete_task_id=request.form.get('delete_task')
            delete_task=Task.query.filter_by(id=delete_task_id).first()
            db.session.delete(delete_task)
            db.session.commit()
            flash('Your task is deleted!',category='success')
            return redirect(url_for('task_page'))

        if request.form.get("clear_task")!=None:
            tasks=Task.query.filter_by(oner_id=current_user.id)
            for task in tasks:
                db.session.delete(task)
            db.session.commit()
            flash('You have no tasks, create an one!',category='success')
            return redirect(url_for('task_page'))

        if request.form.get("tk")==None:
            if task_form.validate_on_submit():
                add_task=Task(title=task_form.title.data, desc=task_form.desc.data,owner=current_user)
                db.session.add(add_task)
                db.session.commit()
                
                return redirect(url_for('task_page'))
                

        else :
            task_id = request.form.get('tk')
            updated_task=Task.query.filter_by(id=int(task_id)).first()
            updated_task.title=update_form.title.data
            updated_task.desc=update_form.desc.data
            updated_task.date=datetime.now().strftime("%d/%m/%y  %H:%M:%S")
            db.session.commit()
            flash('Your task is updated!', category='success')
            return redirect(url_for('task_page'))

        

    return render_template('task.html',update_form=update_form,task_form=task_form, delete_form=delete_form, clearall_form=clearall_form)


@app.route('/logout')
def logout_page():
    logout_user()
    flash('You have been logged out!',category='danger')
    return redirect(url_for('home_page'))



if __name__=="__main__":
    app.run(debug=False)