from flask import Flask, render_template, request,redirect, url_for, flash,send_file,session
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from form import RegisterForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os



app = Flask(__name__)

ENV = 'prod'

if ENV == 'prod':
    app.debug = True
    app.config['SECRET_KEY'] ="gocorona"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://postgres:spoo88#asA@localhost/rove'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
else:
    app.debug = False
    app.config['SECRET_KEY'] = ''
    app.config['SQLALCHEMY_DATABASE_URI'] = ''
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


bootstrap = Bootstrap(app)
db= SQLAlchemy(app) 

login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = 'login'

#Models(Tables):

class User(UserMixin,db.Model):
    __tablename__ = 'User_login'
    id = db.Column(db.Integer, primary_key = True) 
    username = db.Column(db.String(15),unique=True)
    password = db.Column(db.String(80))

    

class Customer(db.Model):
    __tablename__ = 'customer'
    id = db.Column(db.Integer,db.ForeignKey('User_login.id'),primary_key = True)
    name = db.Column(db.String(40))
    mobile = db.Column(db.BigInteger,unique = True)
    email=db.Column(db.String(40),unique = True)
    wallet = db.Column(db.Integer,default=0)
 

    def __init__(self,id,name, mobile ,email):
        self.id = id  
        self.name = name
        self.mobile = mobile
        self.email = email
        
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():

    return render_template('index.html',opt=1)



@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated:
        flash(f'Logged in as {current_user.username} ','success')
       

    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                flash('Login Successful','success')
                login_user(user, remember = form.remember.data)
               
                return "Done"
            flash('Invalid Password ','warning')
            return render_template('login.html', form=form)
        flash('Invalid Login credentials','danger')  
        return redirect(url_for('login'))     
    
    return render_template('login.html', form=form)
  
@app.route('/signup', methods=['GET','POST'])
def signup():
    if current_user.is_authenticated:
        flash('Already Signed In .Press Log In to continue','success')
        return redirect(url_for('index'))
    form = RegisterForm()
    fi="Username already in use."
    
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        try :
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            try :
                new_customer = Customer(id=new_user.id ,name=form.name.data, mobile= int(form.mobile.data),email=form.email.data)
                db.session.add(new_customer)
                db.session.commit()
                
            except:
                fi=""
                flash('Mobile or Email already in use.','warning')
                db.session.execute('DELETE from "User_login" where username = :ids',{"ids":form.username.data})
                db.session.commit()
                return redirect(url_for('signup'))
        except:
            flash(f'{fi} Failed to create an Account .Create Account again !!','danger')
            return redirect(url_for('signup'))
        flash('Upload Your two Wheeler License and continue','success')
        return "DOne 1"
    return render_template('signup.html',form=form)




    





    


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


    



if __name__ == '__main__':
    app.run(debug=True)

