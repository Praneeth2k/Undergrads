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
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://postgres:spoo88#asA@localhost/Hackathon'
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
    __tablename__ = 'userlog'
    id = db.Column(db.Integer, primary_key = True) 
    username = db.Column(db.String(15),unique=True)
    password = db.Column(db.String(80))

    
class Seller(db.Model):
    __tablename__ = 'sellers'
    id = db.Column(db.Integer,db.ForeignKey('userlog.id'),primary_key = True)
    name = db.Column(db.String(40))
    mobile = db.Column(db.BigInteger,unique = True)
    email=db.Column(db.String(40),unique = True)
    address=db.Column(db.String(400))
    type=db.Column(db.String(20))
    wallet = db.Column(db.Numeric,default=0)

 

    def __init__(self,id,name, mobile ,email, address,type):
        self.id = id  
        self.name = name
        self.mobile = mobile
        self.email = email
        self.address=address
        self.type=type


class Order(db.Model):
    __tablename__ = 'orders'
    id=db.Column(db.Integer,primary_key=True)
    sid=db.Column(db.Integer,db.ForeignKey('sellers.id'))
    date = db.Column(db.Date,unique= True, nullable=False)
    time= db.Column(db.Time,unique= True, nullable=False)

    def __init__(self,sid,date,time):
        self.sid = sid 
        self.date = date
        self.time= time
       
        
        
class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(200))
    price = db.Column(db.Numeric)

    def __init__(self,name, price):
        
        self.name = name
        self.price = price
    
class OrdItem(db.Model):
    __tablename__ = 'order_item'
    oid = db.Column(db.Integer,db.ForeignKey('orders.id'),primary_key=True)
    sid = db.Column(db.Integer,db.ForeignKey('sellers.id'))
    quantity = db.Column(db.Numeric)

    def __init__(self,oid,sid,quantity):

        self.oid = oid  
        self.sid = sid
        self.quantity=quantity



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')



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
        flash('Already Signed In .','success')
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
                new_seller = Seller(id=new_user.id ,name=form.name.data, mobile= int(form.mobile.data),email=form.email.data,address=form.address.data,type=form.u.data)
                db.session.add(new_seller)
                db.session.commit()
                
            except:
                fi=""
                flash('Mobile or Email already in use.','warning')
                db.session.execute('DELETE from "userlog" where username = :ids',{"ids":form.username.data})
                db.session.commit()
                return redirect(url_for('signup'))
        except:
            flash(f'{fi} Failed to create an Account .Create Account again !!','danger')
            return redirect(url_for('signup'))
        flash('Account created Successfully','success')
        return "DOne 1"
    return render_template('signup.html',form=form)




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


    



if __name__ == '__main__':
    app.run(debug=True)

