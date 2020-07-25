from flask import Flask, render_template, request,redirect, url_for, flash,send_file,session
from flask_bootstrap import Bootstrap
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from form import RegisterForm, LoginForm, EmailForm, ResetPasswordForm,UploadForm,UpdateProfile
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug import secure_filename
from flask_uploads import UploadSet,configure_uploads,IMAGES
import os 
from io import BytesIO
import pytz
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime 
import math, random


from geopy.distance import geodesic



app = Flask(__name__)


ENV = 'prod'

if ENV == 'prod':
    app.debug = True
    app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
else:
    app.debug = False
    app.config['SECRET_KEY'] = ''
    app.config['SQLALCHEMY_DATABASE_URI'] = ''
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOADS_DEFAULT_DEST']='static/images/uploads'


app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']= "ABCD"
app.config['RECAPTCHA_PRIVATE_KEY']= "abcd"
app.config['RECAPTCHA_OPTIONS']= {'theme':'black'}

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USER")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASS")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

bootstrap = Bootstrap(app)
db= SQLAlchemy(app)
mail=Mail(app)

pics = UploadSet('pics',IMAGES)
configure_uploads(app,pics)

login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = 'login'

#Models(Tables):

class User(UserMixin,db.Model):
    __tablename__ = 'User_login'
    id = db.Column(db.Integer, primary_key = True) 
    username = db.Column(db.String(15),unique=True)
    password = db.Column(db.String(80))

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

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
        
    

class Picture(db.Model):
    __tablename__="customer_License"
    id=db.Column(db.Integer,db.ForeignKey('customer.id'),primary_key=True)
    License=db.Column(db.LargeBinary)
                                            
    def __init__(self,customer_id,License):
        self.id=customer_id
        self.License=License

class Propic(db.Model):
    __tablename__="profile"
    id=db.Column(db.Integer,db.ForeignKey('customer.id'),primary_key=True)
    pic_url=db.Column(db.String(256))

    def __init__(self,customer_id,pic_url):
        self.id=customer_id
        self.pic_url=pic_url

def generateOTP():
    digits = "0123456789"
    OTP = ""

    for i in range(4):
        OTP += digits[math.floor(random.random()*10)]
    return OTP 

def reset_email(user):
    token = user.get_reset_token()
    customer=Customer.query.filter_by(id=user.id).first()
    msg = Message('Password Reset Request',
                  sender='roveapc.2020@gmail.com',
                  recipients=[customer.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset', token=token, _external=True)}
Please ignore if request is not made by you. The token gets expired.
-By Team Rove 
'''
    mail.send(msg)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    if current_user.is_authenticated:
        url=db.session.execute('select pic_url from profile where id=:ids',{"ids":current_user.id}).fetchone() 
        return render_template('index.html',opt=1,username=current_user.username,profileurl=url[0])

    return render_template('index.html',opt=2)



@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated:
        flash(f'Logged in as {current_user.username} ','success')
        return redirect(url_for('book'))

    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                flash('Login Successful','success')
                login_user(user, remember = form.remember.data)
               
                return redirect(url_for('book'))
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
        return redirect(url_for('DL',name=form.name.data))
    return render_template('signup.html',form=form)

@app.route('/DL:<name>',methods=['GET','POST'])
def DL(name):
    form= UploadForm()
    if form.validate_on_submit():
        customer= Customer.query.filter_by(name=name).first()
        if customer is None :
            flash('No customer with this name','warning')
            return redirect(url_for('signup'))
       
        try:
            files = form.license.data
            
            picture=Picture(customer_id=customer.id,License=files.read())
            db.session.add(picture)
            uril="https://static.wixstatic.com/media/cd5c35_e4e3005990ea4a879a280fd6dfe3bdbf~mv2.jpg/v1/fill/w_312,h_318,al_c,q_80,usm_0.66_1.00_0.01/empty-dp.webp"
            newprofile = Propic(customer_id=customer.id,pic_url=uril)
            db.session.add(newprofile)
            db.session.commit()
        except:
            flash('Couldnt Insert License','danger')
            db.session.execute('delete from "customer" where id= :ids',{"ids":customer.id})
            db.session.execute('DELETE from "User_login" where id = :ids',{"ids":customer.id})
            db.session.execute('DELETE from "profile" where id= : ids',{"ids":customer.id})
            db.session.commit()
            return redirect(url_for('signup'))
        flash(f'Account created for {name}  Please Login !','success')
        return redirect(url_for('login'))
    return render_template("imageupload.html",form=form)

@app.route('/resetpassword', methods=['GET','POST'])
def forgot():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = EmailForm()
    if form.validate_on_submit():
        customer = Customer.query.filter_by(email=form.email.data).first()
        if customer is None:
            flash('There is no Account with this email. Please Register.','warning')
            return redirect(url_for('forgot'))
        user = User.query.filter_by(id = customer.id).first()
        reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


    


@app.route('/profile',methods=['GET','POST'])
@login_required
def profile():
    
    hist=[]
    myprofile = db.session.execute('select u.username,c.name,c.mobile,c.email,c.wallet from "User_login" as u, customer as c where c.id=u.id and c.id=:ids',{"ids":current_user.id}).fetchone()
    history=db.session.execute('select r.vehicle_num, v.model, l1.loc_name as froml, l2.loc_name as to, r.datentime from ride as r ,location  as l1,location as l2,vehicle as v where r.vehicle_num=v.vehicle_number and r.from_loc=l1.id and r.to_loc=l2.id and customer_id =:ids order by r.datentime desc',{"ids":current_user.id}).fetchall() 
    for h in history :
        tz = pytz.timezone('Asia/Kolkata')
        now_kl = tz.fromutc(h.datentime)
        hist.append((h.vehicle_num,h.model,h.froml,h.to,now_kl))
        print(hist)
    url=db.session.execute('select pic_url from profile where id=:ids',{"ids":current_user.id}).fetchone() 
    return render_template('profile.html',myprofile=myprofile,history=hist,profileurl=url[0])


@app.route('/update',methods=["GET","POST"])
@login_required
def update():
    form = UpdateProfile()
    if form.validate_on_submit():
        filename=secure_filename(pics.save(form.pic.data))
        filename_url=pics.url(filename)
        
        
        f"filename = {filename_url}"
        db.session.execute('UPDATE profile set pic_url=:url where id=:ids',{"url":filename_url,"ids":current_user.id})
        db.session.commit()
        flash('Photo Updated Successfully','success')
        return redirect(url_for('profile'))
    return render_template('profileupdate.html',form=form)
    

@app.route('/resetpassword/<token>',methods=['GET','POST'])
def reset(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    user = User.verify_reset_token(token)
    if user is None:
        flash('The Token was invalid or expired ! Try Again', 'warning')
        return redirect(url_for('forgot'))
    
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You can Log in', 'success')
        return render_template('success.html',message = user.username)
    return render_template('reset_token.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


    

@app.route("/done", methods = ["GET","POST"])
@login_required
def done():
    url=db.session.execute('SELECT pic_url from profile where id=:ids',{"ids":current_user.id}).fetchone() 
    if request.method == "POST":
        
        if request.form['btn'] == 'New Ride':
            session.pop('from_location',None)  
            session.pop('to_location',None)  
            session.pop('vehicle_n',None)  
            session.pop('model',None)  
            session.pop('time',None)  
            session.pop('distance',None)
            session.pop('cost',None)
            session.pop('otp',None)
            session.pop('rideid',None)
            return redirect(url_for('book'))

        if request.form['btn'] == 'comp':
            complaint = request.form['complaint']
            db.session.execute('INSERT into "complaint"(ride_id, complaint) values (:iid, :c)',{"iid":session['rideid'],"c":complaint})
            db.session.commit()  
            return render_template('done.html', message = "Sorry for the inconvinience, your complaint has been registered", opt = 2,profileurl=url[0],username=current_user.username)
        if request.form['btn'] == 'Home':
            session.pop('from_location',None)  
            session.pop('to_location',None)  
            session.pop('vehicle_n',None)  
            session.pop('model',None)  
            session.pop('time',None)  
            session.pop('distance',None)
            session.pop('cost',None)
            session.pop('otp',None)
            session.pop('rideid',None)
            return redirect(url_for('index'))

        if request.form['btn'] == 'Sign Out':
            session.pop('from_location',None)  
            session.pop('to_location',None)  
            session.pop('vehicle_n',None)  
            session.pop('model',None)  
            session.pop('time',None)  
            session.pop('distance',None)
            session.pop('cost',None)
            session.pop('otp',None)
            session.pop('rideid',None)
            return redirect(url_for('logout'))
    return render_template("done.html", opt = 1,profileurl=url[0],username=current_user.username)

if __name__ == '__main__':
    app.run(debug=True)

