from ast import pattern
import json
import re
from telnetlib import STATUS

from flask import Flask, jsonify, render_template,flash, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,EmailField
from wtforms.validators import InputRequired, Length, ValidationError,EqualTo
from flask_bcrypt import Bcrypt
import sqlite3

f = open('config.json')
data = json.load(f)


log_file = open("log.txt","r+")
log_file.write('kunal')
log_file.flush()




app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = data["DatabaseURI"]
app.config['SECRET_KEY'] = data["SecretKey"]


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)



class Hospital(db.Model):
    Patient_id = db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(20), nullable=False)
    Bed_no = db.Column(db.Integer, nullable=False, unique=True)
    Phone_no= db.Column(db.Integer, nullable=False)
    Emergency_contact_name=db.Column(db.String(20),nullable=False)
    Emergency_contact_no=db.Column(db.Integer,nullable=False)
    Status=db.Column(db.String(20),nullable=False)
    Is_deleted=db.Column(db.String(5),nullable=False)



class RegisterForm(FlaskForm):

    Name = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Name"})

    username = EmailField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    
    c_password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20), EqualTo('password', message='Passwords missmatch')], render_kw={"placeholder": "Confirm Password"})

    Phone_no= StringField(validators=[
                           InputRequired(), Length(min=10, max=10)], render_kw={"placeholder": "Phone Number", "pattern":"^[0-9]*$"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

    def validate_password(form,password):
        if not re.search(r'[a-zA-Z0-9]*[!#$%&][a-zA-Z0-9]*',password.data):
            flash('Password is not valid.')
            raise ValidationError('Password is not valid')
            





class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


def connection():
    con = sqlite3.connect("hospital.db")  
    con.row_factory = sqlite3.Row  
    cur = con.cursor()
    return cur  


@app.route('/report')
def report():
    return render_template('report.html')


@app.route("/dashboard")
@login_required
def dashboard():
    rows=Hospital.query.filter_by(Is_deleted=0).all()
    msg=''
    print(rows)
    flash(msg)
    return render_template("dashboard.html",rows=rows)


@app.route("/", methods=['GET',"POST"])  
@app.route('/login',methods=['GET',"POST"])
def login():
    form = LoginForm()
    msg=''
    if request.method == "POST":
        print('if')
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                msg='Wrong Password'
                return render_template('login.html',form=form ,msg=msg)
        else:   
            msg='Wrong Username'
            return render_template('login.html',form=form, msg=msg)
    return render_template('login.html', form=form,msg=msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm() 

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.Name.data,username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))




@app.route('/adding_records',methods=["GET",'POST'])
def adding_records():
    msg = ""  
    if request.method == "POST":  
        try:  
            name = request.form["Name"]  
            Bed_no = request.form["Bed_no"]
            Phone_no=request.form['Phone_no']
            Emergency_contact_name=request.form['Emergency_contact_name']
            Emergency_contact_no=request.form['Emergency_contact_no'] 
            Status = request.form.get('Status') 
            Is_deleted=0 
            new_data=Hospital(name=name,Bed_no=Bed_no,Phone_no=Phone_no,Emergency_contact_name=Emergency_contact_name,Emergency_contact_no=Emergency_contact_no,Status=Status,Is_deleted=Is_deleted)
            db.session.add(new_data)
            db.session.commit()
        except KeyError as k:
            print(k)
            msg='Key Error'
            flash(msg)
            log_file.write(msg)
            log_file.flush()
        except ValueError as v:
            print(v)
            msg='Value Error'
            flash(msg)
            log_file.write(msg)
        except Exception as e:
            print(e) 
            log_file.write(e)
            msg=(str(e))
            log_file.write(msg)
        finally:  
            flash(msg)
            log_file.writer(msg)
            return redirect(url_for('dashboard'))
            con.close()  





'--------------------------------------------------'


@app.route("/update_record",methods = ["POST","GET"])  
def update_record():  
    if request.method == "POST":  
        Patient_id=request.form['Patient_id']
        name = request.form["Name"]  
        Bed_no = request.form["Bed_no"]
        Phone_no=request.form['Phone_no']
        Emergency_contact_name=request.form['Emergency_contact_name']
        Emergency_contact_no=request.form['Emergency_contact_no'] 
        Status = request.form.get('Status')
        query = {}
        data = {Hospital.name:name, Hospital.Bed_no:Bed_no, Hospital.Phone_no:Phone_no,Hospital.Emergency_contact_name:Emergency_contact_name,Hospital.Emergency_contact_no:Emergency_contact_no,Hospital.Status:Status}
        for i in data:
            if data[i]:
                query[i]=data[i]
        try:
            x=Patient_id.split(',')
            for i in x:
                db.session.query(Hospital).filter(Hospital.Patient_id==i).update(query,synchronize_session=False)
                msg='Patient Record Updated'
                print(msg)
        except Exception as e: 
            print(e)
            msg = "We can not update the Patient to the list"  
        finally:  
            db.session.commit()
            return redirect(url_for("dashboard"))
            con.close()  

#search


@app.route("/search_record",methods = ["POST","GET"])  
def search_record():  
    msg = "msg"  
    if request.method == "POST":  
        Patient_id="%"+request.form['Patient_id']+"%" if request.form['Patient_id'] else '%'
        name="%"+request.form['Name']+"%" if request.form['Name'] else '%'
        Bed_no="%"+request.form['Bed_no']+"%" if request.form['Bed_no'] else '%'
        Phone_no="%"+request.form['Phone_no']+"%" if request.form['Phone_no'] else '%'
        Emergency_contact_name="%"+request.form['Emergency_contact_name']+"%" if request.form['Emergency_contact_name'] else '%'
        Emergency_contact_no="%"+request.form['Emergency_contact_no']+"%" if request.form['Emergency_contact_no'] else '%'
        Status="%"+request.form.get('Status')+"%" if request.form.get('Status') else '%'
        try:  
            rows=db.session.query(Hospital).filter(
                Hospital.Patient_id.like(Patient_id),
                Hospital.name.like(name),
                Hospital.Bed_no.like(Bed_no),
                Hospital.Phone_no.like(Phone_no),
                Hospital.Emergency_contact_name.like(Emergency_contact_name),
                Hospital.Emergency_contact_no.like(Emergency_contact_no),
                Hospital.Status.like(Status)).all()
            msg='search done'
            return render_template("dashboard.html",msg = msg,rows=rows)  
        except Exception as e: 
            print(e)
        return render_template("dashboard.html",msg = msg,rows=rows)  
        
        


'-----------------------------'
@app.route("/delete/<int:id>")  
def deleterecord(id):  
    if request.method=='GET':
        with sqlite3.connect("hospital.db") as con:
            try:
                db.session.query(Hospital).filter_by(Patient_id=id).update({"Is_deleted":1})
                db.session.commit() 
            except Exception as e:  
                print(e)  
            finally:  
                return redirect(url_for('dashboard')) 
                con.close()


@app.route('/refresh')
def refresh():
    with sqlite3.connect("hospital.db") as con:
        print('with')
        try:
            db.session.query(Hospital).filter_by(Is_deleted=1).update({"Is_deleted":0})
            db.session.commit()  
        except Exception as e:
            print(e)  
        finally:    
            return redirect(url_for('dashboard')) 
            con.close()


'--------------------------------------------------------------------'
#report
@app.route('/analytics', methods=['GET', 'POST'])
def analytics():
    return render_template('analytics.html')

@app.route('/analytics_data', methods=['GET','POST'])
def analytics_data():
    con = sqlite3.connect("hospital.db")
    cur = con.cursor()
    cur.execute("select distinct Status from Hospital")
    Status = cur.fetchall()
    print(Status)
    print(len(Status))
    data_list=[]
    for i in range(len(Status)):
        print(Status[i][0])
        cur.execute("select count(name) from Hospital where Status='{}'".format(Status[i][0]))
        count_v=cur.fetchone() 
        data = {}
        data['label'] = Status[i][0]
        data['y'] = count_v[0]
        json_data = json.dumps(data)
        data_list.append(json_data)
    return jsonify(data_list)


if __name__ == "__main__":  
    app.run(debug = True)  