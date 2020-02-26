from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

class RegisterForm(Form):
    name = StringField(label="İsim Soyisim", validators=[validators.Length(min=4, max=25)])
    username = StringField(label="Kullanıcı Adı", validators=[validators.Length(min=5, max=30)])
    email = StringField(label="Email Adresi", validators=[validators.Email(message="Lütfen geçerli bir email adresi giriniz")])
    password = PasswordField(label="Parola", validators=[
        validators.DataRequired(message="Lütfen bir parola belirleyiniz"),
        validators.EqualTo("confirm", message="Parolanız Uyuşmuyor")
    ])
    confirm = PasswordField(label="Parola Doğrula")

class LoginForm(Form):
    username = StringField(label="Kullanıcı Adı")
    password = PasswordField(label="Parola")

app = Flask(__name__)
app.secret_key = "ybblog"
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "123456098"
app.config["MYSQL_DB"] = "ybblog"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
mysql = MySQL(app)



@app.route('/')
def index():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        cursor = mysql.connection.cursor()
        sorgu = "insert into users(name, email, username, password) values(%s, %s, %s, %s)"
        cursor.execute(sorgu, (name,email,username, password))
        mysql.connection.commit()
        cursor.close()
        flash("Başarıyla Kayıt Oldunuz...", "success")
        return redirect(url_for("login"))
    else:
        return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST":
        username = form.username.data
        password_entered = form.password.data
        cursor = mysql.connection.cursor()
        sorgu = "select * from users where username = %s"
        result = cursor.execute(sorgu, (username,))
        if result > 0:
            data = cursor.fetchone()
            real_password = data["password"]
            if sha256_crypt.verify(password_entered, real_password):
                flash("Başarı ile giriş yaptınız", "success")
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("index"))
            else:
                flash("Parolanızı yanlış girdiniz", "danger")
                return redirect(url_for("login"))
        else:
            flash("Böyle bir kullanıcı bulunuyor", "danger")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("index"))
if __name__ == "__main__":
    app.run(debug=True)