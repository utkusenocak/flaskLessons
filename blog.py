from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

#Kullanıcı giriş decorater
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntülemek için lütfen giriş yapın", "danger")
            return redirect(url_for("login"))
    return decorated_function

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

class ArticleForm(Form):
    title = StringField(label="Makale Başlığı", validators=[validators.Length(min=5, max=100)])
    content = TextAreaField(label="Makale İçeriği", validators=[validators.Length(min=10)])


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

@app.route('/articles')
def articles():
    cursor = mysql.connection.cursor()
    sorgu = "select * from articles"
    result = cursor.execute(sorgu)
    if result > 0:
        articles = cursor.fetchall()
        cursor.close()
        return render_template("articles.html", articles = articles)
    else:
        cursor.close()
        return render_template("articles.html")
@app.route('/article/<string:id>')
def article(id):
    cursor = mysql.connection.cursor()
    sorgu = "select * from articles where id = %s"
    result = cursor.execute(sorgu, (id,))
    if result > 0:
        article = cursor.fetchone()
        cursor.close()
        return render_template("article.html", article = article)
    else:
        cursor.close()
        return render_template("article.html")

@app.route('/dashboard')
@login_required
def dashboard():
    cursor = mysql.connection.cursor()
    sorgu = "select * from articles where author = %s"
    result = cursor.execute(sorgu, (session["username"],))
    if result > 0:
        articles = cursor.fetchall()
        cursor.close()
        return render_template("dashboard.html", articles=articles)
    else:
        cursor.close()
        return render_template("dashboard.html")

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
                cursor.close()
                return redirect(url_for("index"))
            else:
                flash("Parolanızı yanlış girdiniz", "danger")
                cursor.close()
                return redirect(url_for("login"))
        else:
            flash("Böyle bir kullanıcı bulunuyor", "danger")
            cursor.close()
            return redirect(url_for("login"))
    return render_template("login.html", form=form)
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route('/addarticle', methods=["POST","GET"])
@login_required
def addarticle():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        content = form.content.data
        cursor = mysql.connection.cursor()
        sorgu = "insert into articles(title, author, content) values(%s, %s, %s)"
        cursor.execute(sorgu, (title, session["username"], content))
        mysql.connection.commit()
        cursor.close()
        flash("Makale başarı ile yayınlandı", "success")
        return redirect(url_for("dashboard"))
    
    return render_template("addarticle.html", form=form)

@app.route('/delete/<string:id>')
@login_required
def delete(id):
    cursor = mysql.connection.cursor()
    sorgu = "select * from articles where author = %s and id = %s"
    result = cursor.execute(sorgu, (session["username"], id))
    if result > 0:
        sorgu2 = "delete from articles where id = %s"
        cursor.execute(sorgu2, (id,))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for("dashboard"))
    else:
        flash("Böyle bir makale yok veya bu işleme yetkiniz yok", "danger")
        cursor.close()
        return redirect(url_for("index"))

@app.route('/edit/<string:id>', methods=["POST","GET"])
@login_required
def update(id):
    if request.method == "GET":
        cursor = mysql.connection.cursor()
        sorgu = "select * from articles where id = %s and author = %s"
        result = cursor.execute(sorgu, (id, session["username"]))
        if result == 0:
            flash("Böyle bir makale yok veya bu işleme yetkiniz yok", "danger")
            cursor.close()
            return redirect(url_for("index"))
        else:
            article = cursor.fetchone()
            form = ArticleForm()
            form.title.data = article["title"]
            form.content.data = article["content"]
            cursor.close()
            return render_template("update.html", form=form)
    else:
        form = ArticleForm(request.form)
        newTitle = form.title.data
        newContent = form.content.data
        cursor = mysql.connection.cursor()
        sorgu = "Update articles set title = %s, content = %s where id = %s"
        cursor.execute(sorgu, (newTitle, newContent, id))
        mysql.connection.commit()
        cursor.close()
        flash("Makaele başarı ile güncellendi", "success")
        return redirect(url_for("dashboard"))
@app.route('/search', methods= ["GET", "POST"])
def search():
    if request.method == "GET":
        return redirect(url_for("index"))
    else:
        keyword = request.form.get("keyword")
        cursor = mysql.connection.cursor()
        sorgu = "select * from articles where title like '%" + keyword + "%'"
        result = cursor.execute(sorgu)
        if result == 0:
            flash("Aranan kelimeye uygun bir makale bulunumadı", "warning")
            cursor.close()
            return redirect(url_for("articles"))
        else:
            articles = cursor.fetchall()
            cursor.close()
            return render_template("articles.html", articles=articles)



if __name__ == "__main__":
    app.run(debug=True)