from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
from datetime import datetime, timezone
from datetime import timedelta
from flask_migrate import Migrate
import re


app = Flask(__name__)



app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'SANSÜR' #Burayı sen değiştirip saklayacaksın önemli!
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


ADMIN_USERNAMES = {'admin','yozgat.m66','bay.beyaz'}  




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Itiraflar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(350), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='itiraflar')
    likes = db.relationship('PostLike', backref='itiraflar', lazy='dynamic')
    
    #begenenler = db.relationship('User', backref='itiraflar_begenenler')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(350), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='comments')
    itiraf_id = db.Column(db.Integer, db.ForeignKey('itiraflar.id'), nullable=False)
    itiraf = db.relationship('Itiraflar', backref='comments')
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #sideid = db.Column(db.Integer, nullable=False)
    text = db.Column(db.String(350), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='ChatMessage')
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)


class PostLike(db.Model):
    __tablename__ = 'post_like'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('itiraflar.id'))


class Anket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    baslik = db.Column(db.String(20) ,default="Ship")
    sec1 = db.Column(db.String(30),default="Evet" ,nullable=False)
    sec2 = db.Column(db.String(30), default="Hayır" ,nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sec1_oy = db.Column(db.Integer, default=0)
    sec2_oy = db.Column(db.Integer, default=0)
    tag = db.Column(db.String(25), default="soru")


class AnketOy(db.Model):
    __tablename__ = 'anket_oy'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    anket_id = db.Column(db.Integer, db.ForeignKey('anket.id'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=True)
    last_name_change_time = db.Column(db.DateTime)  
    username = db.Column(db.String(20), nullable=False, unique=True)
    last_user_change_time = db.Column(db.DateTime) 
    password = db.Column(db.String(80), nullable=False)
    confession_count = db.Column(db.Integer, default=0)
    last_confession_time = db.Column(db.DateTime)  
    last_login_device = db.Column(db.String(100))
    last_login_ip = db.Column(db.String(15))
    last_comment_time = db.Column(db.DateTime)
    last_poll_time = db.Column(db.DateTime)

    liked = db.relationship(
        'PostLike',
        foreign_keys='PostLike.user_id',
        backref='user', lazy='dynamic')
    
    voted = db.relationship(
        'Anket',
        foreign_keys='Anket.user_id',
        backref='user', lazy='dynamic')

    def like_post(self, post):
        if not self.has_liked_post(post):
            like = PostLike(user_id=self.id, post_id=post.id)
            db.session.add(like)

    def unlike_post(self, post):
        if self.has_liked_post(post):
            PostLike.query.filter_by(
                user_id=self.id,
                post_id=post.id).delete()

    def has_liked_post(self, post):
        return PostLike.query.filter(
            PostLike.user_id == self.id,
            PostLike.post_id == post.id).count() > 0
    
    def has_commented(self, post):
        return Comment.query.filter(
            Comment.user_id == self.id,
            Comment.itiraf_id == post.id).count() > 0
    
    def oy_verdi_mi(self, anket):
        return AnketOy.query.filter(
            AnketOy.user_id == self.id,
            AnketOy.anket_id == anket.id).count() > 0
    




    
class Begenenler(db.Model):
    __tablename__ = 'begenenler'
    id = db.Column(db.Integer, primary_key=True)
    begenenler = db.Column(db.String)




# Ban modelini güncelle
class Ban(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(255))
    user = db.relationship('User', backref='bans')





class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Kullanıcı Adı"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Şifre"})
    
    kod = StringField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Kayıt Kodu"})
    
    submit = SubmitField('Kayıt Ol')

    def validate_username(self, username):

        username_value = username.data

        regex = r"^[A-Za-z0-9_.]+$"
        if not re.match(regex, username_value):
            flash("Kullanıcı adı yalnızca harf, sayı, alt çizgi ve nokta içermelidir.")
            raise ValidationError("Kullanıcı adı yalnızca harf, sayı, alt çizgi ve nokta içermelidir.")

        existing_user_username = User.query.filter_by(
            username=username.data.lower()).first()
        if existing_user_username:
            flash('Bu kullanıcı adı zaten mevcut, lütfen başka bir kullanıcı adı seçiniz.')
            raise ValidationError('Bu kullanıcı adı zaten mevcut, lütfen başka bir ad seçiniz.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Kullanıcı Adı"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Şifre"})

    submit = SubmitField('Giriş Yap')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if not user:
            return(user)
            flash("Kullanıcı adı veya şifre hatalı.")
            raise ValidationError("Kullanıcı adı veya şifre hatalı.")


def sansurle_metin(metin, sansur_listesi):
    # Dosyadaki kelimeleri içerecek bir liste oluştur
    with open('karaliste.txt', 'r', encoding='utf-8') as dosya:
        karaliste = [kelime.strip() for kelime in dosya]


    for kelime in karaliste:
        metin = metin.replace(kelime, '*' * len(kelime))
    return metin


def is_user_banned(user):
    ban = Ban.query.filter_by(user_id=user.id).first()
    return ban is not None

@app.before_request
def check_ban():
    if current_user.is_authenticated and is_user_banned(current_user):
        if request.endpoint != 'ban_page':
            return redirect(url_for('ban_page'))
    
@app.before_request
def make_session_permanent():
    session.permanent = True 

@app.route('/ban')
def ban_page():
    if current_user.is_authenticated and is_user_banned(current_user):
        ban = Ban.query.filter_by(user_id=current_user.id).first()
        return render_template('ban.html', ban=ban)
    else:
        return redirect(url_for('itiraf'))


@app.route('/')
def home():
    if current_user.is_authenticated:
        return  redirect(url_for('itirafgonder'))
    else:
        return redirect(url_for('hesapsizitiraf'))

@app.route('/eglence')
@login_required
def eglence():
    return  render_template('eglence.html')

@app.route('/eglence/yolla', methods=['GET', 'POST'])
@login_required
def yolla():

    baslik = request.form.get('baslik')
    kisi1 = request.form.get('kisi1')# bu kafa karıştırmasın kiş değil seçenek bu UNUTMA!
    kisi2 = request.form.get('kisi2')
    tag = request.form.get('tag')
    if not baslik and tag == "ship":
        flash("Boş ship gönderemezsin!")
        return render_template('anket_olustur.html')
    if not baslik and tag == "anket":
        baslik = 'Birini seç !'
    olusturan = current_user.id
    if request.method == 'POST':
        
        if current_user.username not in ADMIN_USERNAMES:
            if current_user.last_poll_time is not None:
                elapsed_time = datetime.now() - current_user.last_poll_time
                cooldown_duration = timedelta(hours=1)  # 1 saat cooldown süresi
                if elapsed_time < cooldown_duration:
                    remaining_time = cooldown_duration - elapsed_time
                    flash(f'Hop hop yavaş saatbaşı anket yollayabilirsin. Kalan süre: {str(remaining_time)[:-7] }')
                    return render_template('anket_olustur.html')
        yeni_anket = Anket(sec1=kisi1, sec2=kisi2, user_id=olusturan, baslik=baslik, tag=tag)
        current_user.last_poll_time = datetime.now()
        db.session.add(yeni_anket)
        db.session.commit()
        if tag == "ship":
            return redirect(url_for("ship"))
        else:
            return redirect(url_for("anket"))
    return render_template('anket_olustur.html')

@app.route('/eglence/muzik')
@login_required

def muzik():
    anket = Anket.query.filter_by(tag='muzik')[0]
    if current_user.oy_verdi_mi(anket) :
        if anket.sec1_oy == 0 and not anket.sec2_oy == 0 :
            sec1_oy_percent = 0 
            sec2_oy_percent = 100 
        elif anket.sec2_oy == 0 and not anket.sec1_oy == 0  :
            sec1_oy_percent = 100 
            sec2_oy_percent = 0 
        elif anket.sec1_oy == 0 and anket.sec2_oy == 0 :
            sec1_oy_percent = 0 
            sec2_oy_percent = 0 
        else :
            sec1_oy_percent = (anket.sec1_oy / (anket.sec1_oy + anket.sec2_oy)) * 100 
            sec2_oy_percent = (anket.sec2_oy / (anket.sec1_oy + anket.sec2_oy)) * 100 
 
    else :
        sec1_oy_percent = 0 
        sec2_oy_percent = 0 
 




    
    return  render_template('muzik.html', anket = anket, sec1_oy_percent = sec1_oy_percent, sec2_oy_percent = sec2_oy_percent)


@app.route('/eglence/ship')
@login_required
def ship():

    ship_anket = Anket.query.filter_by(tag="ship").all()

#    sec1_oy_percent = (ship_anket.sec1_oy / (ship_anket.sec1_oy + ship_anket.sec2_oy)) * 100
#    sec2_oy_percent = (ship_anket.sec2_oy / (ship_anket.sec1_oy + ship_anket.sec2_oy)) * 100

    
    return  render_template('ship.html', anketler = ship_anket)
@app.route('/eglence/anket')
@login_required
def anket():

    anketler = Anket.query.filter_by(tag="anket").all()

    
    return  render_template('anket.html', anketler = anketler)


@app.route('/eglence/muzik/oy-ver/<int:anket_id>', methods=['POST'])
def oy_ver(anket_id):
    anket = Anket.query.get(anket_id)
    if request.method == 'POST':
        if current_user.oy_verdi_mi(anket) == False:
            oy = request.form.get('oy')
            if oy == 'sec1':
                anket.sec1_oy += 1
            elif oy == 'sec2':
                anket.sec2_oy += 1

            anket_oy = AnketOy(user_id=current_user.id, anket_id=anket.id)
            db.session.add(anket_oy)


        db.session.commit()
    return redirect(request.referrer)


@app.route('/destek-ol')
def destek():
    return  redirect('https://iflhub.com.tr/destek-ol')

@app.route('/itiraflar' , methods=['GET', 'POST'])
@login_required #hocalar bakmasın diye
def itiraf():
    itiraflar = Itiraflar.query.all()
    return render_template('itiraflar.html', itiraflar=itiraflar, adminler = ADMIN_USERNAMES)
    

@app.route('/itiraf/<int:itiraf_id>', methods=['GET','POST'])
@login_required
def itiraf_sayfa(itiraf_id):


    itiraf = Itiraflar.query.get(itiraf_id)
    if itiraf:
        
        return render_template('itiraf_detay.html', post=itiraf, adminler = ADMIN_USERNAMES)

    return redirect(url_for('itiraf'))


def delete_old_messages():
    son = ChatMessage.query.all()[-1]

    mesajlar = ChatMessage.query.all()

    for mesaj in mesajlar:
        if mesaj.id < son.id - 30:
            db.session.delete(mesaj)
            

    
    



@app.route('/sohbet-kanali', methods=['GET','POST'])
@login_required
def sohbet():

    mesajlar = ChatMessage.query.all()
    return render_template('sohbet.html', mesajlar=mesajlar, adminler = ADMIN_USERNAMES)

@app.route('/mesaj-at', methods=['GET','POST'])
@login_required
def mesajat():
    comment_text = request.form.get('comment_text')

    delete_old_messages()
    current_user.last_comment_time = datetime.now()
    yeni_mesaj = ChatMessage(text=comment_text, user_id=current_user.id, date_posted=datetime.now())
    db.session.add(yeni_mesaj)
    db.session.commit()

    # Yeni mesajı emit et

    return redirect(url_for('sohbet'))



    




@app.route('/like/<int:post_id>/<action>')
@login_required
def like_action(post_id, action):
    post = Itiraflar.query.filter_by(id=post_id).first_or_404()
    if action == 'like':
        current_user.like_post(post)
        db.session.commit()
    if action == 'unlike':
        current_user.unlike_post(post)
        db.session.commit()
    return redirect(request.referrer)

@app.route('/add_comment/<int:itiraf_id>', methods=['POST'])
@login_required
def add_comment(itiraf_id):
    itiraf = Itiraflar.query.get(itiraf_id)
    if itiraf:
        comment_text = request.form.get('comment_text')

         # Cooldown süresi kontrolü

        if current_user.last_comment_time is not None:
            elapsed_time = datetime.now() - current_user.last_comment_time
            cooldown_duration = timedelta(seconds=20)  # 1 dakika cooldown süresi
            if elapsed_time < cooldown_duration:
                remaining_time = cooldown_duration - elapsed_time
                flash(f'Hop hop yavaş 20 saniyede bir yorum atabilirsin. Kalan süre: {remaining_time.seconds} saniye')
                return redirect(url_for('itiraf_sayfa', itiraf_id=itiraf_id))

        current_user.last_comment_time = datetime.now()
        new_comment = Comment(text=comment_text, user_id=current_user.id, itiraf_id=itiraf.id)
        db.session.add(new_comment)
        db.session.commit()
    return redirect(url_for('itiraf_sayfa', itiraf_id=itiraf_id))

@app.route('/delete_comment/<int:yorum_id>')
@login_required
def delete_comment(yorum_id):
    yorum = Comment.query.get(yorum_id)

    if current_user.id is not yorum.user_id:
        return redirect(request.referrer)

    if itiraf:
        db.session.delete(yorum)
        db.session.commit()
        flash(f'Yorum başarıyla silindi.')
    else:
        flash(f'Yorum bulunamadı.')

    return redirect(request.referrer)



@app.route('/hesabim')
@login_required
def hesabim():
    return render_template('hesabim.html', son_itiraf = str(current_user.last_confession_time)[:-7])

@app.route('/ad_degistir', methods=['POST'])
@login_required
def ad_degistir():
    takma_ad = request.form.get('ad')
    if current_user.is_authenticated:
        user_info = User.query.get(current_user.id)
        if user_info.last_name_change_time is not None and current_user.username not in ADMIN_USERNAMES:
            elapsed_time = datetime.now() - user_info.last_name_change_time
            cooldown_duration = timedelta(days=7)  # Cooldown süresini istediğiniz gibi değiştirin
            if elapsed_time < cooldown_duration:
                remaining_time = cooldown_duration - elapsed_time
                cut_time = str(remaining_time)[:-7]
                flash(f'Haftada bir defa adını değiştirebilirsin! Kalan süre: {cut_time}')
                return redirect(url_for('hesabim'))
    current_user.name = takma_ad
    current_user.last_name_change_time = datetime.now()
    db.session.commit()
    return redirect(url_for('hesabim'))

@app.route('/kullanici_adi_degistir', methods=['POST'])
@login_required
def kul_ad_degistir():

    kul_ad = request.form.get('ad')
    if current_user.is_authenticated:
        user_info = User.query.get(current_user.id)
        if user_info.last_name_change_time is not None and current_user.username not in ADMIN_USERNAMES:
            elapsed_time = datetime.now() - user_info.last_name_change_time
            cooldown_duration = timedelta(days=7)  # Cooldown süresini istediğiniz gibi değiştirin
            if elapsed_time < cooldown_duration:
                remaining_time = cooldown_duration - elapsed_time
                cut_time = str(remaining_time)[:-7]
                flash(f'Haftada bir defa adını değiştirebilirsin! Kalan süre: {cut_time}')
                return redirect(url_for('hesabim'))
    current_user.username = kul_ad.lower()
    current_user.last_name_change_time = datetime.now()
    db.session.commit()
    return redirect(url_for('hesabim'))

@app.route('/tos')
def tos():
#    monosakkarit = User.query.filter_by(id=88)[0]
#    db.session.delete(monosakkarit)
#    db.session.commit()
    return render_template('tos.html')

@app.route('/kurallar')
def kurallar():
    return render_template('kurallar.html')

def sansur_listesi():
    f = open("karaliste.txt", "r")
    karaliste = f.read()
    kliste = []
    for kelime in karaliste:
        kliste.append(kelime)
    return kliste

@app.route('/itiraf-gonder' , methods=['GET', 'POST'])
@login_required
def itirafgonder():
    if request.method == 'POST':
        if current_user.is_authenticated:
            user_info = User.query.get(current_user.id)

            # Cooldown süresi kontrolü
            if user_info.last_confession_time is not None and current_user.username not in ADMIN_USERNAMES:
                elapsed_time = datetime.now() - user_info.last_confession_time
                cooldown_duration = timedelta(hours=1)  # Cooldown süresini istediğiniz gibi değiştirin
                if elapsed_time < cooldown_duration:
                    remaining_time = cooldown_duration - elapsed_time
                    cut_time = str(remaining_time)[:-7]
                    flash(f'Günde sadece 1 kez itiraf gönderebilirsiniz. Kalan süre: {cut_time}')
                    return redirect(url_for('itirafgonder'))
    
            data = request.form.get('message')
            #data = sansurle_metin(data, sansur_listesi())
            # Itiraflar tablosuna yeni itirafı eklerken, kullanıcının id'sini de kaydediyoruz
            anonim_itiraf = request.form.get('anonim_itiraf')
            if anonim_itiraf:
                new_itiraf = Itiraflar(message=data)
                
            else:
                new_itiraf = Itiraflar(message=data, user_id=current_user.id)   
            db.session.add(new_itiraf)

            # Kullanıcı verilerini güncelle
            user_info.confession_count += 1
            user_info.last_confession_time = datetime.now()
            db.session.commit()

    return render_template('itiraf-gonder.html')


@app.route('/hesapsiz-itiraf', methods=['GET', 'POST'])
def hesapsizitiraf():
    # Daha önce itiraf gönderilmiş mi kontrol et
    if session.get('last_submission_time'):
        elapsed_time = datetime.now(timezone.utc) - session['last_submission_time']
        remaining_time = timedelta(seconds=(3 * 60 * 60 - elapsed_time.total_seconds()))

        if remaining_time.total_seconds() > 0:
            remaining_hours, remainder = divmod(remaining_time.seconds, 3600)
            remaining_minutes, remaining_seconds = divmod(remainder, 60)
            remaining_time_str = f"{int(remaining_hours)} saat {int(remaining_minutes)} dakika {int(remaining_seconds)} saniye"
            flash(f"Hesapsız şekilde ard arda itiraf gönderemezsin saatbaşı itiraf göndermek için hesap oluşturunuz. Hesapsız sonraki itirafk hakkı için kalan süre: {remaining_time_str}.")
            return render_template('itiraf-gonder-hesapsiz.html' )

    if request.method == 'POST':
        data = request.form.get('message')
        data = sansurle_metin(data, sansur_listesi())

        new_itiraf = Itiraflar(message=data)
        db.session.add(new_itiraf)
        db.session.commit()

        # Itiraf gönderme zamanını sakla
        session['last_submission_time'] = datetime.now(timezone.utc)

        
        return render_template('itiraf-gonder-hesapsiz.html', message="İtirafınız gönderildi")

    return render_template('itiraf-gonder-hesapsiz.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.lower()).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                user.last_login_device = request.user_agent.string
                user.last_login_ip = request.remote_addr
                db.session.commit()

                return redirect(url_for('itirafgonder'))
            else:
                flash("Kullanıcı adı veya şifre hatalı.")


    


    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if form.kod.data == 'iflhub2024':

            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data.lower(), password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            flash("Kayıt kodu yanlış!")
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


# admin_panel fonksiyonunu güncelle
@app.route('/admin-panel', methods=['GET', 'POST'])
@login_required
def admin_panel():
    # Yalnızca admin kullanıcılarına izin ver
    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('itiraflar'))

    if request.method == 'POST':
        selected_option = request.form.get('admin_option')
        if selected_option == 'itiraf':
            return redirect(url_for('admin_itiraf'))
        elif selected_option == 'kullanici':
            return redirect(url_for('admin_kullanici'))
        elif selected_option == 'banlist':
            return redirect(url_for('admin_banlist'))
        elif selected_option == 'anket':
            return redirect(url_for('admin_anket'))

    return render_template('admin_panel.html')



@app.route('/admin-panel/anket', methods=['GET', 'POST'])
@login_required
def admin_anket():
    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('itiraflar'))
    anketler = Anket.query.all()
    baslik = request.form.get('baslik')
    kisi1 = request.form.get('kisi1')# bu kafa karıştırmasın kiş değil seçenek bu UNUTMA!
    kisi2 = request.form.get('kisi2')
    tag = request.form.get('tag')
    if not baslik:
        baslik = 'Ship'
    olusturan = current_user.id
    if request.method == 'POST':
        yeni_anket = Anket(sec1=kisi1, sec2=kisi2, user_id=olusturan, baslik=baslik, tag=tag)

        db.session.add(yeni_anket)

        db.session.commit()


    return render_template('anket_upload.html', anketler=anketler)

@app.route('/anket/sil/<int:pid>')
@login_required
def anket_sil(pid):
    silinecek = Anket.query.filter_by(id = pid).first()
    if silinecek:
        db.session.delete(silinecek)
        db.session.commit()
    return redirect(request.referrer)

@app.route('/anket/duzenle/<int:pid>', methods=['POST', 'GET'])
@login_required
def anket_duzenle(pid):
    duzenlencek = Anket.query.filter_by(id = pid).first()
    if duzenlencek:
        if request.form.get('baslik'):
            duzenlencek.baslik = request.form.get('baslik')
        if request.form.get('sec1'):
            duzenlencek.sec1 = request.form.get('sec1')
        if request.form.get('sec2'):
            duzenlencek.sec2 = request.form.get('sec2')
        if request.form.get('tag'):
            duzenlencek.tag = request.form.get('tag')
        db.session.commit()
    return redirect(request.referrer)

# Yeni sayfaları ekleyin
@app.route('/admin-panel/itiraf', methods=['GET', 'POST'])
@login_required
def admin_itiraf():
    # Itiraf yönetimi işlemleri burada gerçekleşir
    itiraflar = Itiraflar.query.all()
    return render_template('admin_itiraf.html', itiraflar=itiraflar)






@app.route('/admin/kullanici', methods=['GET', 'POST'])
@login_required
def admin_kullanici():
    # Sadece admin erişebilir
    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('itiraflar'))

    # Tüm kullanıcıları geti
    
#    bans = Ban.query.all()
#    for ban in bans:
#        db.session.delete(ban)

#    rivaldo = User.query.filter_by(id=4).first()
#
#    if rivaldo:
#        db.session.delete(rivaldo) rivaldo aynı isimle iki defa hesap açtığı için tüm sistem çökmüştü aq biri Rivaldo diğeri rivaldo idi 

    for kullanici in User.query.all():
       kullanici.username = kullanici.username.lower()
    
    

    


    # Commit işlemi
    db.session.commit()

    users = User.query.all()

    rivaldo = User.query.filter_by(id=3).first()
    if rivaldo:
        db.session.delete(rivaldo)
        db.session.commit()



    return render_template('admin_kullanici.html', users=users)

# Yeni route tanımı
@app.route('/admin/banlist', methods=['GET'])
@login_required
def admin_banlist():
    # Sadece admin erişebilir
    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('dashboard'))

    # Tüm banlanan kullanıcıları getir
    
    bans = Ban.query.all()

    return render_template('admin_banlist.html', bans=bans)


@app.route('/admin-panel/delete/<int:itiraf_id>', methods=['POST'])
@login_required
def delete_itiraf(itiraf_id):
    # Yalnızca admin kullanıcılarına izin ver
    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('itiraflar'))

    itiraf = Itiraflar.query.get(itiraf_id)
    if itiraf:
        db.session.delete(itiraf)
        db.session.commit()
        flash(f'İtiraf başarıyla silindi.')
    else:
        flash(f'İtiraf bulunamadı.')

    return redirect(url_for('admin_panel'))

@app.route('/admin/ban/<int:user_id>', methods=['POST'])
def admin_ban(user_id):

    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('itiraflar'))

    user = User.query.get(user_id)
    if user:
        # Kullanıcının girdiği ban sebebini al
        ban_reason = request.form.get('ban_reason', 'Neden belirtilmemiş')
        
        # Kullanıcıyı banla
        ban = Ban(user_id=user.id, reason=ban_reason)
        db.session.add(ban)
        db.session.commit()
    return redirect(url_for('admin_kullanici'))


@app.route('/admin/unban/<int:user_id>', methods=['POST'])
def admin_unban(user_id):

    if current_user.username not in ADMIN_USERNAMES:
        return redirect(url_for('itiraflar'))

    user = User.query.get(user_id)
    if user:
        # Kullanıcının banını kaldır
        ban = Ban.query.filter_by(user_id=user.id).first()
        if ban:
            db.session.delete(ban)
            db.session.commit()
    return redirect(url_for('admin_kullanici'))





if __name__ == "__main__":
    #from waitress import serve
    #serve(app, host="87.248.157.245", port=8080)
    app.run(debug=True)
