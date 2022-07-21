# -*- coding: utf-8 -*-
import datetime, json
from flask import Flask, request, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required


from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, DateField, HiddenField, TextAreaField, validators



app = Flask(__name__, static_url_path='/static')
with open('config.json') as f:
	config = json.load(f)
app.config.update(config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
	return db.session.query(User).get(user_id)

@app.route('/', methods=['GET', 'POST'])
def index():
	if current_user.is_authenticated:
		form = DemandForm()
		return render_template('my_demands.html', form = form)
	else:
		return render_template('not_auth.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == "POST":
		got_login = request.form['login']
		got_password = request.form['password']
		
		login = User.query.filter_by(login=got_login).first()
		if login and login.check_password(password=got_password):
			login_user(login)
			return redirect('/')
		else:
			return render_template('login.html', error="Неверное имя пользователя или пароль")
	else:
		return render_template('login.html', error=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == "POST":
		login = request.form['login']
		password1 = request.form['password1']
		password2 = request.form['password2']
		username = request.form['username']
		error=None
		login_db = User.query.filter_by(login=login).first()
		if len(login) < 5: 
			error="Логин не может быть меньше 5 символов"
		elif len(login) > 20: 
			error="Логин не может превышать 20 символов"
		elif login_db:
			error="Пользователь с таким логином уже зарегестрирован"
		elif username == '':
			error="Введите обращение"
		elif len(username) > 80:
			error="Обращение не может превышать 80 символов"
		elif len(password1) < 8: 
			error="Пароль не может быть меньше 8 символов"
		elif password1 != password2:
			error="Пароли не совпадают"
		if error:
			return render_template('register.html', error=error, login=login, password1=password1, password2=password2, username=username)
		try:
			user = User(login=login, password=password1, username=username)
			db.session.add(user)
			db.session.commit()
			return redirect('/')
		except:
			return render_template('error.html')
	else:
		return render_template('register.html', error=None)

@app.route('/demands', methods=['GET', 'POST'])
@login_required
def demands_all():
	form = DemandForm()
	demands = db.session.query(Demand).all()
	return render_template('all_demands.html', form = form, demands = demands)


@app.route('/client/', methods=['GET'])
@login_required
def clients_list():
	clients = db.session.query(Client).filter_by(client_status = 1).all()
	return render_template('clients_list.html', clients=clients)

@app.route('/client/<string:id>/', methods=['GET', 'POST'])
@login_required
def open_client(id):
	return redirect('demand')

@app.route('/client/<int:id>/addresses/', methods=['GET', 'POST'])
@login_required
def addresses(id):
	client = db.session.query(Client).filter_by(client_id = id).first()
	form = AddressForm()
	if form.validate_on_submit():
		try:
			if form.address_edit_id.data:
				address = db.session.query(Address).filter_by(id = form.address_edit_id.data).first()
				address.name = form.name.data
			else:
				address = Address(address_client_id = id, name = form.name.data)
				db.session.add(address)
			db.session.commit()
			return redirect(request.url)
		except:
			return render_template('error.html')
	return render_template('client_addresses.html', form=form, client = client)

@app.route('/client/<int:adress_id>/addresses/delete_<int:id>', methods=['GET'])
@login_required
def address_delete(id, adress_id):
	try:
		address = db.session.query(Address).filter_by(id = adress_id).first()
		db.session.delete(address)
		db.session.commit()
		return redirect('./')
	except:
		return render_template('error.html')

@app.route('/client/<string:id>/people/', methods=['GET', 'POST'])
@login_required
def client_people(id):
	client = db.session.query(Client).filter_by(client_id = id).first()
	form = PeopleForm()
	if form.validate_on_submit():
		try:
			if form.people_edit_id.data:
				man = db.session.query(People).filter_by(people_id = form.people_edit_id.data).first()
				man.people_fio = form.people_fio.data
				man.people_job = form.people_job.data
				man.people_contact = form.people_contact.data
				man.people_comment = form.people_comment.data
			else:
				man = People(people_client_id = id,\
					people_fio = form.people_fio.data,\
					people_job = form.people_job.data, \
					people_contact = form.people_contact.data, \
					people_comment = form.people_comment.data)
				db.session.add(man)
			db.session.commit()
			return redirect(request.url)
		except:
			return render_template('error.html')
			
	return render_template('client_people.html', client=client, form=form)

@app.route('/client/<int:id>/people/delete_<int:people_id>', methods=['GET'])
@login_required
def client_people_delete(id, people_id):
	man = db.session.query(People).filter_by(people_id = people_id).first()
	try:
		db.session.delete(man)
		db.session.commit()
		return redirect('./')
	except:
		return render_template('error.html')

@app.route('/client/<string:id>/equipment/', methods=['GET', 'POST'])
@login_required
def client_equipment(id):
	client = db.session.query(Client).filter_by(client_id = id).first()
	form = EquipmentForm()
	form.equipment_type_id.choices = [(e.equipment_type_id, e.equipment_type) for e in db.session.query(EquipmentType).all()]
	form.equipment_id.choices = [(a.id, a.name) for a in client.addresses.all()]
	if form.validate_on_submit():
		try:
			if form.equipment_edit_id.data:
				equipment = db.session.query(Equipment).filter_by(equipment_id = form.equipment_edit_id.data).first()
				equipment.equipment_type_id = form.equipment_type_id.data
				equipment.equipment_model  = form.equipment_model.data
				equipment.equipment_specs = form.equipment_specs.data
				equipment.equipment_hostname = form.equipment_hostname.data
				equipment.equipment_owner = form.equipment_owner.data
				equipment.equipment_id = form.equipment_id.data

			else:
				equipment = Equipment(equipment_client_id = id,\
					equipment_model = form.equipment_model.data, \
					equipment_specs = form.equipment_specs.data, \
					equipment_hostname = form.equipment_hostname.data, \
					equipment_owner = form.equipment_owner.data, \
					equipment_id = form.equipment_id.data, \
					equipment_type_id = form.equipment_type_id.data)
				db.session.add(equipment)
			db.session.commit()
			return redirect(request.url)
		except:
			return render_template('error.html')
	return render_template('client_equipment.html', client=client, form=form)

@app.route('/client/<int:id>/equipment/delete_<int:equipment_id>', methods=['GET'])
@login_required
def client_equipment_id_delete(id, equipment_id):
	equipment = db.session.query(Equipment).filter_by(equipment_id = equipment_id).first()
	db.session.delete(equipment)
	db.session.commit()
	return redirect('./')

@app.route('/client/<string:id>/document/', methods=['GET', 'POST'])
@login_required
def document(id):
	client = db.session.query(Client).filter_by(client_id = id).first()
	if request.method == "POST":
		try:
			client.client_document = request.form['client_document']
			db.session.commit()
		except:
			return render_template('error.html')
	return render_template('client_document.html', client=client, follow_redirects=True)

@app.route('/client/<string:id>/demand/new', methods=['GET', 'POST'])
@login_required
def demand_new(id):
	form = DemandForm()
	form.demand_performer_id.choices = [(u.id, u.username) for u in db.session.query(User).all()]
	form.demand_equipment_id.choices = [(e.equipment_id, \
		e.equipment_type.equipment_type + " - " + e.equipment_hostname + " (" + e.equipment_owner + ")") \
		for e in db.session.query(Client).filter_by(client_id = id).first().equipments.all()]
	form.demand_equipment_id.choices.insert(0, ("0", "---"))
	client = db.session.query(Client).filter_by(client_id = id).first()
	if form.validate_on_submit():
		try:
			demand = Demand(status = form.status.data, \
			demand_client_id = id, \
			demand_creator_id = current_user.id, \
			demand_performer_id = form.demand_performer_id.data, \
			demand_name = form.demand_name.data, \
			demand_equipment_id = (lambda i : i or None)(form.demand_equipment_id.data), \
			demand_date_deadline = form.demand_date_deadline.data, \
			demand_data = form.demand_data.data, \
			demand_contact = form.demand_contact.data)
			db.session.add(demand)
			db.session.commit()
			return redirect('./')
		except:
			return render_template('error.html')
	return render_template('client_new_demand.html', client=client, form=form)

@app.route('/client/<string:id>/demand/<int:demand_id>', methods=['GET', 'POST'])
@login_required
def demand_edit(id, demand_id):
	demand = db.session.query(Demand).filter_by(demand_id = demand_id).first()
	if id != str(demand.client.client_id):
		return redirect('/client/' + str(demand.client.client_id) + '/demand/' + str(demand_id)) 
	client = demand.client
	if demand.status == 0:
		form = ClosedDemandForm()
	else:
		form = DemandForm()
	form.demand_performer_id.choices = [(u.id, u.username) for u in db.session.query(User).all()]
	form.demand_equipment_id.choices = [(e.equipment_id, \
		e.equipment_type.equipment_type + " - " + e.equipment_hostname + " (" + e.equipment_owner + ")") \
		for e in db.session.query(Client).filter_by(client_id = id).first().equipments.all()]
	form.demand_creator_id.choices = [(u.id, u.username) for u in db.session.query(User).all()]
	form.demand_equipment_id.choices.insert(0, ("", "---"))
	#form.demand_equipment_id.default = demand.demand_equipment_id
	client = db.session.query(Client).filter_by(client_id = id).first()
	demand = client.demands.filter_by(demand_id = demand_id).first()

	if form.validate_on_submit():
		try:
			if demand.status != 0:
				demand.demand_performer_id = form.demand_performer_id.data
				demand.demand_name = form.demand_name.data
				demand.demand_equipment_id = (lambda i : i or None)(form.demand_equipment_id.data)
				demand.demand_date_deadline = form.demand_date_deadline.data
				demand.demand_data = form.demand_data.data
				demand.demand_contact = form.demand_contact.data
				if demand.status == 0:
					demand.demand_date_finish = datetime.datetime.now()
			else:
				demand.demand_date_finish = None
			demand.status = form.status.data
			demand.demand_date_last = datetime.datetime.now()
			db.session.commit()
			return redirect('./')
		except:
			return render_template('error.html')
	return render_template('client_edit_demand.html', client=client, demand = demand, form=form)
	
@app.route('/client/<string:id>/demand/', methods=['GET', 'POST'])
@login_required
def demand_view(id):
	form = DemandForm()
	client = db.session.query(Client).filter_by(client_id = id).first()
	return render_template('client_demands.html', client=client, form=form)


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect('/')





@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html', error = e)

@app.errorhandler(HTTPException)
def some_error(e):
	return render_template('error.html', error = e)

@login_manager.unauthorized_handler
def unauthorized():
	return redirect('/')




class ClientForm(FlaskForm):
	name = StringField(label = 'Полное наименование организации:', validators=[validators.DataRequired(), validators.Length(max=60)])
	short_name = StringField(label = 'Краткое название:', validators=[validators.DataRequired(), validators.Length(max=60)])
	dogovor = StringField(label = 'Номер договора:', validators=[validators.DataRequired(), validators.Length(max=20)])
	date = DateField(label = 'Дата заключения договора:', format='%Y-%m-%d')
	client_status = SelectField(label = 'Статус договора', choices=[('1', 'Активен'), ('0', 'Не обслуживается')])

class PeopleForm(FlaskForm):
	people_edit_id = HiddenField()
	people_fio = StringField(label = 'ФИО', validators=[validators.Length(max=50)])
	people_job = StringField(label = 'Должность', validators=[validators.Length(max=50)])
	people_contact = StringField(label = 'Контакт', validators=[validators.DataRequired(), validators.Length(max=50)])
	people_comment = StringField(label = 'Комментарий')
	submit = SubmitField('Добавить контакт')

class EquipmentForm(FlaskForm):
	equipment_edit_id = HiddenField()
	equipment_type_id = SelectField(label = 'Тип оборудования', validators=[validators.DataRequired()])
	equipment_model = StringField(label = 'Модель', validators=[validators.Length(max=100)])
	equipment_specs  = StringField(label = 'Характеристики', validators=[validators.Length(max=100)])
	equipment_hostname = StringField(label = 'Имя в сети', validators=[validators.Length(max=100)])
	equipment_owner = StringField(label = 'Ответственное лицо', validators=[validators.Length(max=100)])
	equipment_id = SelectField(label = 'Адрес', validators=[validators.DataRequired()])
	submit = SubmitField('Добавить оборудование')

class AddressForm(FlaskForm):
	address_edit_id = HiddenField()
	name = StringField(label = 'Адрес', validators=[validators.DataRequired(), validators.Length(max=50)])
	submit = SubmitField('Добавить адрес')

class DemandForm(FlaskForm):
	demand_id = StringField(label = 'Номер')
	demand_date = StringField(label = 'Дата создания')
	demand_date_last = StringField(label = 'Дата изменения')
	status = SelectField(label = 'Статус', \
			choices=[('1', 'В работе'), ('0', 'Закрыта'), ('2', 'Отслеживается')], \
			validators=[validators.DataRequired()]) 
	demand_performer_id = SelectField(label = 'Исполнитель', \
			validators=[validators.DataRequired()])
	demand_date_deadline = DateField(label = 'Срок выполнения', \
			default = datetime.datetime.now().date() + datetime.timedelta(days=2),\
			validators=[validators.DataRequired()])
	demand_contact = StringField(label = 'Контакт для связи', validators=[validators.Length(max=100)])
	demand_name = StringField(label = 'Краткое название', validators=[validators.Length(max=100), validators.DataRequired()])
	demand_equipment_id = SelectField(label = 'Оборудование')
	demand_creator_id = SelectField(label = 'Автор заявки', validators=[validators.Optional()])
	demand_data = TextAreaField(label = 'Подробное описание')
	submit = SubmitField('Добавить заявку')
	
	def isReadOnly(self, status):
		if status == 0:
			return True
		else:
			return False

class ClosedDemandForm(FlaskForm):
	demand_id = StringField(label = 'Номер', validators=[validators.Optional()])
	demand_date = StringField(label = 'Дата создания', validators=[validators.Optional()])
	demand_date_last = StringField(label = 'Дата изменения', validators=[validators.Optional()])
	status = SelectField(label = 'Статус', \
			choices=[('1', 'В работе'), ('0', 'Закрыта'), ('2', 'Отслеживается')], \
			validators=[validators.DataRequired()])
	demand_performer_id = SelectField(label = 'Исполнитель', \
			validators=[validators.Optional()])
	demand_date_deadline = DateField(label = 'Срок выполнения', \
			default = datetime.datetime.now().date() + datetime.timedelta(days=2),\
			validators=[validators.Optional()])
	demand_contact = StringField(label = 'Контакт для связи', validators=[validators.Optional()])
	demand_name = StringField(label = 'Краткое название', validators=[validators.Optional()])
	demand_equipment_id = SelectField(label = 'Оборудование', validators=[validators.Optional()])
	demand_creator_id = SelectField(label = 'Автор заявки', validators=[validators.Optional()])
	demand_data = TextAreaField(label = 'Подробное описание', validators=[validators.Optional()])
	submit = SubmitField('Добавить заявку', validators=[validators.Optional()])
	
	def isReadOnly(self, status):
		if status == 0:
			return True
		else:
			return False




class User(db.Model, UserMixin):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	login = db.Column(db.String(20), unique=True, nullable=False)
	username = db.Column(db.String(80), nullable=False)
	password_hash = db.Column(db.String(50), nullable=False)
	demands_to = db.relationship('Demand', backref='user_to', lazy='dynamic', foreign_keys = 'Demand.demand_performer_id')
	demands_from = db.relationship('Demand', backref='user_from', lazy='dynamic', foreign_keys = 'Demand.demand_creator_id')
	roles = db.relationship('Role', secondary='user_roles', backref=db.backref('users', lazy='dynamic'))
	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)
		
	def __init__(self, login, username, password):
		self.login = login
		self.username = username
		self.set_password(password)
		self.roles = 'not_active'

	def __repr__(self):
		return f'Note {self.login}'




class Role(db.Model):
	id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
	name = db.Column(db.String(50), unique=True)

class UserRoles(db.Model):
	id = db.Column(db.Integer(), primary_key=True)
	user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
	role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))



class Address(db.Model):
	__tablename__ = 'address'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	name = db.Column(db.String(50))
	address_client_id = db.Column(db.Integer, db.ForeignKey('client.client_id'))
	equipments = db.relationship('Equipment', backref='address', lazy='dynamic')

	def __init__(self, name, address_client_id):
		self.name = name
		self.address_client_id = address_client_id

class Client(db.Model):
	__tablename__ = 'client'

	client_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	name = db.Column(db.String(60))
	short_name = db.Column(db.String(60), nullable=False)
	dogovor = db.Column(db.String(20))
	date = db.Column(db.Date, nullable=False)
	client_status = db.Column(db.Integer, nullable=False, server_default='1')
	client_document = db.Column(db.Text, nullable=False)
	addresses = db.relationship('Address', backref='client', lazy='dynamic')
	demands = db.relationship('Demand', backref='client', lazy='dynamic')
	equipments = db.relationship('Equipment', backref='client', lazy='dynamic')
	people = db.relationship('People', backref='client', lazy='dynamic')
	def __init__(self, name, short_name, dogovor, date, client_status, client_document):
		self.name = name
		self.short_name = short_name
		self.dogovor = dogovor
		self.date = date
		self.client_status = client_status
		self.client_document = client_document

class Demand(db.Model):
	__tablename__ = 'demand'

	demand_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	status = db.Column(db.Integer, nullable=False)
	demand_client_id = db.Column(db.Integer, db.ForeignKey('client.client_id'), nullable=False)
	demand_creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	demand_performer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	demand_date = db.Column(db.DateTime, nullable=False)
	demand_date_last = db.Column(db.DateTime, nullable=False)
	demand_date_deadline = db.Column(db.DateTime, nullable=False)
	demand_date_finish = db.Column(db.DateTime)
	demand_contact = db.Column(db.String(100), nullable=True)
	demand_data = db.Column(db.Text, nullable=True)
	demand_name = db.Column(db.String(100), nullable=False)
	demand_equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.equipment_id'), nullable=True)
	
	def __init__(self, \
		status, demand_client_id, \
		demand_creator_id, demand_name, demand_performer_id,\
		demand_equipment_id = None, \
		demand_date_deadline = datetime.datetime.now() + datetime.timedelta(days = 2), \
		demand_data = None, demand_contact = None):
		self.status = status
		self.demand_client_id = demand_client_id
		self.demand_creator_id = demand_creator_id
		self.demand_performer_id = demand_performer_id
		self.demand_date = (datetime.datetime.now() + datetime.timedelta(days = 2)).date()
		self.demand_date_last = datetime.datetime.now()
		self.demand_date_deadline = demand_date_deadline
		self.demand_contact = demand_contact
		self.demand_data = demand_data
		self.demand_name = demand_name
		self.demand_equipment_id = demand_equipment_id
	def isExpired(self):
		if self.demand_date_deadline.date() < datetime.datetime.now().date():
			return True
		else:
			return False

class Equipment(db.Model):
	__tablename__ = 'equipment'

	equipment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	equipment_type_id = db.Column(db.Integer, db.ForeignKey('equipment_type.equipment_type_id'), nullable=False)
	equipment_client_id = db.Column(db.Integer, db.ForeignKey('client.client_id'), nullable=False)
	equipment_id = db.Column(db.Integer, db.ForeignKey('address.id'), nullable=False)
	equipment_model = db.Column(db.String(100), nullable=True)
	equipment_specs = db.Column(db.String(100), nullable=True)
	equipment_hostname = db.Column(db.String(100), nullable=True)
	equipment_owner = db.Column(db.String(100), nullable=True)
	equipment_status = db.Column(db.Integer, nullable=False, server_default='1')
	demands = db.relationship('Demand', backref='equipment', lazy='dynamic')

	def __init__(self, equipment_type_id, equipment_client_id, equipment_id, equipment_model=None, equipment_hostname = None, equipment_owner = None, equipment_specs = None, equipment_status = 1):
		self.equipment_type_id = equipment_type_id
		self.equipment_client_id = equipment_client_id
		self.equipment_id = equipment_id
		self.equipment_model = equipment_model
		self.equipment_hostname = equipment_hostname
		self.equipment_owner = equipment_owner

class EquipmentType(db.Model):
	__tablename__ = 'equipment_type'

	equipment_type_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	equipment_type = db.Column(db.Text(60))
	equipments = db.relationship('Equipment', backref='equipment_type', lazy='dynamic')

def __init__(self, equipment_type):
	self.equipment_type = equipment_type

class People(db.Model):
	__tablename__ = 'people'

	people_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	people_client_id = db.Column(db.Integer, db.ForeignKey('client.client_id'), nullable=False)
	people_fio = db.Column(db.String(50), nullable=True)
	people_job = db.Column(db.String(50), nullable=True)
	people_contact = db.Column(db.String(50), nullable=False)
	people_comment = db.Column(db.Text, nullable=True)

	def __init__(self, people_client_id, people_fio, people_job, people_contact, people_comment):
		self.people_client_id = people_client_id
		self.people_fio = people_fio
		self.people_job = people_job
		self.people_contact = people_contact
		self.people_comment = people_comment


if __name__ == '__main__':
	app.run()