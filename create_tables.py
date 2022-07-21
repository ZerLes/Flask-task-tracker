import os
from app import db
try:
	if os.path.exists("demofile.txt"):
		os.remove("test1.db")
	db.create_all()
	print('База данных успешно создана!')
except:
	print('Ошибка при создании базы данных!')