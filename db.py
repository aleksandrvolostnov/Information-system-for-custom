from app import db, CertificationCenters  # Импортируйте вашу модель и db
db.create_all()  # Убедитесь, что таблица создана
centers = CertificationCenters.query.all()  # Получаем все записи
print(centers)  # Выводим записи