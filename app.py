from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
app.secret_key = 'secret_key'

# Настройки базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1111@127.0.0.1/customs_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Папка для хранения загруженных файлов
UPLOAD_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")  # Папка "Загрузки"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # Папка "uploads" будет создана в корневой директории проекта
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


db = SQLAlchemy(app)


# Модель пользователя
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


# Модель товара
class Items(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    import_date = db.Column(db.Date, nullable=False)
    country_of_origin = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    ipfs_link = db.Column(db.String(255), nullable=True)  # Ссылка на IPFS


    # Связь с таблицей документов
    documents = db.relationship('Documents', backref='item', lazy=True)


# Модель документа
class Documents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=True)
    file_name = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)

class Centers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    street = db.Column(db.String(255), nullable=False)
    contact_phone = db.Column(db.String(50), nullable=False)
    working_hours = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=True)  # Координаты (широта)
    longitude = db.Column(db.Float, nullable=True)  # Координаты (долгота)






@app.route('/')
def welcome():
    return render_template('welcome.html')


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        new_user = Users(username=data['username'], password=data['password'])
        db.session.add(new_user)
        db.session.commit()
        flash('Пользователь зарегистрирован успешно!')
        return redirect(url_for('login'))
    return render_template('register.html')


# Вход в систему
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        user = Users.query.filter_by(username=username).first()
        if user and user.password == password:
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Неверные учетные данные!', 'error')
            return redirect(url_for('login'))

    flash('Введите свои учетные данные:', 'info')
    return render_template('login.html')


# Панель управления

from sqlalchemy import func

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем все товары
    all_items = Items.query.all()

    # Извлекаем статистику по странам
    item_counts = db.session.query(Items.country_of_origin, func.count(Items.id))\
                            .group_by(Items.country_of_origin).all()

    # Преобразуем данные для графика
    if item_counts:
        countries = [country for country, _ in item_counts]
        counts = [count for _, count in item_counts]
    else:
        countries = []  # Пустой список, если нет данных
        counts = []  # Пустой список, если нет данных

    # Отправляем данные в шаблон
    return render_template('dashboard.html', items=all_items, labels=countries, data=counts)

import requests

def get_coordinates(address):
    api_url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": address, "key": "YOUR_GOOGLE_API_KEY"}  # Укажите свой API-ключ
    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        data = response.json()
        if data['results']:
            location = data['results'][0]['geometry']['location']
            return location['lat'], location['lng']
    return None, None


@app.route('/centers', methods=['GET'])
def centers():
    search_query = request.args.get('search_query', '')
    if search_query:
        all_centers = Centers.query.filter(
            Centers.city.ilike(f'%{search_query}%')
        ).all()
    else:
        all_centers = Centers.query.all()

    # Преобразуем объекты Centers в список словарей
    centers_data = [
        {
            "id": center.id,
            "name": center.name,
            "city": center.city,
            "street": center.street,
            "latitude": center.latitude,
            "longitude": center.longitude,
            "contact_phone": center.contact_phone,
            "working_hours": center.working_hours,
        }
        for center in all_centers
    ]

    app.logger.info(f'Найденные центры: {centers_data}')

    return render_template('centers.html', centers=centers_data)


from sqlalchemy.orm import load_only

@app.route('/update_coordinates', methods=['GET'])
def update_coordinates():
    centers = Centers.query.filter(
        (Centers.latitude.is_(None)) | (Centers.longitude.is_(None))
    ).options(load_only(Centers.id, Centers.city, Centers.street)).all()

    for center in centers:
        address = f"{center.city}, {center.street}"
        lat, lng = get_coordinates(address)
        if lat and lng:
            center.latitude = lat
            center.longitude = lng
            db.session.commit()
    return "Coordinates updated successfully"

# Хранилище файлов
@app.route('/file_storage', methods=['GET'])
def file_storage():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Получаем все документы (файлы) для всех товаров
    all_documents = Documents.query.all()

    return render_template('file_storage.html', documents=all_documents)


# Загрузка файла
@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_document = Documents(user_id=session['user_id'], file_name=filename, file_path=file_path)
            db.session.add(new_document)
            db.session.commit()
            flash('Файл успешно загружен!')
            return redirect(url_for('file_storage'))
        else:
            flash('Файл не выбран.')
            return redirect(url_for('upload_file'))

    return render_template('upload_file.html')


@app.route('/download_file', methods=['GET'])
def download_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    filename = request.args.get('document_id')  # Получаем имя файла из параметров запроса

    if filename:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    else:
        flash('Файл не найден.')
        return redirect(url_for('file_storage'))


# Удаление файла
@app.route('/delete_file/<filename>', methods=['POST'])
def delete_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    document = Documents.query.filter_by(file_name=filename, user_id=session['user_id']).first()
    if document:
        db.session.delete(document)
        db.session.commit()
        os.remove(document.file_path)  # Удаляем файл из файловой системы
        flash('Файл успешно удалён!')

    return redirect(url_for('file_storage'))


# Выход
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Вы вышли из системы.')
    return redirect(url_for('welcome'))


# Добавление товара
@app.route('/add_item', methods=['GET', 'POST'])
def add_item():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        item_name = request.form['name']
        import_date = request.form['import_date']
        country_of_origin = request.form['country_of_origin']
        description = request.form.get('description', '')

        new_item = Items(name=item_name, import_date=import_date, country_of_origin=country_of_origin,
                         description=description)

        # Сохраняем новый товар
        db.session.add(new_item)
        db.session.commit()

        # Загружаем файл, если он был выбран
        file = request.files.get('file')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_document = Documents(user_id=session['user_id'], item_id=new_item.id, file_name=filename,
                                     file_path=file_path)
            db.session.add(new_document)

        db.session.commit()
        flash('Товар добавлен успешно!')
        return redirect(url_for('dashboard'))
    return render_template('add_item.html')


# Редактирование товара
@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    item = Items.query.get_or_404(item_id)

    if request.method == 'POST':
        # Обновление данных товара
        item.name = request.form['name']
        item.import_date = request.form['import_date']
        item.country_of_origin = request.form['country_of_origin']
        item.description = request.form.get('description', '')

        # Проверка на наличие нового файла
        file = request.files.get('file')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_document = Documents(user_id=session['user_id'], item_id=new_item.id, file_name=filename,
                                     file_path=file_path)
            db.session.add(new_document)
        db.session.commit()  # Коммитим все изменения
        flash('Товар успешно обновлён!')
        return redirect(url_for('items'))

    return render_template('edit_item.html', item=item)

# Страница товаров
@app.route('/items', methods=['GET'])
def items():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    all_items = Items.query.all()
    return render_template('items.html', items=all_items)

# Поиск товаров
@app.route('/search_items', methods=['GET', 'POST'])
def search_items():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    searched_items = []

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        country = request.form.get('country', '').strip()
        start_date = request.form.get('start_date', None)
        end_date = request.form.get('end_date', None)

        # Начинаем с базового запроса
        query = Items.query

        if search_query:
            query = query.filter(Items.name.ilike(f'%{search_query}%'))

        if country:
            query = query.filter(Items.country_of_origin.ilike(f'%{country}%'))

        if start_date:
            query = query.filter(Items.import_date >= start_date)

        if end_date:
            query = query.filter(Items.import_date <= end_date)

        searched_items = query.all()

    return render_template('search_items.html', found_items=searched_items)
import pandas as pd
from io import BytesIO
from flask import send_file

@app.route('/export_to_excel', methods=['POST'])
def export_to_excel():
    search_query = request.form.get('search_query', '').strip()
    country = request.form.get('country', '').strip()
    start_date = request.form.get('start_date', None)
    end_date = request.form.get('end_date', None)

    # Выполняем тот же поиск, что и в search_items
    query = Items.query
    if search_query:
        query = query.filter(Items.name.ilike(f'%{search_query}%'))
    if country:
        query = query.filter(Items.country_of_origin.ilike(f'%{country}%'))
    if start_date:
        query = query.filter(Items.import_date >= start_date)
    if end_date:
        query = query.filter(Items.import_date <= end_date)

    items = query.all()

    # Формируем DataFrame
    data = [{
        "Название": item.name,
        "Дата ввоза": item.import_date.strftime('%Y-%m-%d'),
        "Страна происхождения": item.country_of_origin,
        "Описание": item.description,
    } for item in items]

    df = pd.DataFrame(data)

    # Генерируем Excel-файл
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Товары')

    output.seek(0)

    # Возвращаем файл пользователю
    return send_file(output, as_attachment=True, download_name='search_results.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# Просмотр товара
@app.route('/view_item/<int:item_id>', methods=['GET'])
def view_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    item = Items.query.get_or_404(item_id)
    return render_template('view_item.html', item=item)


@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    app.logger.info(f"Удаление товара с ID: {item_id}")
    if 'user_id' not in session:
        return redirect(url_for('login'))

    item = Items.query.get_or_404(item_id)

    # Удаляем связанные документы
    documents = Documents.query.filter_by(item_id=item.id).all()
    for document in documents:
        try:
            os.remove(document.file_path)
        except FileNotFoundError:
            app.logger.error(f"Файл {document.file_path} не найден")
        db.session.delete(document)

    # Удаляем сам товар
    db.session.delete(item)
    db.session.commit()

    flash(f'Товар "{item.name}" был удалён!')
    return redirect(url_for('dashboard'))
@app.route('/statistics')
def statistics():
    # Получаем статистику из базы данных, например, количество товаров по странам
    country_counts = db.session.query(Items.country_of_origin, db.func.count(Items.id)).group_by(Items.country_of_origin).all()

    # Преобразуем данные для графика
    countries = [country for country, _ in country_counts]
    counts = [count for _, count in country_counts]

    return render_template('statistics.html', labels=countries, data=counts)


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

@app.route('/signature', methods=['GET', 'POST'])
def signature():
    # Логика для цифровой подписи
    return render_template('signature.html')

# Генерация пары ключей (закрытого и открытого)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сериализация закрытого ключа
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Сериализация открытого ключа
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


# Подписание документа
def sign_document(private_key_pem, document_data):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    signature = private_key.sign(
        document_data.encode(),  # Преобразуем текст документа в байты
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()


# Проверка подписи
def verify_signature(public_key_pem, document_data, signature):
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    try:
        public_key.verify(
            base64.b64decode(signature),
            document_data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False


# Пример использования
private_key_pem, public_key_pem = generate_keys()
document_data = "Это пример документа, который будет подписан."

# Подписываем документ
signature = sign_document(private_key_pem, document_data)

# Проверяем подпись
is_valid = verify_signature(public_key_pem, document_data, signature)

print("Подпись документа действительна:", is_valid)



#Блокчейн
from web3 import Web3

# Подключение к локальной или удаленной сети Ethereum
INFURA_URL = "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"  # Замените на свой Infura URL
web3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Проверяем подключение
if web3.isConnected():
    print("Подключение к Ethereum успешно!")
else:
    print("Ошибка подключения к Ethereum.")

# Пример функции для развертывания контракта
def deploy_contract(abi, bytecode, private_key):
    account = web3.eth.account.privateKeyToAccount(private_key)
    contract = web3.eth.contract(abi=abi, bytecode=bytecode)

    # Создаем транзакцию
    transaction = contract.constructor().buildTransaction({
        'from': account.address,
        'nonce': web3.eth.getTransactionCount(account.address),
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei')
    })

    # Подписываем транзакцию
    signed_txn = web3.eth.account.signTransaction(transaction, private_key)

    # Отправляем транзакцию в блокчейн
    tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)

    # Ждем подтверждения
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    return tx_receipt.contractAddress

# Пример вызова функции контракта
def call_contract_function(contract_address, abi, function_name, args, private_key):
    account = web3.eth.account.privateKeyToAccount(private_key)
    contract = web3.eth.contract(address=contract_address, abi=abi)

    # Создаем транзакцию
    transaction = contract.functions[function_name](*args).buildTransaction({
        'from': account.address,
        'nonce': web3.eth.getTransactionCount(account.address),
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei')
    })

    # Подписываем и отправляем транзакцию
    signed_txn = web3.eth.account.signTransaction(transaction, private_key)
    tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)

    # Ждем подтверждения
    receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    return receipt

if __name__ == '__main__':
    app.run(debug=True)
