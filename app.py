
import sqlite3
import os
from pycpfcnpj import cpfcnpj
from datetime import datetime,timedelta
from email_validator import validate_email, EmailNotValidError
import hashlib
from flask import Flask, request, session, render_template, redirect, url_for

from flask import jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route('/')
def index():
    return render_template('index.html', name='login')
@app.route('/calc',methods=['GET','POST'])
def calc_page():
    print(request.method)
    if request.method == 'POST':
        data = request.get_json()
        num1 = int(data['num1'])
        num2 = int(data['num2'])
        operator = data['operator']
        swicher = {
            'add': num1 + num2,
            'subtract': num1 - num2,
            'multiply': num1 * num2, 
            'divide' : num1 / num2 if num2 != 0 else 'cannot divide by zero',
        }
        result = swicher.get(operator, 'Invalid operator')
        return jsonify(result)
    return render_template('page.html', name='index')

def generate_token():
    return hashlib.sha256(os.urandom(24)).hexdigest()

def validate_token(user_id, token):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    command = f"SELECT data_hora_expiracao FROM login_sessions WHERE user_id = ? AND hash = ?"
    cursor.execute(command, (user_id, token))
    session_data = cursor.fetchone()
    connection.close()
    if session_data:
        expiration_time = datetime.strptime(session_data[0], "%Y-%m-%d %H:%M:%S")
        if datetime.now() < expiration_time:
            return True
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    user_id = session.get('user_id')
    token = session.get('user_hash')
    
    # Verifica se o usuário já tem um token válido
    if user_id and token and validate_token(user_id, token):
        # Redireciona para a página protegida
        return redirect(url_for('protected'))
    
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['password']
        date_time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        
        command = "SELECT * FROM users WHERE email = ? AND password = ?"
        cursor.execute(command, (email, senha))
        user_data = cursor.fetchone()
        connection.close()
        
        if user_data:
            session['logged_in'] = True
            session['user_id'] = user_data[0]
            token = generate_token()
            session['user_hash'] = token
            date_time_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            date_time_expiration = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            
            connection = sqlite3.connect("database.db")
            cursor = connection.cursor()
            cursor.execute("INSERT INTO login_sessions (user_id, data_hora_login, hash, data_hora_expiracao) VALUES (?, ?, ?, ?)", 
                           (session['user_id'], date_time_login, token, date_time_expiration))
            connection.commit()
            connection.close()
            
            # return f"Usuário logado com sucesso. Seu ID é {user_data[0]}, data de login: {date_time_login}, data de expiração: {date_time_expiration}, hash: {token}"
            return redirect(url_for('calc_page'))
    return render_template('index.html', name='login')

@app.route('/protected')
def protected():
    user_id = session.get('user_id')
    token = session.get('user_hash')
    if user_id and token and validate_token(user_id, token):
        new_expiration = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute("UPDATE login_sessions SET data_hora_expiracao = ? WHERE user_id = ? AND hash = ?", 
                       (new_expiration, user_id, token))
        connection.commit()
        connection.close()
        return "Acesso permitido. Sessão renovada."
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome']
        cpf = request.form['cpf']
        email = request.form['email']
        whatsapp = request.form['whatsapp']
        password = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']

        if 'foto' in request.files:
            foto = request.files['foto']
            if foto.filename != '':
                if not os.path.exists("data"):
                    os.makedirs("data")
                foto_path = os.path.join("data", foto.filename)
                foto.save(foto_path)
            else:
                foto_path = None
        else:
            foto_path = None

        # Validação de CPF
        if not validar_cpf(cpf):
            return "CPF inválido"

        # Validação de E-mail
        if not validar_email(email):
            return "Email inválido"

        # Verifica se as senhas conferem
        if password != confirmar_senha:
            return "Senhas não conferem"

        # Comando SQL para inserir os dados na tabela 'users'
        command = f"""INSERT INTO users (nome, cpf, email, whatsapp, password, foto) 
                        VALUES ('{nome}', '{cpf}', '{email}', '{whatsapp}', '{password}', '{foto_path}')"""

        # Executa o comando SQL para inserção no banco de dados
        if database_insert(command):
            return "Cadastro realizado com sucesso"
        else:
            return "Erro ao cadastrar usuário"

    return render_template('register.html', name='register')

def validar_cpf(cpf):
    return cpfcnpj.validate(cpf)

def validar_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def database_insert(command):
    try:
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute(command)
        connection.commit()
        connection.close()
        return True
    except Exception as e:
        print(e)
        return False

if __name__ == '__main__':
    app.run(debug=True)