from flask import Flask
from flask import render_template
from flask import request
import sqlite3
import os
from pycpfcnpj import cpfcnpj
from datetime import datetime,timedelta
from email_validator import validate_email, EmailNotValidError
app = Flask(__name__)
import hashlib
from flask import Flask, render_template, request, session,jsonify

app = Flask(__name__)
app.secret_key = os.urandom(24)

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

@app.route('/login', methods=['GET', 'POST'])
def login():
      
        if request.method == 'POST':
            email = request.form['email']
            senha = request.form['password']

            command = f"SELECT * FROM users WHERE email = '{email}' AND password = '{senha}'"

            try:
                connection = sqlite3.connect("database.db")
                cursor = connection.cursor()
                user_data =  cursor.execute(command).fetchone()
                print(user_data)
                connection.close()
            except Exception as e:
                print(e)
                user_data = None
            if user_data or user_data is not None:
                session['logged_in'] = True
                session['user_id'] = user_data[0]
                session['user_hash'] = hashlib.sha256(os.urandom(24)).hexdigest()
                date_time_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                date_time_expiration = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                connection = sqlite3.connect("database.db")
                cursor = connection.cursor()
                cursor.execute(f"INSERT INTO login_sessions (user_id, data_hora_login, hash, data_hora_expiracao) VALUES ({session['user_id']}, '{date_time_login}', '{session['user_hash']}', '{date_time_expiration}')")
                connection.commit()
                connection.close()
                
                return f"Usuário logado com sucesso. Seu ID é {user_data[0]}, data de login: {date_time_login}, data de expiração: {date_time_expiration}, hash: {session['user_hash']}"

        return render_template('index.html', name='login')

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