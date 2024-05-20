from flask import Flask
from flask import render_template
from flask import request
import sqlite3
import os
from pycpfcnpj import cpfcnpj
from email_validator import validate_email, EmailNotValidError
app = Flask(__name__)
import hashlib
from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/calc',methods=['GET','POST'])
def calc_page():
    if request.method == 'POST':
        num1 = request.form['num1']
        num2 = request.form['num2']
        operator = request.form['operator']
        
        swicher = {
            'add': num1 + num2,
            'subtract': num1 - num2,
            'multiply': num1 * num2, 
            'divide' : num1 / num2 if num2 != 0 else 'Invalid operator'
        }
        result = swicher.get(operator, 'Invalid operator')
        print(result)
        return render_template('calc.html', result=result)
        
    return render_template('page.html', name='index')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        # Comando SQL para buscar usuário pelo e-mail e senha
        command = f"SELECT * FROM users WHERE email = '{email}' AND senha = '{senha}'"

        # Executa o comando SQL para buscar usuário no banco de dados
        user_data = database_select(command)

        if user_data:
            # Criação do hash para o login bem-sucedido
            session['logged_in'] = True
            session['user_id'] = user_data['id']
            session['user_hash'] = hashlib.sha256(os.urandom(24)).hexdigest()

            # Retorna para o usuário todas as informações do banco de dados
            return f"Login bem-sucedido. Informações do usuário: {user_data}"
        else:
            return "E-mail ou senha incorretos."

    return render_template('login.html', name='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome']
        cpf = request.form['cpf']
        email = request.form['email']
        whatsapp = request.form['whatsapp']
        senha = request.form['senha']
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
        if senha != confirmar_senha:
            return "Senhas não conferem"

        # Comando SQL para inserir os dados na tabela 'users'
        command = f"""INSERT INTO users (nome, cpf, email, whatsapp, senha, foto) 
                        VALUES ('{nome}', '{cpf}', '{email}', '{whatsapp}', '{senha}', '{foto_path}')"""

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