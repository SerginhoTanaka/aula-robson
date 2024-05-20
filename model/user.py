import sqlite3

connection = sqlite3.connect("database.db")
cursor = connection.cursor()

# Criação da tabela 'users' com id autoincrementado
command_users = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT,
    password TEXT, 
    cpf TEXT,
    email TEXT,
    whatsapp TEXT,
    senha TEXT,
    foto TEXT
);
"""
cursor.execute(command_users)

# Criação da tabela 'login_sessions' com relacionamento
command_login_sessions = """
CREATE TABLE IF NOT EXISTS login_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    data_hora_login TIMESTAMP,
    hash TEXT,
    data_hora_expiracao TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""
cursor.execute(command_login_sessions)

# Commit das alterações e fechamento da conexão
connection.commit()
connection.close()
