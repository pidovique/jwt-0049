from flask import Flask, request
import sqlite3
import os


app = Flask(__name__)
DATABASE = 'example.db'

def init_db():

    if  os.path.exists(DATABASE):
        os.remove(DATABASE)


    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Poblar la base de datos con algunos datos
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # insert some sample data

    users = [

        ('admin', 'admin123'),
        ('user1', 'password1'),
        ('user2', 'password2'),
    ]

    cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
    conn.commit()
    conn.close()


@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username', '')

    conn =sqlite3.connect(DATABASE)
    cursor = conn.cursor()


    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)    

    result = cursor.fetchone()
    conn.close()

    if result:
        return f"Welcome {result[0]} Existe!"
    else:
        return "User no encontrado.", 404 
    
if __name__ == '__main__':
    init_db()
    app.run(debug=True)



