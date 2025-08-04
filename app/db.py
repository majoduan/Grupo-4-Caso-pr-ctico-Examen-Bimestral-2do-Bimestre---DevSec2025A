import os
import psycopg2

# Variables de entorno (definidas en docker-compose o con valores por defecto)
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')

def get_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    
    # Crear esquema y tabla users con campo otp
    cur.execute("""
    CREATE SCHEMA IF NOT EXISTS bank AUTHORIZATION postgres;

    CREATE TABLE IF NOT EXISTS bank.users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        otp TEXT
    );
    """)
    conn.commit()
    
    # Crear tabla accounts
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.accounts (
        id SERIAL PRIMARY KEY,
        balance NUMERIC NOT NULL DEFAULT 0,
        user_id INTEGER REFERENCES bank.users(id)
    );
    """)
    conn.commit()
    
    # Crear tabla credit_cards
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.credit_cards (
        id SERIAL PRIMARY KEY,
        limit_credit NUMERIC NOT NULL DEFAULT 1,
        balance NUMERIC NOT NULL DEFAULT 0,
        user_id INTEGER REFERENCES bank.users(id)
    );
    """)
    
    # Crear tabla tokens
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    
    # Insertar usuarios de ejemplo si no existen
    cur.execute("SELECT COUNT(*) FROM bank.users;")
    count = cur.fetchone()[0]
    if count == 0:
        sample_users = [
        ('user1', 'password1', 'cliente', 'Usuario Uno', 'user1@example.com', None),
        ('user2', 'password2', 'cliente', 'Usuario Dos', 'user2@example.com', None),
        ('user3', 'password3', 'cajero', 'Usuario Tres', 'user3@example.com', '123456')
    ]
        for username, password, role, full_name, email, otp in sample_users:
            cur.execute("""
                INSERT INTO bank.users (username, password, role, full_name, email, otp)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;
            """, (username, password, role, full_name, email, otp))
            user_id = cur.fetchone()[0]
            # Crear cuenta con saldo inicial 1000
            cur.execute("""
                INSERT INTO bank.accounts (balance, user_id)
                VALUES (%s, %s);
            """, (1000, user_id))
            # Crear tarjeta de crédito con límite 5000 y deuda 0
            cur.execute("""
                INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                VALUES (%s, %s, %s);
            """, (5000, 0, user_id))
        conn.commit()
    cur.close()
    conn.close()
