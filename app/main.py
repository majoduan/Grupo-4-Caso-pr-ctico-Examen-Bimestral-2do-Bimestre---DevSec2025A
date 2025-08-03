import secrets
import re
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db
from .logger import logger, log_request, log_auth_attempt

# Define a simple in-memory token store
tokens = {}

# JWT Helper Functions
def generate_jwt_token(user_data):
    """Genera un token JWT con la información del usuario"""
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'full_name': user_data['full_name'],
        'email': user_data['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token):
    """Decodifica y valida un token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expirado
    except jwt.InvalidTokenError:
        return None  # Token inválido

#log = logging.getLogger(__name__)
logging.basicConfig(
     filename="app.log",
     level=logging.DEBUG,
     encoding="utf-8",
     filemode="a",
     format="{asctime} - {levelname} - {message}",
     style="{",
     datefmt="%Y-%m-%d %H:%M",
)
# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        """Inicia sesión y devuelve un token de autenticación."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        otp = data.get("otp")  
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, full_name, email, otp FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user:
            if user[3] == 'cajero':
                # Un cajero requiere OTP
                if not otp or otp != user[6]:
                    cur.close()
                    conn.close()
                    api.abort(401, "OTP required or invalid for cashier")
            if user[2] == password:
                token = secrets.token_hex(16)
                cur.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", (token, user[0]))
                conn.commit()
                cur.close()
                conn.close()
                return {"message": "Login successful", "token": token}, 200
        cur.close()
        conn.close()
        
        if user and user[2] == password:
            # Crear datos del usuario para el JWT
            user_data = {
                'id': user[0],
                'username': user[1],
                'role': user[3],
                'full_name': user[4],
                'email': user[5]
            }
            
            # Generar token JWT
            token = generate_jwt_token(user_data)
            
            # Registrar login exitoso
            log_auth_attempt(username, True, 200)
            
            return {
                "message": "Login successful", 
                "token": token,
                "user": {
                    "id": user_data['id'],
                    "username": user_data['username'],
                    "role": user_data['role'],
                    "full_name": user_data['full_name']
                }
            }, 200
        else:
            # Registrar intento de login fallido
            log_auth_attempt(username, False, 401)
            api.abort(401, "Invalid credentials")

        api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    @log_request('INFO')
    def post(self):
        """Invalida el token de autenticación."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM bank.tokens WHERE token = %s", (token,))
        if cur.rowcount == 0:
            conn.commit()
            cur.close()
            conn.close()
            api.abort(401, "Invalid token")
        conn.commit()
        cur.close()
        conn.close()
        return {"message": "Logout successful"}, 200

@auth_ns.route('/me')
class UserProfile(Resource):
    @auth_ns.doc('get_user_profile')
    @log_request('INFO')
    def get(self):
        """Obtiene la información del usuario autenticado usando JWT."""
        # Verificación manual de JWT para este endpoint hasta reorganizar
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        
        token = auth_header.split(" ")[1]
        payload = decode_jwt_token(token)
        if not payload:
            api.abort(401, "Invalid or expired JWT token")
            
# Registrar cajero
register_cashier_model = auth_ns.model('RegisterCashier', {
    'username': fields.String(required=True, description='Usuario (letras y números)', example='cajero123'),
    'password': fields.String(required=True, description='Contraseña (mínimo 10 caracteres, letras, números y símbolos)', example='Cajero$2025!'),
    'otp': fields.String(required=True, description='OTP para el cajero', example='123456')
})

# estringe el acceso solo a usuarios con rol 'cajero'
def cashier_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user.get('role') != 'cajero':
            api.abort(403, "Only cashiers can perform this operation")
        return f(*args, **kwargs)
    return decorated

# Endpoint para registrar cajero
@auth_ns.route('/register-cashier')
class RegisterCashier(Resource):
    @auth_ns.expect(register_cashier_model, validate=True)
    @auth_ns.doc('register_cashier')
    def post(self):
        """Registra un nuevo cajero (solo username, password y OTP)."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        otp = data.get("otp")

        # Validar username: letras y números
        if not re.match(r'^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]+$', username):
            api.abort(400, "Username must contain both letters and numbers")
        # Validar password: mínimo 10 caracteres, letras, números y símbolos
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).{10,}$', password):
            api.abort(400, "Password must be at least 10 characters and include letters, numbers, and symbols")
        # Validar OTP: solo números, 6 dígitos
        if not re.match(r'^\d{6}$', otp):
            api.abort(400, "OTP must be a 6-digit number")

        conn = get_connection()
        cur = conn.cursor()
        # Verificar que el usuario no exista
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            api.abort(400, "Username already exists")
        # Insertar cajero
        cur.execute(
            "INSERT INTO bank.users (username, password, role, otp) VALUES (%s, %s, %s, %s)",
            (username, password, 'cajero', otp)
        )
        conn.commit()
        cur.close()
        conn.close()
        return {"message": "Cashier registered successfully"}, 201

# ---------------- Token-Required Decorator ----------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]

        logger.debug(f"JWT Token received: {token[:20]}...", 200)
        
        # Decodificar y validar el token JWT
        payload = decode_jwt_token(token)
        if not payload:
            api.abort(401, "Invalid or expired JWT token")
        
        # Establecer la información del usuario en el contexto global
        logging.debug("Token: "+str(token))
        conn = get_connection()
        cur = conn.cursor()
        # Query the token in the database and join with users table to retrieve user info
        cur.execute("""
            SELECT u.id, u.username, u.role, u.full_name, u.email 
            FROM bank.tokens t
            JOIN bank.users u ON t.user_id = u.id
            WHERE t.token = %s
        """, (token,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user:
            api.abort(401, "Invalid or expired token")
        g.user = {
            "id": user[0],
            "username": user[1],
            "role": user[2],
            "full_name": user[3],
            "email": user[4]
        }
        
        logger.debug(f"JWT Token validated for user: {g.user['username']}", 200)

        return f(*args, **kwargs)
    return decorated

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    logging.debug("Entering....")
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit')
    @token_required
    @cashier_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        logger.debug("Entering deposit endpoint", 200)

        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        
        conn = get_connection()
        cur = conn.cursor()
        # Update the specified account using its account number (primary key)
        cur.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (amount, account_number)
        )
        result = cur.fetchone()
        if not result:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        new_balance = float(result[0])
        conn.commit()
        cur.close()
        conn.close()
        
        # Log the successful deposit with amount details
        logger.info(f"Depósito exitoso: ${amount:.2f} en cuenta {account_number}. Nuevo saldo: ${new_balance:.2f}", 200)
        
        return {"message": "Deposit successful", "new_balance": new_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    @cashier_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        current_balance = float(row[0])
        if current_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
        new_balance = float(cur.fetchone()[0])
        conn.commit()
        cur.close()
        conn.close()
        
        # Log the successful withdrawal with amount details
        logger.info(f"Retiro exitoso: ${amount:.2f} de cuenta del usuario {g.user['username']}. Nuevo saldo: ${new_balance:.2f}", 200)
        
        return {"message": "Withdrawal successful", "new_balance": new_balance}, 200

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        if not target_username or amount <= 0:
            api.abort(400, "Invalid data")
        if target_username == g.user['username']:
            api.abort(400, "Cannot transfer to the same account")
        conn = get_connection()
        cur = conn.cursor()
        # Check sender's balance
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Sender account not found")
        sender_balance = float(row[0])
        if sender_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        # Find target user
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            cur.close()
            conn.close()
            api.abort(404, "Target user not found")
        target_user_id = target_user[0]
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            
            # Log the successful transfer with amount details
            logger.info(f"Transferencia exitosa: ${amount:.2f} de {g.user['username']} a {target_username}. Nuevo saldo: ${new_balance:.2f}", 200)
            
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error during transfer: {str(e)}")
        cur.close()
        conn.close()
        return {"message": "Transfer successful", "new_balance": new_balance}, 200

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment')
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds in account")
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            conn.commit()
            
            # Log the successful credit purchase with amount details
            logger.info(f"Compra a crédito exitosa: ${amount:.2f} para usuario {g.user['username']}. Saldo cuenta: ${new_account_balance:.2f}, Deuda tarjeta: ${new_credit_balance:.2f}", 200)
            
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error processing credit card purchase: {str(e)}")
        cur.close()
        conn.close()
        return {
            "message": "Credit card purchase successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_balance
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance')
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        # Check account funds
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds in account")
        # Get current credit card debt
        cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            api.abort(404, "Credit card not found")
        credit_debt = float(row[0])
        payment = min(amount, credit_debt)
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
            
            # Log the successful credit payment with amount details
            logger.info(f"Pago de tarjeta de crédito exitoso: ${payment:.2f} de usuario {g.user['username']}. Saldo cuenta: ${new_account_balance:.2f}, Nueva deuda: ${new_credit_debt:.2f}", 200)
            
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error processing credit balance payment: {str(e)}")
        cur.close()
        conn.close()
        return {
            "message": "Credit card debt payment successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_debt
        }, 200

# ---------------- Admin Endpoints ----------------

@auth_ns.route('/logs')
class ViewLogs(Resource):
    @auth_ns.doc('view_logs')
    @token_required
    @log_request('INFO')
    def get(self):
        """Consulta los logs del sistema (solo para administradores)."""
        # Verificar que el usuario tenga rol de administrador
        if g.user.get('role') != 'admin':
            logger.warning("Intento de acceso no autorizado a logs", 403)
            api.abort(403, "Access denied. Admin role required.")
        
        try:
            # Parámetros de consulta opcionales
            limit = request.args.get('limit', 50, type=int)
            log_level = request.args.get('level', '')
            username = request.args.get('username', '')
            
            conn = logger._get_logs_connection()
            cursor = conn.cursor()
            
            # Construir consulta con filtros
            query = "SELECT * FROM logs WHERE 1=1"
            params = []
            
            if log_level:
                query += " AND log_level = %s"
                params.append(log_level)
            
            if username:
                query += " AND username = %s"
                params.append(username)
            
            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            logs = cursor.fetchall()
            
            # Formatear resultados
            logs_list = []
            for log in logs:
                logs_list.append({
                    'id': log[0],
                    'timestamp_local': log[1],
                    'log_level': log[2],
                    'remote_ip': log[3],
                    'username': log[4],
                    'action_message': log[5],
                    'http_response_code': log[6],
                    'created_at': log[7].isoformat() if log[7] else None
                })
            
            cursor.close()
            conn.close()
            
            return {
                'logs': logs_list,
                'total_returned': len(logs_list),
                'filters_applied': {
                    'limit': limit,
                    'log_level': log_level,
                    'username': username
                }
            }, 200
            
        except Exception as e:
            logger.error(f"Error consultando logs: {str(e)}", 500)
            api.abort(500, f"Error retrieving logs: {str(e)}")

@bank_ns.route('/accounts')
class Accounts(Resource):
    @bank_ns.doc('get_accounts')
    @token_required
    def get(self):
        """Obtiene las cuentas del usuario autenticado con su saldo y número de cuenta."""
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        accounts = cur.fetchall()
        cur.close()
        conn.close()

        result = [{"account_number": acc[0], "balance": float(acc[1])} for acc in accounts]
        return {"accounts": result}, 200

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)


