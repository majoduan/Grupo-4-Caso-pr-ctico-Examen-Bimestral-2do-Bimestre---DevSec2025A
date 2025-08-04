import secrets
import re
import decimal
import datetime
import jwt
import logging
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db
from .logger import logger, log_request, log_auth_attempt

# JWT Configuration
JWT_SECRET_KEY = "B4nk3c_$3cur3_JWT_K3y_2025!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`1234567890abcdefABCDEF"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 5  # 5 minutos para tokens JWT (seguridad bancaria)

# Funciones de validación
def validate_amount(amount):
    """Valida que el monto sea un número positivo válido"""
    try:
        amount = float(amount)
        if amount <= 0:
            return False, "Amount must be greater than zero"
        if amount > 999999999.99:  # Límite máximo
            return False, "Amount exceeds maximum limit"
        # Verificar que no tenga más de 2 decimales
        if decimal.Decimal(str(amount)).as_tuple().exponent < -2:
            return False, "Amount cannot have more than 2 decimal places"
        return True, None
    except (ValueError, TypeError, decimal.InvalidOperation):
        return False, "Invalid amount format"

def validate_username(username):
    """Valida formato de username"""
    if not username or not isinstance(username, str):
        return False, "Username is required"
    if len(username) < 3 or len(username) > 50:
        return False, "Username must be between 3 and 50 characters"
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username contains invalid characters"
    return True, None

def validate_password(password):
    """Valida formato de password"""
    if not password or not isinstance(password, str):
        return False, "Password is required"
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    return True, None

def validate_account_number(account_number):
    """Valida número de cuenta"""
    try:
        account_number = int(account_number)
        if account_number <= 0:
            return False, "Account number must be positive"
        return True, None
    except (ValueError, TypeError):
        return False, "Invalid account number format"

def mask_sensitive_data(data, field_name):
    """Enmascara datos sensibles para logging"""
    if not data:
        return "***"
    
    if field_name.lower() in ['password', 'otp']:
        return "***MASKED***"
    elif field_name.lower() in ['username', 'email']:
        if len(data) <= 3:
            return "***"
        return data[:2] + "*" * (len(data) - 3) + data[-1]
    elif field_name.lower() in ['amount', 'balance']:
        return f"${float(data):.2f}"
    else:
        return str(data)

# JWT Helper Functions
def generate_jwt_token(user_data):
    """Genera un token JWT con la información del usuario"""
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'full_name': user_data['full_name'],
        'email': user_data['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES),
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

# Configurar logging estándar para desarrollo
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define a simple in-memory token store
tokens = {}
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
    'password': fields.String(required=True, description='Contraseña', example='pass1'),
    'otp': fields.String(required=False, description='OTP para cajeros', example='123456')
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
        
        # Validar parámetros de entrada
        valid_user, user_error = validate_username(username)
        if not valid_user:
            logger.warning(f"Login attempt with invalid username format: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, user_error)
        
        valid_pass, pass_error = validate_password(password)
        if not valid_pass:
            logger.warning(f"Login attempt with invalid password format for user: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, pass_error)
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, full_name, email, otp FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user:
            if user[3] == 'cajero':
                # Un cajero requiere OTP
                if not otp:
                    cur.close()
                    conn.close()
                    logger.warning(f"Cashier login attempt without OTP for user: {mask_sensitive_data(username, 'username')}", 401)
                    api.abort(401, "OTP required for cashier")
                if otp != user[6]:
                    cur.close()
                    conn.close()
                    logger.warning(f"Cashier login attempt with invalid OTP for user: {mask_sensitive_data(username, 'username')}", 401)
                    log_auth_attempt(username, False, 401)
                    api.abort(401, "Invalid OTP for cashier")
                    
            if user[2] == password:
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
                
                cur.close()
                conn.close()
                
                # Log successful login with masked data
                logger.info(f"Login exitoso para usuario: {mask_sensitive_data(username, 'username')} con rol: {user[3]}", 200)
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
        
        cur.close()
        conn.close()
        
        # Registrar intento de login fallido con datos enmascarados
        logger.warning(f"Login fallido para usuario: {mask_sensitive_data(username, 'username')}", 401)
        log_auth_attempt(username, False, 401)
        api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    @log_request('INFO')
    def post(self):
        """Invalida el token JWT (logout del lado del cliente)."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        
        token = auth_header.split(" ")[1]
        
        try:
            # Validar que el token JWT sea válido antes del logout
            payload = decode_jwt_token(token)
            if not payload:
                api.abort(401, "Invalid token")
            
            # Con JWT siendo stateless, el logout es responsabilidad del cliente
            # El cliente debe eliminar el token de su almacenamiento local
            logger.info(f"User {mask_sensitive_data(payload['username'], 'username')} logged out successfully", 200)
            
        except Exception as e:
            logger.warning(f"Logout attempt with invalid JWT token: {str(e)}", 401)
            api.abort(401, "Invalid token")
        
        return {"message": "Logout successful - Please remove token from client storage"}, 200

@auth_ns.route('/me')
class UserProfile(Resource):
    @auth_ns.doc('get_user_profile')
    def get(self):
        """Obtiene la información del usuario autenticado."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        
        token = auth_header.split(" ")[1]
        
        try:
            # Decodificar el token JWT
            payload = decode_jwt_token(token)
            if not payload:
                api.abort(401, "Invalid or expired token")
            
            user_id = payload['user_id']
            
        except Exception as e:
            logger.warning(f"JWT Token validation failed in /me endpoint: {str(e)}", 401)
            api.abort(401, "Invalid or expired token")
        
        conn = get_connection()
        cur = conn.cursor()
        # Query user info from database using user_id from JWT
        cur.execute("""
            SELECT u.id, u.username, u.role, u.full_name, u.email,
                   a.balance, cc.balance as credit_debt, cc.limit_credit
            FROM bank.users u
            LEFT JOIN bank.accounts a ON u.id = a.user_id
            LEFT JOIN bank.credit_cards cc ON u.id = cc.user_id
            WHERE u.id = %s
        """, (user_id,))
        
        user_data = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user_data:
            api.abort(404, "User not found")
        
        return {
            "user": {
                "id": user_data[0],
                "username": user_data[1],
                "role": user_data[2],
                "full_name": user_data[3],
                "email": user_data[4]
            },
            "account": {
                "balance": float(user_data[5]) if user_data[5] else 0,
                "credit_debt": float(user_data[6]) if user_data[6] else 0,
                "credit_limit": float(user_data[7]) if user_data[7] else 0
            }
        }, 200
            
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

        # Validar parámetros de entrada
        valid_user, user_error = validate_username(username)
        if not valid_user:
            logger.warning(f"Cashier registration attempt with invalid username: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, user_error)

        # Validar username: letras y números (más estricto para cajeros)
        if not re.match(r'^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]+$', username):
            logger.warning(f"Cashier registration with username not matching pattern: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, "Username must contain both letters and numbers")
            
        # Validar password: mínimo 10 caracteres, letras, números y símbolos
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).{10,}$', password):
            logger.warning(f"Cashier registration with weak password for user: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, "Password must be at least 10 characters and include letters, numbers, and symbols")
            
        # Validar OTP: solo números, 6 dígitos
        if not otp or not isinstance(otp, str):
            logger.warning(f"Cashier registration without OTP for user: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, "OTP is required")
            
        if not re.match(r'^\d{6}$', otp):
            logger.warning(f"Cashier registration with invalid OTP format for user: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, "OTP must be a 6-digit number")

        conn = get_connection()
        cur = conn.cursor()
        # Verificar que el usuario no exista
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            logger.warning(f"Cashier registration attempt with existing username: {mask_sensitive_data(username, 'username')}", 400)
            api.abort(400, "Username already exists")
            
        # Insertar cajero
        cur.execute(
            "INSERT INTO bank.users (username, password, role, otp) VALUES (%s, %s, %s, %s)",
            (username, password, 'cajero', otp)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Cajero registrado exitosamente: {mask_sensitive_data(username, 'username')}", 201)
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
        
        try:
            # Decodificar el token JWT
            payload = decode_jwt_token(token)
            if not payload:
                api.abort(401, "Invalid or expired token")
            
            # Establecer información del usuario desde el JWT payload
            g.user = {
                "id": payload['user_id'],
                "username": payload['username'],
                "role": payload['role']
            }
            
            logger.debug(f"JWT Token validated for user: {mask_sensitive_data(g.user['username'], 'username')}", 200)
            
        except Exception as e:
            logger.warning(f"JWT Token validation failed: {str(e)}", 401)
            api.abort(401, "Invalid or expired token")

        return f(*args, **kwargs)
    return decorated

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
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
        
        # Validar número de cuenta
        valid_account, account_error = validate_account_number(account_number)
        if not valid_account:
            logger.warning(f"Deposit attempt with invalid account number by user: {mask_sensitive_data(g.user['username'], 'username')}", 400)
            api.abort(400, account_error)
        
        # Validar monto
        valid_amount, amount_error = validate_amount(amount)
        if not valid_amount:
            logger.warning(f"Deposit attempt with invalid amount by user: {mask_sensitive_data(g.user['username'], 'username')}", 400)
            api.abort(400, amount_error)
        
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
            logger.warning(f"Deposit attempt to non-existent account {account_number} by user: {mask_sensitive_data(g.user['username'], 'username')}", 404)
            api.abort(404, "Account not found")
        new_balance = float(result[0])
        conn.commit()
        cur.close()
        conn.close()
        
        # Log the successful deposit with masked amount
        logger.info(f"Depósito exitoso: {mask_sensitive_data(amount, 'amount')} en cuenta {account_number} por cajero {mask_sensitive_data(g.user['username'], 'username')}. Nuevo saldo: {mask_sensitive_data(new_balance, 'balance')}", 200)
        
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
        
        # Validar monto
        valid_amount, amount_error = validate_amount(amount)
        if not valid_amount:
            logger.warning(f"Withdraw attempt with invalid amount by user: {mask_sensitive_data(g.user['username'], 'username')}", 400)
            api.abort(400, amount_error)
            
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            logger.warning(f"Withdraw attempt from non-existent account by user: {mask_sensitive_data(g.user['username'], 'username')}", 404)
            api.abort(404, "Account not found")
        current_balance = float(row[0])
        if current_balance < amount:
            cur.close()
            conn.close()
            logger.warning(f"Withdraw attempt with insufficient funds by user: {mask_sensitive_data(g.user['username'], 'username')}, requested: {mask_sensitive_data(amount, 'amount')}, available: {mask_sensitive_data(current_balance, 'balance')}", 400)
            api.abort(400, "Insufficient funds")
        cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
        new_balance = float(cur.fetchone()[0])
        conn.commit()
        cur.close()
        conn.close()
        
        # Log the successful withdrawal with masked data
        logger.info(f"Retiro exitoso: {mask_sensitive_data(amount, 'amount')} por cajero {mask_sensitive_data(g.user['username'], 'username')}. Nuevo saldo: {mask_sensitive_data(new_balance, 'balance')}", 200)
        
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
        
        # Validar parámetros de entrada
        valid_target, target_error = validate_username(target_username)
        if not valid_target:
            logger.warning(f"Transfer attempt with invalid target username by user: {mask_sensitive_data(g.user['username'], 'username')}", 400)
            api.abort(400, target_error)
            
        valid_amount, amount_error = validate_amount(amount)
        if not valid_amount:
            logger.warning(f"Transfer attempt with invalid amount by user: {mask_sensitive_data(g.user['username'], 'username')}", 400)
            api.abort(400, amount_error)
            
        if target_username == g.user['username']:
            logger.warning(f"Transfer attempt to same account by user: {mask_sensitive_data(g.user['username'], 'username')}", 400)
            api.abort(400, "Cannot transfer to the same account")
            
        conn = get_connection()
        cur = conn.cursor()
        # Check sender's balance
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            logger.warning(f"Transfer attempt from non-existent sender account by user: {mask_sensitive_data(g.user['username'], 'username')}", 404)
            api.abort(404, "Sender account not found")
        sender_balance = float(row[0])
        if sender_balance < amount:
            cur.close()
            conn.close()
            logger.warning(f"Transfer attempt with insufficient funds by user: {mask_sensitive_data(g.user['username'], 'username')}, requested: {mask_sensitive_data(amount, 'amount')}, available: {mask_sensitive_data(sender_balance, 'balance')}", 400)
            api.abort(400, "Insufficient funds")
        # Find target user
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            cur.close()
            conn.close()
            logger.warning(f"Transfer attempt to non-existent target user: {mask_sensitive_data(target_username, 'username')} by user: {mask_sensitive_data(g.user['username'], 'username')}", 404)
            api.abort(404, "Target user not found")
        target_user_id = target_user[0]
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            
            # Log the successful transfer with masked data
            logger.info(f"Transferencia exitosa: {mask_sensitive_data(amount, 'amount')} de {mask_sensitive_data(g.user['username'], 'username')} a {mask_sensitive_data(target_username, 'username')}. Nuevo saldo: {mask_sensitive_data(new_balance, 'balance')}", 200)
            
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            logger.error(f"Error during transfer by user: {mask_sensitive_data(g.user['username'], 'username')}: {str(e)}", 500)
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

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)


