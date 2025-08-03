# app/logger.py
import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import datetime
from functools import wraps
from flask import request, g
import jwt

# Configuración de la base de datos de logs
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')
LOGS_DB_NAME = 'corebank_logs'

# Configuración JWT
JWT_SECRET_KEY = "B4nk3c_$3cur3_JWT_K3y_2025!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`1234567890abcdefABCDEF"
JWT_ALGORITHM = "HS256"

class CoreBankLogger:
    """Sistema de logging personalizado para CoreBank"""
    
    def __init__(self):
        # UTC-5 para Ecuador
        self.ecuador_offset_seconds = -5 * 3600  # -5 horas en segundos
        self._init_logs_database()
    
    def _init_logs_database(self):
        """Inicializa la base de datos de logs y crea la tabla si no existe"""
        try:
            # Conectar a la base de datos por defecto para crear la nueva DB
            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database="postgres"  # Base de datos por defecto
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            
            # Verificar si existe la base de datos de logs
            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (LOGS_DB_NAME,))
            exists = cursor.fetchone()
            
            if not exists:
                cursor.execute(f"CREATE DATABASE {LOGS_DB_NAME}")
                print(f"Base de datos {LOGS_DB_NAME} creada exitosamente")
            
            cursor.close()
            conn.close()
            
            # Conectar a la nueva base de datos para crear la tabla
            self._create_logs_table()
            
        except Exception as e:
            print(f"Error inicializando base de datos de logs: {e}")
    
    def _create_logs_table(self):
        """Crea la tabla de logs en la base de datos de logs"""
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=LOGS_DB_NAME
            )
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    timestamp_local VARCHAR(30) NOT NULL,
                    log_level VARCHAR(10) NOT NULL,
                    remote_ip VARCHAR(45) NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    action_message TEXT NOT NULL,
                    http_response_code INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Crear índices para mejores consultas
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp_local);
                CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(log_level);
                CREATE INDEX IF NOT EXISTS idx_logs_username ON logs(username);
                CREATE INDEX IF NOT EXISTS idx_logs_response_code ON logs(http_response_code);
            """)
            
            conn.commit()
            cursor.close()
            conn.close()
            print("Tabla de logs creada exitosamente")
            
        except Exception as e:
            print(f"Error creando tabla de logs: {e}")
    
    def _get_logs_connection(self):
        """Obtiene conexión a la base de datos de logs"""
        return psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=LOGS_DB_NAME
        )
    
    def _get_ecuador_timestamp(self):
        """Obtiene la fecha y hora actual en zona horaria de Ecuador (UTC-5)"""
        # Obtener tiempo UTC actual
        utc_now = datetime.datetime.utcnow()
        # Aplicar offset de Ecuador (UTC-5)
        ecuador_time = utc_now + datetime.timedelta(seconds=self.ecuador_offset_seconds)
        # Formato: AAAA-MM-DD HH:MM:SS.ssss (máximo 23 caracteres)
        return ecuador_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-2]  # AAAA-MM-DD HH:MM:SS.ssss
    
    def _get_username_from_request(self):
        """Extrae el nombre de usuario del JWT token en el request"""
        try:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
                return payload.get('username', 'anonymous')
        except:
            pass
        return 'anonymous'
    
    def _get_remote_ip(self):
        """Obtiene la dirección IP remota del cliente"""
        # Intentar obtener IP real detrás de proxy
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or 'unknown'
    
    def log(self, level, action_message, http_response_code):
        """
        Registra un evento en el sistema de logs
        
        Args:
            level (str): Nivel del log (INFO, DEBUG, WARNING, ERROR)
            action_message (str): Descripción de la acción realizada
            http_response_code (int): Código de respuesta HTTP
        """
        try:
            timestamp_local = self._get_ecuador_timestamp()
            remote_ip = self._get_remote_ip()
            username = self._get_username_from_request()
            
            # Registrar en la base de datos
            conn = self._get_logs_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO logs (timestamp_local, log_level, remote_ip, username, action_message, http_response_code)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (timestamp_local, level, remote_ip, username, action_message, http_response_code))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"Error registrando log: {e}")
    
    def info(self, action_message, http_response_code=200):
        """Registra un log de nivel INFO"""
        self.log('INFO', action_message, http_response_code)
    
    def debug(self, action_message, http_response_code=200):
        """Registra un log de nivel DEBUG"""
        self.log('DEBUG', action_message, http_response_code)
    
    def warning(self, action_message, http_response_code=400):
        """Registra un log de nivel WARNING"""
        self.log('WARNING', action_message, http_response_code)
    
    def error(self, action_message, http_response_code=500):
        """Registra un log de nivel ERROR"""
        self.log('ERROR', action_message, http_response_code)

# Instancia global del logger
logger = CoreBankLogger()

def log_request(log_level='INFO'):
    """
    Decorador para logging automático de endpoints
    
    Args:
        log_level (str): Nivel de log por defecto
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Obtener información antes de ejecutar la función
            endpoint = request.endpoint or 'unknown_endpoint'
            method = request.method
            
            try:
                # Ejecutar la función original
                result = f(*args, **kwargs)
                
                # Determinar código de respuesta
                if isinstance(result, tuple):
                    response_data, status_code = result
                    http_code = status_code
                else:
                    response_data = result
                    http_code = 200
                
                # Crear mensaje de acción
                action_message = f"{method} {endpoint} - Operación exitosa"
                
                # Registrar log exitoso
                logger.log(log_level, action_message, http_code)
                
                return result
                
            except Exception as e:
                # Registrar error
                error_message = f"{method} {endpoint} - Error: {str(e)}"
                logger.error(error_message, 500)
                raise  # Re-lanzar la excepción
        
        return decorated_function
    return decorator

def log_auth_attempt(username, success, http_code):
    """
    Función especializada para registrar intentos de autenticación
    
    Args:
        username (str): Nombre de usuario que intenta autenticarse
        success (bool): Si la autenticación fue exitosa
        http_code (int): Código HTTP de respuesta
    """
    try:
        timestamp_local = logger._get_ecuador_timestamp()
        remote_ip = logger._get_remote_ip()
        
        if success:
            level = 'INFO'
            action_message = f"Login exitoso para usuario: {username}"
        else:
            level = 'WARNING'
            action_message = f"Intento de login fallido para usuario: {username}"
        
        # Registrar en base de datos
        conn = logger._get_logs_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO logs (timestamp_local, log_level, remote_ip, username, action_message, http_response_code)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (timestamp_local, level, remote_ip, username or 'anonymous', action_message, http_code))
        
        conn.commit()
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error registrando intento de autenticación: {e}")
