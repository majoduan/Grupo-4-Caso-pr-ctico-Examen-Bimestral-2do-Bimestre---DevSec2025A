# Core Bancario API - Proyecto de Examen

## ¿Qué es esto?

API bancaria desarrollada en Flask que implementa requerimientos como: Logging personalizado sin librerías externas. Simula operaciones bancarias con autenticación JWT, validación robusta de datos, enmascaramiento de información sensible y sistema de auditoría completo.

## Características de Seguridad Implementadas

- ✅ **Sistema de logging personalizado** sin librerías externas
- ✅ **Base de datos separada** para logs de auditoría (`corebank_logs`)
- ✅ **JWT con expiración de 5 minutos** (seguridad bancaria)
- ✅ **Validación exhaustiva** de todos los parámetros de entrada
- ✅ **Enmascaramiento automático** de datos sensibles en logs
- ✅ **Autenticación de dos factores** para cajeros (OTP)
- ✅ **Control de roles** (cliente, cajero, administrador)
- ✅ **Zona horaria Ecuador** (UTC-5) sin librerías externas

## Tecnologías

- **Python 3.10** - Lenguaje principal
- **Flask** - Framework web
- **PostgreSQL** - Base de datos
- **Docker** - Contenedor de la aplicación
- **JWT (PyJWT)** - Para autenticación segura
- **Flask-RESTX** - Para documentación automática con Swagger

## La API corre en `http://localhost:10090`

## Usuarios de prueba

3 usuarios predeterminados para probar:

- `user1` / `pass1` (cliente, tiene $1000 en cuenta)
- `user2` / `pass2` (cliente, tiene $1000 en cuenta)
- `user3` / `pass3` (cajero, tiene $1000 en cuenta - **requiere OTP: 111111**)

## Endpoints principales

### Autenticación
- `POST /auth/login` - Hacer login y obtener JWT
- `POST /auth/logout` - Cerrar sesión
- `GET /auth/me` - Ver info del usuario logueado

### Operaciones bancarias (necesitas JWT)
- `POST /bank/deposit` - Depositar dinero
- `POST /bank/withdraw` - Retirar dinero
- `POST /bank/transfer` - Transferir a otro usuario
- `POST /bank/credit-payment` - Comprar con tarjeta de crédito
- `POST /bank/pay-credit-balance` - Pagar deuda de tarjeta

## JWT

El sistema JWT implementado tiene las siguientes características de seguridad:

- **Expiración de 5 minutos**: Tokens de corta duración para mayor seguridad bancaria
- **Información del usuario en el token**: ID, username, rol, email
- **Validación robusta**: Verificación de firma y expiración
- **Stateless**: No requiere consultas a base de datos para validar tokens

### Flujo de autenticación:

1. **Login**: Mandas usuario y contraseña (+ OTP si eres cajero)
2. **Server**: Si está bien, te genera un JWT con tu info (ID, nombre, rol, etc.)
3. **Cliente**: Guardas ese token y lo mandas en cada request
4. **Server**: Verifica que el token sea válido sin consultar la base de datos
5. **Expiración**: Después de 5 minutos debes hacer login nuevamente

## Estructura del proyecto

```text
core-bankec-python/
├── app/
│   ├── __init__.py          # Vacío, solo para que Python reconozca el paquete
│   ├── main.py              # La API principal con todos los endpoints y JWT
│   ├── db.py                # Conexión a PostgreSQL y creación de tablas
│   └── logger.py            # Sistema de logging personalizado sin librerías externas
├── docker-compose.yml       # Configuración de Docker
├── Dockerfile              # Imagen de la app
├── requirements.txt        # Dependencias de Python
└── README.md               # Este archivo
```

## Testing básico JWT

### 1. Login como cliente

```bash
curl -X POST http://localhost:10090/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "password123"}'
```

### 2. Login como cajero (requiere OTP)

```bash
curl -X POST http://localhost:10090/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user3", "password": "password123", "otp": "111111"}'
```

### 3. Operación bancaria (con el token que te dio el login)

```bash
curl -X POST http://localhost:10090/bank/withdraw \
  -H "Authorization: Bearer [TU_TOKEN_AQUI]" \
  -H "Content-Type: application/json" \
  -d '{"amount": 50}'
```

**Nota**: Los tokens JWT expiran en 5 minutos por seguridad bancaria.

Si todo está bien, deberías ver que el balance se actualiza.

## Notas finales

Este proyecto implementa un sistema de logging personalizado sin librerías externas, JWT con expiración de 5 minutos, validación robusta de datos y enmascaramiento de información sensible.

La documentación completa está en `/swagger` cuando corres el proyecto.

---
*Hecho con ☕ y muchas búsquedas en Stack Overflow*
