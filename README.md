# Core Bancario API - Proyecto de Examen

## ¿Qué es esto?

Básicamente es una API bancaria hecha en Flask que simula operaciones típicas de un banco. Es el examen práctico del segundo bimestre. 

Permite hacer login, transferir plata, retirar, depositar y manejar tarjetas de crédito. Todo usando JWT para autenticación.

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
- `user3` / `pass3` (cajero, tiene $1000 en cuenta)

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

1. **Login**: Mandas usuario y contraseña
2. **Server**: Si está bien, te genera un JWT con tu info (ID, nombre, rol, etc.)
3. **Cliente**: Guardas ese token y lo mandas en cada request
4. **Server**: Verifica que el token sea válido sin consultar la base de datos

## Estructura del proyecto

```
core-bankec-python/
├── app/
│   ├── __init__.py          # Vacío, solo para que Python reconozca el paquete
│   ├── main.py              # La API principal con todos los endpoints
│   └── db.py                # Conexión a PostgreSQL y creación de tablas
├── docker-compose.yml       # Configuración de Docker
├── Dockerfile              # Imagen de la app
├── requirements.txt        # Dependencias de Python
└── README.md               # Este archivo
```

## Testing básico JWT

1. **Login**:
```bash
curl -X POST http://localhost:10090/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "pass1"}'
```

2. **Retirar dinero** (con el token que te dio el login):
```bash
curl -X POST http://localhost:10090/bank/withdraw \
  -H "Authorization: Bearer [TU_TOKEN_AQUI]" \
  -H "Content-Type: application/json" \
  -d '{"amount": 50}'
```

Si todo está bien, deberías ver que el balance se actualiza.

## Notas finales

Este proyecto está hecho para fines educativos. En un banco real necesitarías muchísima más seguridad, validaciones, auditoría, etc. Pero para entender cómo funciona JWT y APIs REST está bien.

La documentación completa está en `/swagger` cuando corres el proyecto.

---
*Hecho con ☕ y muchas búsquedas en Stack Overflow*
