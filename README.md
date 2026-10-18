# Práctica OAuth + bcrypt con Flask y MySQL Workbench

Este proyecto permite iniciar sesión de dos maneras:

1. Correo + contraseña protegida con bcrypt.
2. Google OAuth 2.0 + OpenID Connect.

## Herramientas

- Python 3.10+
- Visual Studio Code
- MySQL Server
- MySQL Workbench
- Google Cloud / Google Auth Platform
- Navegador web

XAMPP no es necesario.

## 1. Crear la base de datos

Abre MySQL Workbench y conéctate a tu servidor local.

Ejecuta el archivo:

database.sql

La conexión esperada para esta práctica es:

- Host: 127.0.0.1
- Port: 3306
- User: root
- Password: la contraseña configurada en tu MySQL Server

## 2. Crear entorno virtual

En PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Luego:

```powershell
pip install -r requirements.txt
```

## 3. Configurar variables

Copia `.env.example` y crea un archivo llamado `.env`.

Para la base de datos ya está preparado así:

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=TU_PASSWORD_MYSQL
DB_NAME=oauth_practica
```

Completa además:

```env
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

## 4. Crear credenciales de Google

Crea un cliente OAuth de tipo:

Web application

URI de redirección autorizada:

```text
http://localhost:5000/auth/google/callback
```

Copia el Client ID y Client Secret a `.env`.

## 5. Ejecutar

```powershell
python app.py
```

Abre:

```text
http://localhost:5000
```

## Flujo bcrypt

Registro:

```text
Contraseña
   ↓
bcrypt.gensalt()
   ↓
bcrypt.hashpw()
   ↓
Hash
   ↓
MySQL
```

Login:

```text
Contraseña introducida
        +
Hash guardado
        ↓
bcrypt.checkpw()
        ↓
True / False
```

## Flujo OAuth/OIDC

```text
Usuario
   ↓
Continuar con Google
   ↓
Google
   ↓
Authorization Code
   ↓
Callback Flask
   ↓
Tokens + identidad OIDC
   ↓
Buscar/crear usuario
   ↓
Sesión Flask
```

## Seguridad

- No subas `.env` a GitHub.
- No guardes contraseñas sin hash.
- No guardes la contraseña de Google.
- Usa HTTPS en producción.
- Desactiva `debug=True` al publicar.
- Para una aplicación real, crea un usuario MySQL específico en lugar de usar root.
