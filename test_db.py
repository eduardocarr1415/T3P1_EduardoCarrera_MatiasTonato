import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

try:
    connection = pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "oauth_practica"),
    )

    print("Conexion con MySQL correcta.")
    connection.close()

except Exception as error:
    print("No se pudo conectar a MySQL:")
    print(error)
