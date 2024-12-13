# PROYECTO II 

En este proyecto nuestra problemática radica en que la UPIIZ necesita una aplicación para gestioanr la información de alumnos, profesores y mmaterias.
Esta aplicación permite la creación de crear, leer, actualizar y/o eliminar registro de estudiantes, profesores y materias.

## Objetivo
Crear una API RESTful que permita gestionar la información de una escuela, utilizando FastAPI como framework, MongoDB como base de datos NoSQL y AWS S3 como almacenamiento de archivos.


## Tecnologías usadas
- Python
- Visual Studio Code
- Mongo DB
- FastAPI
- AWS S3


### ¿Cómo funciona?
Módulos utilizados:

```from fastapi import ```
- FastAPI: módulo principal para crear la aplicación web. 
- File, UploadFile: se utilizan para manejar archivos subidos por el usuario a través de la API.
- HTTPException: sirve para generar excepciones que se traducen en códigos de error HTTp específicos.
- Form: permite acceder a datos enviados por el usuario en los formularios.
- Depends: se usa para definir dependencias que se inyectan en las funciones de la API.

```from pathlib import``` 
- Path: proporciona herramientas para trabajar con rutas de archivos de forma sencilla.

```import shutil```: ofrece funciones para mover, renombrar y eliminar archivos.

```from pydantic import```
- BaseModel: se utiliza para definir modelos de datos que validan la información entrante y saliente de la API.

```from motor import```
- motor_asyncio: permite interactuar con bases de datos MongoDB de manera asíncrona.

```import boto3```: proporciona acceso a los servicios de Amazon Web Services (AWS).

```from botocore.exceptions import```
- NoCredentialsError: contiene excepciones específicas de la biblioteca boto3.

```from datetime import```
- datetime, timedelta: módulos para trabajar con fechas, horas y diferencias temporales.

```import uuid```: genera identificadores únicos universales (UUID).

```from typing import```
- Optional, List, Annotated: proporciona tipos para anotaciones estáticas en Python, mejorando la legibilidad del código.

```from fastapi.security import```
- OAuth2AuthorizationCodeBearer, OAuth2PasswordBearer, OAuth2PasswordRequestForm: módulos para implementar seguridad en la API

```from jose import``` 
- jwt: librería para trabajar con tokens JSON Web (JWT).



Configuración de conexión con MongoDB:
  ```python
MONGO_URI = "mongodb://localhost:27017"
cliente = motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = cliente["Escuela"]  
  ```

Configuración de cliente S3:
  ```python
s3 = boto3.client('s3')
BUCKET_NAME = "sistemas-distribuidos-upiiz-departamental2"  
  ```

Colecciones:
  ```python
alumnos_collection = db["Alumnos"]
materias_collection = db["Materias"]
profesores_collection = db["Profesores"]
calificacions_collection = db["Calificaciones"]  
  ```

Objeto para interactura con FastAPI:
  ```python
app = FastAPI()  
  ```

Ruta de almacenamiento de imágenes:
  ```python
IMAGES_DIR = Path("img")
IMAGES_DIR.mkdir(exist_ok=True)  # Crea la carpeta si no existe  
  ```

Tenemos 6 modelos de datos, los cuales son:
- Alumno:  ```id, nombre, apellido, fecha_nacimiento, direccion, foto ```
- Materias:  ```id, nombre, descripcion, profesor_id ```
- Profesor:  ```id, nombre, apellido, fecha_nacimiento, direccion, especialidad, materias_id ```
- calificacion:  ```id, alumno_id, materia_id, calificacion ```
- Token:  ```access_token, token_type ```
- User:  ```username, role ```

Configuración de cliente OAuth2:
  ```python
SECRET_KEY = "my-secret"  # Cambiar por una clave más segura en producción
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  
  ```

Diccionario de usuarios:
  ```python
users = {
    "admin": {"username": "admin", "password": "1234", "role": "admin"},
    "user": {"username": "user", "password": "1234", "role": "user"},
}

@app.get("/")
async def read_root():
    return {
        "message": "¡Bienvenido a la API de Ecuela!",
        "1": "Miguel Alejandro Rodríguez Cruz",
        "2": "Carlos Omar Fernández Casillas",
        "3": "Axel Giovanni Ojeda Hernández",
        "4": "Perla Patricia Gómez",
        "5": "Karla Guadalupe Rocha Quezada",
        "6": "Desire Castañeda García",
    }  
  ```

Para los alumnos, profesores, materias y calificaciones se implementa su CRUD respectivamente.
- Crear  ```@app.post() ```
- Leer  ```@app.get() ```
- Actualizar  ```@app.put() ```
- Eliminar  ```@app.delete() ```

Las materias son asignadas a profesores y estos pueden tener varias materias a la vez.
Los alumnos son inscritos a la materias  pueden estar inscritos en varias materias a la vez.
Las calificaciones están asociadas a un alumno y una materia específica.

En la API solo los usuarios autorizados pueden acceder y/o modificar la información. Para esto tenemos 3 funciones:
- ```create_access_token ```: esta función es para generar un token de acceso.
- ```get_current_user ```: esta función es para obtener el usuario actual basado en el token.
- ```admin_required ```: esta funcion es para verificar el rol de administrador.
A su vez tenemos las rutas para obtener un token (```@app.post("/token", response_model=Token) ```) y obtener el perfil del usuario actual(```@app.post("/token", response_model=Token) ```).

### Video del funcionamiento del sistema

https://www.youtube.com/watch?v=cXj3pgo5yWw


#### Integrantes:
##### - Carlos Omar Fernández Casillas
##### - Miguel Alejandro Rodríguez Cruz
##### - Desireé Castañeda García
##### - Axel Giovanni Ojeda Hernández
##### - Perla Patricia Gómez Correa
##### - Karla Guadalupe Rocha Quezada
