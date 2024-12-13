from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Depends
from pathlib import Path
import shutil
from pydantic import BaseModel
from motor import motor_asyncio
import boto3
from botocore.exceptions import NoCredentialsError
from datetime import datetime, timedelta
import uuid
from typing import Optional, List, Annotated
from fastapi.security import OAuth2AuthorizationCodeBearer, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException
from jose import jwt

# Configurar la conexión con MongoDB
MONGO_URI = "mongodb://localhost:27017"
cliente = motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = cliente["Escuela"]

# Configurar cliente de S3
s3 = boto3.client('s3')
BUCKET_NAME = "sistemas-distribuidos-upiiz-departamental2"  # Cambia esto por tu bucket de S3

# Colecciones
alumnos_collection = db["Alumnos"]
materias_collection = db["Materias"]
profesores_collection = db["Profesores"]
calificacions_collection = db["Calificaciones"]

# Objeto para interactuar con la API
app = FastAPI()

# Ruta de la carpeta donde se almacenarán las imágenes
IMAGES_DIR = Path("img")
IMAGES_DIR.mkdir(exist_ok=True)  # Crea la carpeta si no existe

# Modelos de datos
class Alumno(BaseModel):
    id: int
    nombre: str
    apellido: str
    fecha_nacimiento: datetime
    direccion: str
    foto: str

class Materias(BaseModel):
    id: int
    nombre: str
    descripcion: str
    profesor_id: int

class Profesor(BaseModel):
    id: int
    nombre: str
    apellido: str
    fecha_nacimiento: datetime
    direccion: str
    especialidad: str
    materias_ids: Optional[List[int]] = []

class calificacion(BaseModel):
    id: int
    alumno_id: int
    materia_id: int
    calificacion: float

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    role: str

# Configurar cliente de OAuth2
SECRET_KEY = "my-secret"  # Cambiar por una clave más segura en producción
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Diccionario de usuarios
users = {
    "admin": {"username": "admin", "password": "1234", "role": "admin"},
    "user": {"username": "user", "password": "1234", "role": "user"},
}

@app.get("/")
async def read_root():
    return {
        "message": "¡Bienvenido a la API de Escuela!",
        "1": "Miguel Alejandro Rodríguez Cruz",
        "2": "Carlos Omar Fernández Casillas",
        "3": "Axel Giovanni Ojeda Hernández",
        "4": "Perla Patricia Gómez",
        "5": "Karla Guadalupe Rocha Quezada",
        "6": "Desire Castañeda García",
    }

# ---------------------------------- Usuarios -----------------------------------

# Función para generar un token de acceso
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependencia para obtener el usuario actual basado en el token
def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in users:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        user_data = users[username]
        return User(username=username, role=user_data["role"])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Dependencia para verificar el rol de administrador
def admin_required(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return current_user

# Ruta para obtener un token
@app.post("/token", response_model=Token)
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = users.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Ruta para obtener el perfil del usuario actual
@app.get("/users/profile", response_model=User)
def profile(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

# ---------------------------------- Alumnos -----------------------------------

@app.get("/alumnos/")
async def get_alumnos():
    resultados = {}
    alumnos = await alumnos_collection.find().to_list(None)
    for i, alumno in enumerate(alumnos):
        resultado = {
            "id": alumno["id"],
            "nombre": alumno["nombre"],
            "apellido": alumno["apellido"],
            "fecha_nacimiento": alumno["fecha_nacimiento"].isoformat(),
            "direccion": alumno["direccion"],
            "foto": alumno["foto"],
        }
        if "materias_ids" in alumno and alumno["materias_ids"]:
            resultado["materias_ids"] = alumno["materias_ids"]

        resultados[i] = resultado
    return resultados


@app.get("/alumno/{id}")
async def get_alumno(id: int):
    alumno = await alumnos_collection.find_one({"id": id})
    if not alumno:
        raise HTTPException(status_code=404, detail="El alumno no se encontró")

    respuesta = {
        "id": alumno["id"],
        "nombre": alumno["nombre"],
        "apellido": alumno["apellido"],
        "fecha_nacimiento": alumno["fecha_nacimiento"].isoformat(),
        "direccion": alumno["direccion"],
        "foto": alumno["foto"],
    }
    if "materias_ids" in alumno and alumno["materias_ids"]:
        respuesta["materias_ids"] = alumno["materias_ids"]

    return respuesta


@app.post("/alumno/")
async def create_alumno(
    current_user: Annotated[User, Depends(admin_required)],
    file: UploadFile = File(...),
    nombre: str = Form(...),
    apellido: str = Form(...),
    fecha_nacimiento: datetime = Form(...),
    direccion: str = Form(...),
    materias_ids: Optional[str] = Form(None)
):
    # Convertir la cadena de materias_ids en una lista de enteros
    materias_ids_list = []
    if materias_ids:
        try:
            materias_ids_list = [int(id.strip()) for id in materias_ids.split(",")]
        except ValueError:
            raise HTTPException(
                status_code=422, detail="El campo materias_ids debe contener solo números separados por comas."
            )

        materias_existentes = await materias_collection.find(
            {"id": {"$in": materias_ids_list}}
        ).to_list(None)
        ids_encontrados = {materia["id"] for materia in materias_existentes}
        ids_no_encontrados = set(materias_ids_list) - ids_encontrados
        if ids_no_encontrados:
            raise HTTPException(
                status_code=404,
                detail=f"Los siguientes IDs de materias no existen: {list(ids_no_encontrados)}"
            )

    # Generar nuevo ID y subir imagen
    ultimo_alumno = await alumnos_collection.find_one(sort=[("id", -1)])
    nuevo_id = (ultimo_alumno["id"] + 1) if ultimo_alumno else 1
    imagen_url = upload_image_to_s3(file, BUCKET_NAME, "credenciales")

        # Crear nuevo alumno
    nuevo_alumno = {
        "id": nuevo_id,
        "nombre": nombre,
        "apellido": apellido,
        "fecha_nacimiento": fecha_nacimiento,
        "direccion": direccion,
        "foto": imagen_url,
        "materias_ids": materias_ids_list,
    }

    # Insertar nuevo alumno
    await alumnos_collection.insert_one(nuevo_alumno)

    # Eliminar el campo "_id" (que MongoDB genera automáticamente) antes de devolver la respuesta
    nuevo_alumno.pop("_id", None)  # Eliminar _id generado automáticamente por MongoDB
    return nuevo_alumno


@app.put("/alumno/{id}")
async def update_alumno(
    current_user: Annotated[User, Depends(admin_required)],
    id: int,
    nombre: Optional[str] = Form(None),
    apellido: Optional[str] = Form(None),
    fecha_nacimiento: Optional[datetime] = Form(None),
    direccion: Optional[str] = Form(None),
    foto: Optional[UploadFile] = File(None),
    materias_ids: Optional[str] = Form(None)
):
    update_data = {}
    if nombre:
        update_data["nombre"] = nombre
    if apellido:
        update_data["apellido"] = apellido
    if fecha_nacimiento:
        update_data["fecha_nacimiento"] = fecha_nacimiento
    if direccion:
        update_data["direccion"] = direccion
    if foto:
        imagen_url = upload_image_to_s3(foto, BUCKET_NAME, "credenciales")
        update_data["foto"] = imagen_url

    if materias_ids:
        try:
            materias_ids_list = [int(id.strip()) for id in materias_ids.split(",")]
        except ValueError:
            raise HTTPException(
                status_code=422, detail="El campo materias_ids debe contener solo números separados por comas."
            )

        materias_existentes = await materias_collection.find(
            {"id": {"$in": materias_ids_list}}
        ).to_list(None)
        ids_encontrados = {materia["id"] for materia in materias_existentes}
        ids_no_encontrados = set(materias_ids_list) - ids_encontrados
        if ids_no_encontrados:
            raise HTTPException(
                status_code=404,
                detail=f"Los siguientes IDs de materias no existen: {list(ids_no_encontrados)}"
            )

        update_data["materias_ids"] = materias_ids_list

    if not update_data:
        raise HTTPException(status_code=400, detail="No hay datos para actualizar")

    result = await alumnos_collection.update_one({"id": id}, {"$set": update_data})
    if result.matched_count == 1:
        updated_alumno = await alumnos_collection.find_one({"id": id})
        updated_alumno.pop("_id", None)  # Eliminar _id generado automáticamente por MongoDB
        return updated_alumno

    raise HTTPException(status_code=404, detail="El alumno no se encontró")


@app.delete("/alumno/{id}")
async def delete_alumno(id: int, current_user: Annotated[User, Depends(admin_required)]):
    # Buscar el alumno por su ID 
    alumno = await alumnos_collection.find_one({"id": id})
    
    if not alumno:
        raise HTTPException(status_code=404, detail="El alumno no se encontró")

    # Eliminar el alumno
    result = await alumnos_collection.delete_one({"id": id})
    
    if result.deleted_count == 1:
        return {
            "message": "El alumno se eliminó correctamente"
        }
    
    raise HTTPException(status_code=404, detail="Error al eliminar el alumno")

# Función para subir imagen a S3
def upload_image_to_s3(file: UploadFile, bucket: str, folder: str):
    
    try:
        # Generar un nombre único para la imagen
        image_filename = f"{folder}/{uuid.uuid4()}_{file.filename}"

        # Subir la imagen a S3
        s3.upload_fileobj(file.file, bucket, image_filename)

        # Generar URL pública de la imagen
        image_url = f"https://{bucket}.s3.amazonaws.com/{image_filename}"
        return image_url
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="Credenciales de AWS no encontradas")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al subir imagen: {str(e)}")
    
# ---------------------------------- Materias -----------------------------------

@app.get("/materias/")
async def get_materias():
    resultados = dict()
    #Obtener de manera asíncrona todos los usuarios
    materias = await materias_collection.find().to_list(None)
    #Iterar todos los elementos de la lista users
    for i, materia in enumerate(materias):
        #Diccionario para cada usuario
        resultados[i] = dict()
        resultados[i]["id"]=materia["id"]
        resultados[i]["nombre"]=materia["nombre"]
        resultados[i]["descripcion"]=materia["descripcion"]
        resultados[i]["profesor_id"]=materia["profesor_id"]
    return resultados

@app.post("/materias/",response_model=dict)
async def create_lector(current_user: Annotated[User, Depends(admin_required)],nombre: str, descripcion: str, profesor_id: int):

    profesor = await profesores_collection.find_one({"id": profesor_id})
    if not profesor:
        raise HTTPException(status_code=404, detail="Profesor no encontrado")
    # Buscar el préstamo con el id más alto y sumarle 1
    ultima_materia = await materias_collection.find_one(sort=[("id", -1)])
    if ultima_materia:
        nuevo_id = ultima_materia["id"] + 1
    else:
        nuevo_id = 1  # Si no hay alumnos, se comienza desde 1
    # Crear un nuevo alumno con el id incrementado
    nuevo_materia = dict()
    nuevo_materia["id"] = nuevo_id
    nuevo_materia["nombre"] = nombre
    nuevo_materia["descripcion"] = descripcion
    nuevo_materia["profesor_id"] = profesor_id

    await materias_collection.insert_one(nuevo_materia)

    # Devolver el nuevo préstamo con las fechas en formato ISO 8601
    materia_dict = {
        "id": nuevo_materia["id"],  # Asegúrate de que se devuelve el nuevo id
        "nombre": nuevo_materia["nombre"],
        "descripcion": nuevo_materia["descripcion"],
        "profesor_id": nuevo_materia["profesor_id"]
    }

    return materia_dict


@app.get("/materias/{id}")
async def get_materia(id: int):
    # Aquí se busca el usuario y se retorna un diccionario o un objeto User
    resultado_materia = await materias_collection.find_one({"id": id})
    if resultado_materia is None:
        raise HTTPException(status_code=404, detail="Materia no encontrada")
    

    # El modelo User se usa para la respuesta
    return {
        "id" : str(resultado_materia["id"]),
        "nombre" : resultado_materia["nombre"],
        "descripcion" : resultado_materia["descripcion"],
        "profesor_id": resultado_materia["profesor_id"]
    }

@app.put("/materias/{id}")
async def update_materia(
    current_user: Annotated[User, Depends(admin_required)],
    id: int,
    nombre: Optional[str] = Form(None),
    descripcion: Optional[str] = Form(None),
    profesor_id: Optional[int] = Form(None)
    ):

    # Construir el diccionario con los datos a actualizar
    update_data = {}
    if nombre is not None:
        update_data["nombre"] = nombre
    if descripcion is not None:
        update_data["descripcion"] = descripcion
    if profesor_id is not None:
        profesor = await profesores_collection.find_one({"id": profesor_id})
        if not profesor:
            raise HTTPException(status_code=404, detail="Profesor no encontrado")
        update_data["profesor_id"] = profesor_id

    # Verificar si el diccionario está vacío
    if not update_data:  # Esta línea comprueba si el diccionario está vacío
        raise HTTPException(status_code=400, detail="No hay datos para actualizar")

    # Buscar la materia para verificar si existe
    existing_materia = await materias_collection.find_one({"id": id})
    if existing_materia is None:
        raise HTTPException(status_code=404, detail="Materia no encontrada")
    
    # Realizar la actualización
    update_result = await materias_collection.update_one(
        {"id": id},
        {"$set": update_data}  # Usa $set para actualizar los campos específicos
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=304, detail="No se realizaron cambios en la materia")

    # Obtener la materia actualizada
    updated_materia = await materias_collection.find_one({"id": id})

    return {
        "id": str(updated_materia["id"]),
        "nombre": updated_materia["nombre"],
        "descripcion": updated_materia["descripcion"],
        "profesor_id": updated_materia["profesor_id"]
    }


@app.delete("/materias/{id}")
async def delete_materia(id: int,current_user: Annotated[User, Depends(admin_required)]):
    # Buscar el alumno por su ID 
    alumno = await materias_collection.find_one({"id": id})
    
    if not alumno:
        raise HTTPException(status_code=404, detail="La materia no se encontró")

    # Eliminar el alumno
    result = await materias_collection.delete_one({"id": id})
    
    if result.deleted_count == 1:
        return {
            "message": "La materia se eliminó correctamente"
        }
    
    raise HTTPException(status_code=404, detail="Error al eliminar la materia")

# ---------------------------------- Profesores -----------------------------------


@app.get("/profesores/")
async def get_profesores():
    resultados = {}
    profesores = await profesores_collection.find().to_list(None)
    # Iterar sobre los profesores y construir la respuesta
    for i, profesor in enumerate(profesores):
        # Crear el diccionario base para cada profesor
        resultado = {
            "id": profesor["id"],
            "nombre": profesor["nombre"],
            "apellido": profesor["apellido"],
            "fecha_nacimiento": profesor["fecha_nacimiento"].isoformat(),
            "direccion": profesor["direccion"],
            "especialidad": profesor["especialidad"],
        }

        # Incluir materias_ids si están presentes
        if "materias_ids" in profesor and profesor["materias_ids"]:
            resultado["materias_ids"] = profesor["materias_ids"]

        # Agregar el resultado al diccionario final
        resultados[i] = resultado

    return resultados

@app.post("/profesores/")
async def create_profesor(
    current_user: Annotated[User, Depends(admin_required)],
    nombre: str = Form(...),
    apellido: str = Form(...),
    fecha_nacimiento: datetime = Form(...),
    direccion: str = Form(...),
    especialidad: str = Form(...),
    materias_ids: Optional[str] = Form(None)  # Aceptar como cadena
):
    # Convertir la cadena de materias_ids en una lista de enteros
    materias_ids_list = []
    if materias_ids:
        try:
            materias_ids_list = [int(id.strip()) for id in materias_ids.split(",")]
        except ValueError:
            raise HTTPException(
                status_code=422, detail="El campo materias_ids debe contener solo números separados por comas."
            )

    # Verificar que los IDs de las materias existan en la base de datos
    if materias_ids_list:
        materias_existentes = await materias_collection.find(
            {"id": {"$in": materias_ids_list}}
        ).to_list(None)
        ids_encontrados = {materia["id"] for materia in materias_existentes}

        # Identificar IDs que no existen
        ids_no_encontrados = set(materias_ids_list) - ids_encontrados
        if ids_no_encontrados:
            raise HTTPException(
                status_code=404,
                detail=f"Los siguientes IDs de materias no existen: {list(ids_no_encontrados)}"
            )

    # Generar un nuevo ID para el profesor
    ultimo_profesor = await profesores_collection.find_one(sort=[("id", -1)])
    nuevo_id = (ultimo_profesor["id"] + 1) if ultimo_profesor else 1

    # Crear el nuevo profesor
    nuevo_profesor = {
        "id": nuevo_id,
        "nombre": nombre,
        "apellido": apellido,
        "fecha_nacimiento": fecha_nacimiento,
        "direccion": direccion,
        "especialidad": especialidad,
        "materias_ids": materias_ids_list  # Guardar los IDs de materias
    }

    await profesores_collection.insert_one(nuevo_profesor)

    return {
        "id": nuevo_profesor["id"],
        "nombre": nuevo_profesor["nombre"],
        "apellido": nuevo_profesor["apellido"],
        "fecha_nacimiento": nuevo_profesor["fecha_nacimiento"].isoformat(),
        "direccion": nuevo_profesor["direccion"],
        "especialidad": nuevo_profesor["especialidad"],
        "materias_ids": nuevo_profesor["materias_ids"]
    }


@app.get("/profesores/{id}")
async def get_profesor(id: int):
    profesor = await profesores_collection.find_one({"id": id})
    if not profesor:
        raise HTTPException(status_code=404, detail="Profesor no encontrado")

    respuesta = {
        "id": profesor["id"],
        "nombre": profesor["nombre"],
        "apellido": profesor["apellido"],
        "fecha_nacimiento": profesor["fecha_nacimiento"].isoformat(),
        "direccion": profesor["direccion"],
        "especialidad": profesor["especialidad"],
    }

    # Incluir materias_ids si existen en el documento
    if "materias_ids" in profesor and profesor["materias_ids"]:
        respuesta["materias_ids"] = profesor["materias_ids"]

    return respuesta

@app.put("/profesores/{id}")
async def update_profesor(
    current_user: Annotated[User, Depends(admin_required)],
    id: int,
    nombre: Optional[str] = Form(None),
    apellido: Optional[str] = Form(None),
    fecha_nacimiento: Optional[datetime] = Form(None),
    direccion: Optional[str] = Form(None),
    especialidad: Optional[str] = Form(None),
    materias_ids: Optional[str] = Form(None)
):
    update_data = {}

    # Actualizar los campos básicos si se proporcionan
    if nombre:
        update_data["nombre"] = nombre
    if apellido:
        update_data["apellido"] = apellido
    if fecha_nacimiento:
        update_data["fecha_nacimiento"] = fecha_nacimiento
    if direccion:
        update_data["direccion"] = direccion
    if especialidad:
        update_data["especialidad"] = especialidad

    # Manejar materias_ids
    if materias_ids:
        try:
            materias_ids_list = [int(id.strip()) for id in materias_ids.split(",")]
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail="El campo materias_ids debe contener solo números separados por comas."
            )

        # Verificar existencia de materias en la base de datos
        materias_existentes = await materias_collection.find(
            {"id": {"$in": materias_ids_list}}
        ).to_list(None)
        ids_encontrados = {materia["id"] for materia in materias_existentes}

        # Identificar IDs no encontrados
        ids_no_encontrados = set(materias_ids_list) - ids_encontrados
        if ids_no_encontrados:
            raise HTTPException(
                status_code=404,
                detail=f"Los siguientes IDs de materias no existen: {list(ids_no_encontrados)}"
            )

        # Agregar los IDs de materias al update_data
        update_data["materias_ids"] = materias_ids_list

    # Verificar que haya datos para actualizar
    if not update_data:
        raise HTTPException(status_code=400, detail="No hay datos para actualizar")

    # Verificar si el profesor existe
    existing_profesor = await profesores_collection.find_one({"id": id})
    if not existing_profesor:
        raise HTTPException(status_code=404, detail="Profesor no encontrado")

    # Actualizar los datos en la base de datos
    update_result = await profesores_collection.update_one(
        {"id": id},
        {"$set": update_data}
    )

    # Verificar si se realizó alguna modificación
    if update_result.modified_count == 0:
        raise HTTPException(status_code=304, detail="No se realizaron cambios en el profesor")

    # Recuperar el documento actualizado
    updated_profesor = await profesores_collection.find_one({"id": id})
    return {
        "id": updated_profesor["id"],
        "nombre": updated_profesor["nombre"],
        "apellido": updated_profesor["apellido"],
        "fecha_nacimiento": updated_profesor["fecha_nacimiento"].isoformat(),
        "direccion": updated_profesor["direccion"],
        "especialidad": updated_profesor["especialidad"],
        "materias_ids": updated_profesor.get("materias_ids", [])
    }

@app.delete("/profesores/{id}")
async def delete_profesor(id: int,current_user: Annotated[User, Depends(admin_required)]):
    profesor = await profesores_collection.find_one({"id": id})
    if not profesor:
        raise HTTPException(status_code=404, detail="Profesor no encontrado")

    result = await profesores_collection.delete_one({"id": id})
    if result.deleted_count == 1:
        return {"message": "El profesor se eliminó correctamente"}

    raise HTTPException(status_code=404, detail="Error al eliminar el profesor")

# ---------------------------------- Calificaciones -----------------------------------

@app.post("/calificacions/", response_model=dict)
async def add_calificacion(current_user: Annotated[User, Depends(admin_required)],calificacion: float, alumno_id: int, materia_id: int):
    # Buscar el préstamo con el id más alto y sumarle 1
    ultima_calificacion = await calificacions_collection.find_one(sort=[("id", -1)])
    nuevo_id = ultima_calificacion["id"] + 1 if ultima_calificacion else 1

    # Verificar existencia de estudiante y materia
    alumno = await alumnos_collection.find_one({"id": alumno_id})
    if not alumno:
        raise HTTPException(status_code=404, detail="Alumno no encontrado")
    
    materia = await materias_collection.find_one({"id": materia_id})
    if not materia:
        raise HTTPException(status_code=404, detail="Materia no encontrada")

    # Crear un nuevo alumno con el id incrementado
    nueva_calificacion = dict()
    nueva_calificacion["id"] = nuevo_id
    nueva_calificacion["alumno_id"] = alumno_id
    nueva_calificacion["materia_id"] = materia_id
    nueva_calificacion["calificacion"] = calificacion

    await calificacions_collection.insert_one(nueva_calificacion)

    # Crear nueva calificación
    new_calificacion = {
        "id": nuevo_id,
        "alumno_id": alumno_id,
        "materia_id": materia_id,
        "calificacion": calificacion
    }

    return new_calificacion

@app.get("/calificacions/", response_model=List[dict])
async def get_calificacions():
    calificaciones = await calificacions_collection.find().to_list(100)
    return [{"id": calificacion["id"],
             "alumno_id": calificacion["alumno_id"],
             "materia_id": calificacion["materia_id"],
             "calificacion": calificacion["calificacion"]} for calificacion in calificaciones]

@app.get("/calificacions/{calificacion_id}", response_model=dict)
async def get_calificacion(calificacion_id: int):
    calificacion = await calificacions_collection.find_one({"id": calificacion_id})
    if not calificacion:
        raise HTTPException(status_code=404, detail="Calificación no encontrada")
    return {
        "id": calificacion["id"],
        "alumno_id": calificacion["alumno_id"],
        "materia_id": calificacion["materia_id"],
        "calificacion": calificacion["calificacion"]
    }

@app.put("/calificacions/{calificacion_id}", response_model=dict)
async def update_calificacion(
    current_user: Annotated[User, Depends(admin_required)],
    calificacion_id: int,
    calificacion: Optional[float] = Form(None),
    alumno_id: Optional[int] = Form(None),
    materia_id: Optional[int] = Form(None)
):
    # Verificar si la calificación existe
    calificacion_existente = await calificacions_collection.find_one({"id": calificacion_id})
    if not calificacion_existente:
        raise HTTPException(status_code=404, detail="Calificación no encontrada")

    # Construir el documento para actualizar solo los campos proporcionados
    actualizacion = {}
    if calificacion is not None:
        actualizacion["calificacion"] = calificacion
    if alumno_id is not None:
        # Verificar existencia del alumno
        alumno = await alumnos_collection.find_one({"id": alumno_id})
        if not alumno:
            raise HTTPException(status_code=404, detail="Alumno no encontrado")
        actualizacion["alumno_id"] = alumno_id
    if materia_id is not None:
        # Verificar existencia de la materia
        materia = await materias_collection.find_one({"id": materia_id})
        if not materia:
            raise HTTPException(status_code=404, detail="Materia no encontrada")
        actualizacion["materia_id"] = materia_id

    # Si no se proporcionaron campos para actualizar, lanzar un error
    if not actualizacion:
        raise HTTPException(status_code=400, detail="No se proporcionaron campos para actualizar")

    # Actualizar la calificación
    await calificacions_collection.update_one({"id": calificacion_id}, {"$set": actualizacion})

    # Devolver los datos actualizados
    calificacion_actualizada = await calificacions_collection.find_one({"id": calificacion_id})
    return {
        "id": calificacion_actualizada["id"],
        "alumno_id": calificacion_actualizada["alumno_id"],
        "materia_id": calificacion_actualizada["materia_id"],
        "calificacion": calificacion_actualizada["calificacion"]
    }

@app.delete("/calificacions/{calificacion_id}", response_model=dict)
async def delete_calificacion(current_user: Annotated[User, Depends(admin_required)],calificacion_id: int):
    calificacion = await calificacions_collection.find_one({"id": calificacion_id})
    if not calificacion:
        raise HTTPException(status_code=404, detail="Calificación no encontrada")

    await calificacions_collection.delete_one({"id": calificacion_id})
    return {"message": f"Calificación con id {calificacion_id} eliminada exitosamente"}