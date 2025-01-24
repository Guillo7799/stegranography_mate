import os
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random

def es_primo_fermat(num, iteraciones=5):
    if num <= 1:
        return False
    if num <= 3:
        return True
    for _ in range(iteraciones):
        a = random.randint(2, num - 2)
        if pow(a, num - 1, num) != 1:
            return False
    return True

def cargar_imagen():
    archivo = filedialog.askopenfilename(title="Seleccionar imagen",
                                         filetypes=[("Archivos de imagen", "*.png;*.jpg;*.jpeg")])
    if archivo:
        try:
            img = Image.open(archivo)
            img.thumbnail((250, 250))
            img = ImageTk.PhotoImage(img)
            etiqueta_imagen.config(image=img)
            etiqueta_imagen.image = img
            app.archivo_imagen = archivo
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la imagen: {e}")


def cifrar_imagen():
    if not hasattr(app, 'archivo_imagen'):
        messagebox.showwarning("Advertencia", "Primero seleccione una imagen")
        return

    clave = entrada_clave.get()
    if len(clave) == 0:
        messagebox.showwarning("Advertencia", "Debe ingresar una clave para cifrar")
        return

    clave_num = sum(ord(char) for char in clave)
    if not es_primo_fermat(clave_num):
        messagebox.showerror("Error", "La clave no es válida según el Teorema de Fermat (no es primo)")
        return

    try:
        with open(app.archivo_imagen, "rb") as file:
            datos_imagen = file.read()

        # Generamos una clave de 32 bytes y un IV de 16 bytes
        clave_bytes = clave.encode('utf-8')
        clave_bytes = clave_bytes.ljust(32, b'\0')[:32]  # Asegurarse de que sea de 32 bytes
        iv = os.urandom(16)

        # Ciframos la imagen
        cipher = Cipher(algorithms.AES(clave_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        datos_cifrados = encryptor.update(datos_imagen) + encryptor.finalize()

        with open("imagen_cifrada.bin", "wb") as file:
            file.write(iv + datos_cifrados)  # Almacenamos IV + datos cifrados
        messagebox.showinfo("Éxito", "Imagen cifrada con éxito.")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo cifrar la imagen: {e}")


def descifrar_imagen():
    clave = entrada_clave.get()
    if len(clave) == 0:
        messagebox.showwarning("Advertencia", "Debe ingresar una clave para descifrar")
        return

    # Convertir la clave en un número para validarla con el Teorema de Fermat
    clave_num = sum(ord(char) for char in clave)  # Sumar los valores ASCII de la clave
    if not es_primo_fermat(clave_num):
        messagebox.showerror("Error", "La clave no es válida según el Teorema de Fermat (no es primo)")
        return

    try:
        # Leemos los datos cifrados
        with open("imagen_cifrada.bin", "rb") as file:
            datos_cifrados = file.read()

        # Obtenemos el IV y los datos cifrados
        iv = datos_cifrados[:16]
        datos_cifrados = datos_cifrados[16:]

        # Generamos una clave de 32 bytes
        clave_bytes = clave.encode('utf-8')
        clave_bytes = clave_bytes.ljust(32, b'\0')[:32]

        # Desciframos la imagen
        cipher = Cipher(algorithms.AES(clave_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        datos_descifrados = decryptor.update(datos_cifrados) + decryptor.finalize()

        with open("imagen_descifrada.png", "wb") as file:
            file.write(datos_descifrados)

        # Mostramos la imagen descifrada
        img = Image.open("imagen_descifrada.png")
        img.thumbnail((250, 250))
        img = ImageTk.PhotoImage(img)
        etiqueta_imagen.config(image=img)
        etiqueta_imagen.image = img

        messagebox.showinfo("Éxito", "Imagen descifrada con éxito.")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo descifrar la imagen: {e}")


app = Tk()
app.title("Cifrado y Descifrado de Imágenes")
app.geometry("400x500")

boton_cargar = Button(app, text="Cargar Imagen", command=cargar_imagen)
boton_cargar.pack(pady=10)

etiqueta_imagen = Label(app)
etiqueta_imagen.pack(pady=10)

etiqueta_clave = Label(app, text="Ingrese clave:")
etiqueta_clave.pack(pady=5)

entrada_clave = Entry(app, show="*", width=32)
entrada_clave.pack(pady=5)

boton_cifrar = Button(app, text="Cifrar Imagen", command=cifrar_imagen)
boton_cifrar.pack(pady=10)

boton_descifrar = Button(app, text="Descifrar Imagen", command=descifrar_imagen)
boton_descifrar.pack(pady=10)

app.mainloop()
