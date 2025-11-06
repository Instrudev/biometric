#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aplicación de registro biométrico con captura asíncrona de huellas
==================================================================

Esta versión añade un módulo de validación de identidad:
  * Tras capturar la huella, la compara con todas las plantillas
    guardadas en MySQL.
  * Usa PyFingerprint para subir características a los búferes 1 y 2
    y compara ambas plantillas.
"""

import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    import mysql.connector  # type: ignore[import]
except ImportError:
    mysql = None

# Parámetros del sensor y la base de datos
PORT = 'COM7'
BAUD = 57600
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'biometric_db',
}

def crear_esquema_y_tabla() -> None:
    """Crea la base de datos y la tabla si no existen."""
    if mysql is None:
        messagebox.showerror('Dependencia faltante', "Instala 'mysql-connector-python'.")
        return
    try:
        conn = mysql.connector.connect(host=DB_CONFIG['host'], user=DB_CONFIG['user'], password=DB_CONFIG['password'])
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS biometric_db CHARACTER SET utf8mb4")
        cursor.close(); conn.close()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS huellas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nombre VARCHAR(255) NOT NULL,
                huella LONGBLOB NOT NULL,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit(); cursor.close(); conn.close()

    except mysql.connector.Error as e:
        messagebox.showerror('Error DB', f'No se pudo crear la base de datos: {e}')

def abrir_conexion():
    """Devuelve una conexión a MySQL."""
    if mysql is None:
        raise ImportError("Instala 'mysql-connector-python'.")
    return mysql.connector.connect(**DB_CONFIG)

def guardar_en_db(nombre: str, datos: bytes) -> None:
    """Guarda un registro en la tabla huellas."""
    try:
        conn = abrir_conexion()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO huellas (nombre, huella) VALUES (%s, %s)", (nombre, datos))
        conn.commit(); cursor.close(); conn.close()
        messagebox.showinfo('Éxito', 'Registro almacenado correctamente.')
    except mysql.connector.Error as e:
        messagebox.showerror('Error DB', f'Error al guardar: {e}')

def capturar_huella_desde_archivo() -> bytes:
    ruta = filedialog.askopenfilename(
        title='Seleccione la imagen o plantilla de huella',
        filetypes=[('Imágenes','*.bmp *.png *.jpg *.jpeg *.wsq'),('Todos','*.*')]
    )
    if ruta:
        try:
            return open(ruta,'rb').read()
        except Exception as ex:
            messagebox.showerror('Error de archivo', f'No se pudo leer el archivo: {ex}')
    return b''

def captura_en_hilo(callback):
    """Captura la huella en un hilo y luego invoca callback."""
    try:
        from pyfingerprint.pyfingerprint import PyFingerprint, FINGERPRINT_CHARBUFFER1, FINGERPRINT_CHARBUFFER2  # type: ignore
    except ImportError:
        callback(False,None,"Instala la biblioteca 'pyfingerprint'.")
        return

    try:
        sensor = PyFingerprint(PORT, BAUD, 0xFFFFFFFF, 0x00000000)
        if not sensor.verifyPassword():
            raise Exception('Contraseña del sensor incorrecta')

        timeout = time.time() + 10
        while not sensor.readImage():
            if time.time() > timeout:
                raise Exception('Tiempo agotado esperando la huella')
            time.sleep(0.1)

        sensor.convertImage(FINGERPRINT_CHARBUFFER1)
        data_list = sensor.downloadCharacteristics(FINGERPRINT_CHARBUFFER1)
        data_bytes = bytes(data_list)

        # Ahora validamos identidad contra BD:
        identidad = validar_identidad(sensor, data_list)
        callback(True, data_bytes, identidad)

    except Exception as e:
        callback(False, None, str(e))

def validar_identidad(sensor, captura_list: list[int]) -> str | None:
    """
    Sube la huella capturada a CHARBUFFER1 (ya lo hizo captura_en_hilo),
    luego recorre la BD subiendo cada plantilla a CHARBUFFER2 y comparando.
    Devuelve el nombre si hay coincidencia (score>=50), o None.
    """
    try:
        conn = abrir_conexion()
        cursor = conn.cursor()
        cursor.execute("SELECT nombre, huella FROM huellas")
        records = cursor.fetchall()
        cursor.close(); conn.close()

        from pyfingerprint.pyfingerprint import FINGERPRINT_CHARBUFFER2  # type: ignore

        for nombre, blob in records:
            plantilla = list(blob)
            sensor.uploadCharacteristics(FINGERPRINT_CHARBUFFER2, plantilla)
            score = sensor.compareCharacteristics()
            # Umbral de similitud (ajustable; a mayor, más restrictivo)
            if score >= 50:
                return nombre
    except Exception:
        pass
    return None

class AplicacionHuella(tk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master)
        self.master = master
        master.title('Registro y Validación Biométrica')
        master.geometry('520x300')
        master.resizable(False, False)
        self.pack(fill='both', expand=True)

        self.nombre_var = tk.StringVar()
        self.datos_huella = b''

        tk.Label(self, text='Nombre o ID (sólo para registro):').place(x=20,y=20)
        tk.Entry(self, textvariable=self.nombre_var, width=40).place(x=200,y=20)

        tk.Button(self, text='Seleccionar huella (archivo)',
                  command=self.on_capturar_archivo).place(x=20,y=60,width=240)
        tk.Button(self, text='Capturar huella (sensor)',
                  command=self.on_capturar_sensor).place(x=280,y=60,width=240)

        self.estado = tk.Label(self, text='⏺ Huella no capturada', fg='gray')
        self.estado.place(x=20,y=110)

        tk.Button(self, text='Guardar en BD', bg='#4CAF50', fg='white',
                  command=self.on_guardar).place(x=20,y=150,width=240,height=35)
        tk.Button(self, text='Validar identidad', bg='#2196F3', fg='white',
                  command=self.on_validar).place(x=280,y=150,width=240,height=35)
        tk.Button(self, text='Salir', command=master.quit).place(x=20,y=205,width=500,height=35)

        crear_esquema_y_tabla()

    def on_capturar_archivo(self):
        datos = capturar_huella_desde_archivo()
        if datos:
            self.datos_huella = datos
            self.estado.config(text='✅ Huella cargada (archivo)', fg='green')
        else:
            self.estado.config(text='❌ Huella no capturada', fg='red')

    def on_capturar_sensor(self):
        self.estado.config(text='⏳ Capturando huella...', fg='orange')
        self.update_idletasks()
        def terminar(success, data, identidad):
            if success and data:
                self.datos_huella = data
                if identidad:
                    self.estado.config(text=f'✔ Usuario validado: {identidad}', fg='blue')
                else:
                    self.estado.config(text='✖ Huella no reconocida', fg='red')
                    messagebox.showwarning('Validación','No se encontró coincidencia en la base de datos.')
            else:
                self.datos_huella = b''
                self.estado.config(text='❌ Error al capturar', fg='red')
                messagebox.showerror('Captura', data if not success else '')
        threading.Thread(target=captura_en_hilo, args=(terminar,), daemon=True).start()

    def on_guardar(self):
        nombre = self.nombre_var.get().strip()
        if not nombre:
            messagebox.showwarning('Datos incompletos','Escribe un nombre o-ID para registrar.')
            return
        if not self.datos_huella:
            messagebox.showwarning('Datos incompletos','Debes capturar una huella primero.')
            return
        guardar_en_db(nombre, self.datos_huella)
        self.nombre_var.set('')
        self.datos_huella = b''
        self.estado.config(text='⏺ Huella no capturada', fg='gray')

    def on_validar(self):
        """Permite validar una huella ya capturada (sin recapturar)."""
        if not self.datos_huella:
            messagebox.showwarning('Sin huella','Captura una huella antes de validar.')
            return
        # Para validar sin volver a leer del sensor, reusamos sensor:
        from pyfingerprint.pyfingerprint import PyFingerprint, FINGERPRINT_CHARBUFFER1
        sensor = PyFingerprint(PORT, BAUD, 0xFFFFFFFF, 0x00000000)
        sensor.uploadCharacteristics(FINGERPRINT_CHARBUFFER1, list(self.datos_huella))
        identidad = validar_identidad(sensor, list(self.datos_huella))
        if identidad:
            self.estado.config(text=f'✔ Usuario validado: {identidad}', fg='blue')
            messagebox.showinfo('Validación','Identidad confirmada: ' + identidad)
        else:
            self.estado.config(text='✖ Huella no reconocida', fg='red')
            messagebox.showwarning('Validación','No se encontró coincidencia en la base de datos.')

def main():
    root = tk.Tk()
    AplicacionHuella(root)
    root.mainloop()

if __name__ == '__main__':
    main()
