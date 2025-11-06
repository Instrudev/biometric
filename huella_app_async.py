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

import base64
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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
    'database': 'sicefa',
}

def crear_esquema_y_tabla() -> None:
    """Crea la base de datos y la tabla si no existen."""
    if mysql is None:
        messagebox.showerror('Dependencia faltante', "Instala 'mysql-connector-python'.")
        return
    try:
        conn = mysql.connector.connect(host=DB_CONFIG['host'], user=DB_CONFIG['user'], password=DB_CONFIG['password'])
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS sicefa CHARACTER SET utf8mb4")
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS people (
                id INT AUTO_INCREMENT PRIMARY KEY,
                first_name VARCHAR(255) NOT NULL,
                first_last_name VARCHAR(255) NOT NULL,
                biometric_code LONGTEXT
            )
        """)
        try:
            cursor.execute("ALTER TABLE people MODIFY COLUMN biometric_code LONGTEXT")
        except mysql.connector.Error:
            pass
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

def obtener_personas(filtro: str | None = None) -> list[tuple[int, str, str, str | None]]:
    """Recupera las personas registradas en la tabla people."""
    try:
        conn = abrir_conexion()
        cursor = conn.cursor()
        if filtro:
            patron = f"%{filtro}%"
            cursor.execute(
                """
                SELECT id, first_name, first_last_name, biometric_code
                FROM people
                WHERE first_name LIKE %s
                   OR first_last_name LIKE %s
                   OR COALESCE(biometric_code, '') LIKE %s
                """,
                (patron, patron, patron),
            )
        else:
            cursor.execute("SELECT id, first_name, first_last_name, biometric_code FROM people")
        rows = cursor.fetchall()
        cursor.close(); conn.close()
        return rows
    except mysql.connector.Error as e:  # type: ignore[attr-defined]
        messagebox.showerror('Error DB', f'No se pudo consultar la tabla people: {e}')
    return []

def actualizar_codigo_persona(person_id: int, codigo: str) -> None:
    """Actualiza el biometric_code de una persona."""
    try:
        conn = abrir_conexion()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE people SET biometric_code = %s WHERE id = %s",
            (codigo, person_id),
        )
        conn.commit(); cursor.close(); conn.close()
        messagebox.showinfo('Actualización', 'Código biométrico actualizado correctamente.')
    except mysql.connector.Error as e:  # type: ignore[attr-defined]
        messagebox.showerror('Error DB', f'No se pudo actualizar: {e}')

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

def codificar_huella(datos: bytes) -> str:
    """Convierte los bytes de la huella en un string base64."""
    if not datos:
        return ''
    return base64.b64encode(datos).decode('ascii')

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
        master.geometry('560x520')
        master.resizable(False, False)
        self.pack(fill='both', expand=True)

        self.nombre_var = tk.StringVar()
        self.datos_huella = b''
        self.codigo_var = tk.StringVar()
        self.busqueda_var = tk.StringVar()

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

        ttk.Separator(self, orient='horizontal').place(x=20, y=210, width=520)

        tk.Label(self, text='Buscar:').place(x=20, y=240)
        tk.Entry(self, textvariable=self.busqueda_var, width=30).place(x=80, y=240)
        tk.Button(self, text='Aplicar búsqueda', command=self.on_buscar).place(x=320, y=235, width=140, height=30)
        tk.Button(self, text='Limpiar', command=self.on_limpiar_busqueda).place(x=470, y=235, width=70, height=30)

        tk.Label(self, text='Código biométrico:').place(x=20, y=270)
        self.codigo_entry = tk.Entry(self, textvariable=self.codigo_var, width=60, state='readonly')
        self.codigo_entry.place(x=160, y=270)
        tk.Button(self, text='Actualizar código', command=self.on_actualizar_codigo,
                  bg='#FF9800', fg='white').place(x=360, y=265, width=160, height=30)

        tabla_frame = ttk.LabelFrame(self, text='Personas (tabla people)')
        tabla_frame.place(x=20, y=310, width=520, height=160)

        columns = ('first_name', 'first_last_name', 'biometric_code')
        self.tabla = ttk.Treeview(tabla_frame, columns=columns, show='headings', height=6)
        for col, title in zip(columns, ('Nombre', 'Apellido', 'Código biométrico')):
            self.tabla.heading(col, text=title)
            self.tabla.column(col, width=150 if col != 'biometric_code' else 180, anchor='center')
        self.tabla.pack(side='left', fill='both', expand=True, padx=(0, 0), pady=5)

        scrollbar = ttk.Scrollbar(tabla_frame, orient='vertical', command=self.tabla.yview)
        scrollbar.pack(side='right', fill='y')
        self.tabla.configure(yscrollcommand=scrollbar.set)

        self.tabla.bind('<<TreeviewSelect>>', self.on_seleccionar_persona)

        tk.Button(self, text='Salir', command=master.quit).place(x=20,y=480,width=520,height=35)

        crear_esquema_y_tabla()
        self.cargar_personas()

    def on_capturar_archivo(self):
        datos = capturar_huella_desde_archivo()
        if datos:
            self.datos_huella = datos
            self.estado.config(text='✅ Huella cargada (archivo)', fg='green')
            self._mostrar_codigo(codificar_huella(datos))
        else:
            self.estado.config(text='❌ Huella no capturada', fg='red')
            self._mostrar_codigo('')

    def on_capturar_sensor(self):
        self.estado.config(text='⏳ Capturando huella...', fg='orange')
        self.update_idletasks()
        def terminar(success, data, identidad):
            if success and data:
                self.datos_huella = data
                self._mostrar_codigo(codificar_huella(data))
                if identidad:
                    self.estado.config(text=f'✔ Usuario validado: {identidad}', fg='blue')
                else:
                    self.estado.config(text='✖ Huella no reconocida', fg='red')
                    messagebox.showwarning('Validación','No se encontró coincidencia en la base de datos.')
            else:
                self.datos_huella = b''
                self.estado.config(text='❌ Error al capturar', fg='red')
                mensaje = identidad if isinstance(identidad, str) and identidad else 'No se pudo capturar la huella.'
                messagebox.showerror('Captura', mensaje)
                self._mostrar_codigo('')
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

    def cargar_personas(self, filtro: str | None = None):
        """Carga los registros de la tabla people en el Treeview."""
        for item in self.tabla.get_children():
            self.tabla.delete(item)
        for person_id, first_name, first_last_name, codigo in obtener_personas(filtro):
            self.tabla.insert('', 'end', iid=str(person_id),
                              values=(first_name, first_last_name, codigo or ''))
        for seleccion in self.tabla.selection():
            self.tabla.selection_remove(seleccion)
        self._mostrar_codigo('')
        self.datos_huella = b''

    def on_seleccionar_persona(self, _event=None):
        """Cuando se selecciona una persona, muestra su código actual."""
        seleccion = self.tabla.selection()
        if not seleccion:
            return
        item = self.tabla.item(seleccion[0])
        codigo = item['values'][2] if len(item['values']) > 2 else ''
        self._mostrar_codigo(codigo or '')
        self.datos_huella = b''

    def on_actualizar_codigo(self):
        seleccion = self.tabla.selection()
        if not seleccion:
            messagebox.showwarning('Actualización', 'Selecciona una persona de la tabla.')
            return
        if not self.datos_huella:
            messagebox.showwarning('Actualización', 'Captura una huella antes de actualizar el código.')
            return
        try:
            person_id = int(seleccion[0])
        except ValueError:
            messagebox.showerror('Actualización', 'Identificador inválido.')
            return
        codigo = codificar_huella(self.datos_huella)
        actualizar_codigo_persona(person_id, codigo)
        self.cargar_personas()
        self.estado.config(text='✔ Código biométrico actualizado', fg='blue')
        self.datos_huella = b''
        self._mostrar_codigo(codigo)

    def on_buscar(self):
        filtro = self.busqueda_var.get().strip()
        self.cargar_personas(filtro or None)

    def on_limpiar_busqueda(self):
        self.busqueda_var.set('')
        self.cargar_personas()

    def _mostrar_codigo(self, codigo: str) -> None:
        """Actualiza el campo visible del código respetando el estado readonly."""
        state = self.codigo_entry.cget('state')
        self.codigo_entry.configure(state='normal')
        self.codigo_var.set(codigo)
        self.codigo_entry.configure(state=state)

def main():
    root = tk.Tk()
    AplicacionHuella(root)
    root.mainloop()

if __name__ == '__main__':
    main()
