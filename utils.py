from flask import Flask, render_template, request, make_response, redirect, url_for
import sqlite3
from crypto import *

app = Flask(__name__)


def delete_all():
    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()

        cursor.execute('DELETE FROM Credentials')
        cursor.execute('DELETE FROM Passwords')

        cursor.execute("INSERT INTO Credentials (ID, Username, Password, IsAdmin) VALUES (?, ?, ?, ?)", (1, "admin", hash_password("adpass"), True))

        cursor.execute("INSERT INTO Credentials (ID, Username, Password, IsAdmin) VALUES (?, ?, ?, ?)", (2, "notadmin", hash_password("adfail"), False))
    return


def remove_user(id):
    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Credentials WHERE ID = ?", (id,))
        cursor.execute("DELETE FROM Passwords WHERE ID = ?", (id,))

def remove_table():
    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()
        cursor.execute("DROP TABLE IF EXISTS PatientInformation")

        connection.commit()
        connection.close()

def create_table():
    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS Passwords (ID INTEGER, SiteName TEXT NOT NULL, url TEXT NOT NULL, Password TEXT NOT NULL, FOREIGN KEY (ID) REFERENCES Credentials(ID))")
        connection.commit()
        connection.close()

def remove_user_passwords(id):
    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Passwords WHERE ID = ?", (id,))

def remove_site_password(id, site_name):
    with sqlite3.connect("db.sqlite3") as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Passwords WHERE ID = ? AND SiteName = ?", (id, site_name))
