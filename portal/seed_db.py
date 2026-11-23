#!/usr/bin/env python3
"""Seed the SQLite DB with realistic-looking flight/booking/user data."""
import sqlite3
import bcrypt

DB_PATH = '/opt/sf-portal/flights.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.executescript("""
DROP TABLE IF EXISTS flights;
DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS users;

CREATE TABLE flights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flight_no TEXT NOT NULL,
    origin TEXT NOT NULL,
    destination TEXT NOT NULL,
    departure TEXT NOT NULL,
    price REAL NOT NULL
);

CREATE TABLE bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_ref TEXT UNIQUE NOT NULL,
    flight_no TEXT NOT NULL,
    passenger_name TEXT NOT NULL,
    passport_no TEXT NOT NULL,
    seat TEXT
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
);
""")

flights_data = [
    ('AS101', 'TUN', 'CDG', '2026-08-15 08:30', 245.00),
    ('AS102', 'TUN', 'FRA', '2026-08-15 09:15', 289.00),
    ('AS103', 'TUN', 'LHR', '2026-08-15 10:00', 312.00),
    ('AS201', 'CDG', 'TUN', '2026-08-15 14:00', 245.00),
    ('AS202', 'FRA', 'TUN', '2026-08-15 15:30', 289.00),
    ('AS301', 'TUN', 'DXB', '2026-08-16 22:45', 478.00),
    ('AS401', 'TUN', 'IST', '2026-08-16 12:20', 198.00),
    ('AS501', 'MIR', 'CDG', '2026-08-17 07:00', 265.00),
]
c.executemany("INSERT INTO flights (flight_no, origin, destination, departure, price) VALUES (?, ?, ?, ?, ?)", flights_data)

bookings_data = [
    ('BK-2026-001', 'AS101', 'Amira Ben Salem', 'TN2394857', '14A'),
    ('BK-2026-002', 'AS102', 'Karim Ferjani', 'TN5847293', '22C'),
    ('BK-2026-003', 'AS103', 'Sofia Mansouri', 'TN9384756', '3F'),
    ('BK-2026-004', 'AS201', 'Youssef Trabelsi', 'TN1029384', '17B'),
]
c.executemany("INSERT INTO bookings (booking_ref, flight_no, passenger_name, passport_no, seat) VALUES (?, ?, ?, ?, ?)", bookings_data)

users_data = [
    ('admin', bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode(), 'admin'),
    ('marie.leclerc', bcrypt.hashpw(b'X7p!nQ2vR9wKmL4z', bcrypt.gensalt()).decode(), 'operator'),
    ('ahmed.hamdi', bcrypt.hashpw(b'B3f#gT8jN2eYqW5x', bcrypt.gensalt()).decode(), 'operator'),
    ('lisa.dubois', bcrypt.hashpw(b'M9k@rP4vC7hZbF6t', bcrypt.gensalt()).decode(), 'operator'),
    ('omar.chaabane', bcrypt.hashpw(b'H2n$sL5xQ8wJdG3y', bcrypt.gensalt()).decode(), 'supervisor'),
]
c.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", users_data)

conn.commit()
conn.close()
print("DB seeded: 8 flights, 4 bookings, 5 users")
print("Admin credentials (deliberate weakness): admin / admin123")
