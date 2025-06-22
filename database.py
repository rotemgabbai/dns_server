import psycopg2
from psycopg2.extensions import connection
from config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT

def get_db_conn() -> connection:
    """
    Create a connection to the PostgreSQL database

    Output: Return the connection object
    """
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    return conn
