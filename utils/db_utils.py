from database import get_db_conn

def get_answer(qtype, qname):
    query = """ 
        SELECT type, name, value, ttl FROM dns_records 
        WHERE type = %s and name = %s
    """
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (qtype, qname))
            return cur.fetchone()