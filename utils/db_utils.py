from typing import Optional, Tuple
from database import get_db_conn

def get_answer(qtype: str, qname: str) -> Optional[Tuple[str, str, str, int]]:
    """
    Select the relevant record that fits the query

    Args: qtype: Record type 'A' or 'PTR'
          qname: Record name
    Output: Return the database record that fits the query
    """
    query = """ 
        SELECT type, name, value, ttl FROM dns_records 
        WHERE type = %s and name = %s
    """
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (qtype, qname))
            return cur.fetchone()