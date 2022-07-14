from mysql.connector.cursor import CursorBase


def create_new_database(cursor: CursorBase, name: str) -> None:
    cursor.execute("CREATE DATABASE IF NOT EXISTS %s" % name)
    cursor.execute("USE %s" % name)


def create_db_structure_frontier_service(cursor: CursorBase) -> None:
    cursor.execute("CREATE TABLE IF NOT EXISTS Peers (peer_id VARCHAR(36) PRIMARY KEY, ip_address VARCHAR(50), port int, score int)")
    cursor.execute("CREATE TABLE IF NOT EXISTS Frontiers (peer_id VARCHAR(36), frontier_hash VARCHAR(64), " +
                   "account_hash VARCHAR(64), PRIMARY KEY(peer_id, account_hash), " +
                   "FOREIGN KEY (peer_id) REFERENCES Peers(peer_id))")


def query_accounts_different_hashes(cursor: CursorBase):
    cursor.execute("SELECT DISTINCT f1.account_hash FROM frontiers f1 JOIN frontiers f2 " +
                   "WHERE f1.account_hash = f2.account_hash and f1.frontier_hash != f2.frontier_hash")
    return cursor
