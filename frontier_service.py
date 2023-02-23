#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import sys
import time
import lmdb
import threading
import frontier_request
import peercrawler
import mysql.connector
from abc import ABC, abstractmethod
from typing import Set

from _logger import get_logger, get_logging_level_from_int, VERBOSE, setup_logger
from args import add_network_switcher_args
from sql_utils import *
from pynanocoin import *
from peer import Peer


logger = get_logger()


class frontier_service:
    def __init__(self, ctx, interface, verbosity = 0):
        assert isinstance(interface, frontier_database)
        self.ctx = ctx
        self.database_interface: frontier_database = interface
        self.verbosity = verbosity
        self.peers: Set[Peer] = set()
        self.blacklist = blacklist_manager(Peer, 1800)
        self.ready = False

    def start_service(self, addr='::', port=7080) -> None:
        def incoming_connection_handler(sock: socket.socket):
            try:

                self.comm_thread(sock)
            finally:
                semaphore.release()

        # start the frontier request thread
        threading.Thread(target=self.run, daemon=True).start()

        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, port))

            s.listen()

            semaphore = threading.BoundedSemaphore(8)
            while True:
                semaphore.acquire()
                conn, addr = s.accept()
                
                conn.settimeout(60)
                threading.Thread(target=incoming_connection_handler, args=(conn,), daemon=True).start()

    def comm_thread(self, s) -> None:
        with s:
            s.settimeout(10)

            data = s.recv(33)
            c_packet = client_packet.parse(data)

            if c_packet.is_all_zero():
                frontiers = self.database_interface.get_all()
                s_packet = server_packet(frontiers)
                s.sendall(s_packet.serialise())
                return

            else:
                frontier = self.database_interface.get_frontier(c_packet.account)
                s_packet = server_packet([frontier])
                s.sendall(s_packet.serialise())

    def fetch_peers(self) -> None:
        peers = peercrawler.get_peers_from_service(self.ctx)
        peers = list(filter(lambda p: p.score >= 1000 and p.ip.is_ipv4(), peers))
        assert peers
        self.merge_peers(peers)

    def run(self) -> None:
        while True:
            self.fetch_peers()
            self.single_pass()
            if not self.ready:
                self.ready = True

    def single_pass(self) -> None:
        for p in self.peers:
            try:
                logger.debug(f"Fetching frontiers from peer {p}")
                self.manage_peer_frontiers(p)
            except (ConnectionRefusedError, socket.timeout, PyNanoCoinException, FrontierServiceSlowPeer) as exception:
                p.deduct_score(200)
                logger.info(f"Error while connecting to peer {p}", exc_info=exception)

    def manage_peer_frontiers(self, p) -> None:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(15)

            s.connect((str(p.ip), p.port))

            # maxacc argument can be removed in final version
            hdr = frontier_request.frontier_request.generate_header(self.ctx)
            req = frontier_request.frontier_request(hdr)
            s.sendall(req.serialise())

            front_iter = frontier_read_iter(s)
            self.add_fronts_from_iter(front_iter, p)

    def add_fronts_from_iter(self, front_iter, peer) -> None:
        while True:
            try:
                front = next(front_iter)
                self.database_interface.add_frontier(front, peer)
            except StopIteration:
                return

    # Function which will query all accounts with different frontier hashes
    # def find_accounts_different_hashes(self):
    #     fetched_records = []
    #
    #     query_accounts_different_hashes(self.cursor)
    #
    #     for record in self.cursor.fetchall():
    #         fetched_records.append(record[0])
    #
    #     return fetched_records
    #
    # def get_all_records(self):
    #     records = []
    #
    #     self.cursor.execute("SELECT * FROM frontiers")
    #     for rec in self.cursor.fetchall():
    #         records.append(frontiers_record.from_tuple(rec))
    #
    #     return records

    def count_frontiers(self) -> int:
        return self.database_interface.count_frontiers()

    def merge_peers(self, peers) -> None:
        for p in peers:
            if not self.blacklist.is_blacklisted(p) and p not in self.peers:
                self.peers.add(p)


class client_packet:
    def __init__(self, account):
        self.account = account
        self.magic = ord('K')

    @classmethod
    def parse(cls, data):
        assert len(data) == 33
        assert data[0] == ord('K')
        account = data[1:]
        return client_packet(account)

    def is_all_zero(self) -> bool:
        return self.account == b'\x00' * 32

    def serialise(self) -> bytes:
        data = b''
        data += ord('K').to_bytes(1, 'big')
        data += self.account
        return data


class server_packet_header:
    def __init__(self, no_of_frontiers):
        self.no_of_frontiers = no_of_frontiers

    def serialise(self) -> bytes:
        data = b''
        data += ord('K').to_bytes(1, 'big')
        data += self.no_of_frontiers.to_bytes(8, 'big')
        return data

    @classmethod
    def parse(cls, data):
        assert data[0] == ord('K')
        no_of_frontiers = int.from_bytes(data[1:9], 'big')
        return server_packet_header(no_of_frontiers)

    def __str__(self):
        return str(self.no_of_frontiers)


class server_packet:
    def __init__(self, frontiers):
        # TODO: make this a header followed by frontier_response (nano protocol)
        assert isinstance(frontiers, list)
        self.frontiers = frontiers
        self.header = server_packet_header(len(frontiers))

    def serialise(self) -> bytes:
        data = b''
        data += self.header.serialise()
        for f in self.frontiers:
            data += f.serialise()
        data += b'\x00' * 64
        return data

    @classmethod
    def parse(cls, hdr, data):
        assert len(data) == 64 * hdr.no_of_frontiers + 64
        frontiers = []
        start_index = 0
        end_index = 64

        for i in range(0, hdr.no_of_frontiers):
            front = frontier_request.frontier_entry(data[start_index:end_index - 32], data[end_index - 32:end_index])
            frontiers.append(front)
            start_index += 64
            end_index += 64

        return server_packet(frontiers)

    def __str__(self):
        string = 'No of frontiers: %s\n' % str(self.header)
        for f in self.frontiers:
            string += str(f) + '\n\n'
        return string


class frontier_database(ABC):
    @abstractmethod
    def add_frontier(self, frontier, peer) -> None:
        raise NotImplementedError()

    @abstractmethod
    def remove_frontier(self, frontier, peer) -> None:
        raise NotImplementedError()

    @abstractmethod
    def get_frontier(self, account) -> tuple[str, str]:
        raise NotImplementedError()

    @abstractmethod
    def get_all(self) -> list:
        raise NotImplementedError()

    @abstractmethod
    def count_frontiers(self) -> int:
        raise NotImplementedError()


class my_sql_db(frontier_database):
    BATCH_SIZE = 1024

    def __init__(self, cursor, db):
        self.cursor = cursor
        self.db = db
        self.peers_stored = []

        self.__cache = []
        self.__cache_lock = threading.Lock()

    def add_frontier(self, frontier, peer) -> None:
        if peer not in self.peers_stored:
            self.add_peer_to_db(peer)
            self.peers_stored.append(peer)

        query = "('%s', '%s', '%s')" % (hexlify(peer.serialise()), hexlify(frontier.account), hexlify(frontier.frontier_hash))
        with self.__cache_lock:
            self.__cache.append(query)

            if len(self.__cache) > self.BATCH_SIZE:
                self.__add_batch()

    def __add_batch(self):
        query = f"INSERT INTO Frontiers(peer_id, account_hash, frontier_hash) VALUES {', '.join(self.__cache)} ON DUPLICATE KEY UPDATE frontier_hash = VALUES(frontier_hash)"
        self.__cache.clear()

        self.cursor.execute(query)
        self.db.commit()

    def get_frontier(self, account) -> tuple[str, str]:
        query = 'SELECT (account_hash, frontier_hash) FROM Frontiers WHERE account_hash = "%s"' % hexlify(account)
        self.cursor.execute(query)
        return self.cursor.fetchone()

    def remove_frontier(self, frontier, peer) -> None:
        self.remove_peer_data(peer)

        self.cursor.execute("DELETE FROM Frontiers WHERE account  = '%s'")

    def count_frontiers(self) -> int:
        query = "SELECT COUNT(*) from Frontiers;"
        self.cursor.execute(query)
        return self.cursor.fetchone()[0]

    def remove_peer_data(self, p) -> None:
        self.cursor.execute("DELETE FROM Frontiers WHERE peer_id = '%s'" % hexlify(p.serialise()))
        self.cursor.execute("DELETE FROM Peers WHERE peer_id = '%s'" % hexlify(p.serialise()))
        self.db.commit()

    def add_peer_to_db(self, peer) -> None:
        query = "INSERT INTO Peers(peer_id, ip_address, port, score) "
        query += "VALUES('%s', '%s', %d, %d) " % (hexlify(peer.serialise()), str(peer.ip), peer.port, peer.score)
        query += "ON DUPLICATE KEY UPDATE port = port"

        logger.info(f"Adding new peer to database: {peer}")

        self.cursor.execute(query)
        self.db.commit()

    def get_all(self) -> list:
        raise NotImplementedError()


class store_in_ram_interface(frontier_database):
    def __init__(self):
        self.__frontiers = []

    def add_frontier(self, frontier, peer) -> None:
        existing_front = self.get_frontier(frontier.account)
        if existing_front is not None:
            existing_front.frontier_hash = frontier.frontier_hash
            logger.info("Updated %s accounts frontier to %s" % (hexlify(frontier.account), hexlify(frontier.frontier_hash)))
        else:
            self.__frontiers.append(frontier)
            logger.info("Added %s accounts frontier %s " % (hexlify(frontier.account), hexlify(frontier.frontier_hash)))

    def remove_frontier(self, frontier, peer) -> None:
        existing_front = self.get_frontier(frontier.account)
        if existing_front is not None:
            self.__frontiers.remove(existing_front)
            logger.info("Removed the following frontier from list %s" % str(existing_front))

    def get_frontier(self, account):
        for f in self.__frontiers:
            if f.account == account:
                return f
        return None

    def count_frontiers(self) -> int:
        return len(self.__frontiers)

    def get_all(self):
        return copy.copy(self.__frontiers)

    def __str__(self):
        string = "--- Frontiers in RAM ---\n"
        for f in self.__frontiers:
            string += "acc: %s   front: %s\n" % (hexlify(f.account), hexlify(f.frontier_hash))
        return string


class store_in_lmdb(frontier_database):
    def __init__(self, file_name: str = "frontiers_db"):
        self.lmdb_env = self.get_lmdb_env(file_name)

    def add_frontier(self, frontier, peer):
        with self.lmdb_env.begin(write=True) as tx:
            tx.put(frontier.account, frontier.frontier_hash)
            logger.info("Added values %s, %s to lmdb" % (hexlify(frontier.account), hexlify(frontier.frontier_hash)))

    @staticmethod
    def get_lmdb_env(name):
        os.makedirs('frontier_lmdb_databases', exist_ok=True)
        return lmdb.open('frontier_lmdb_databases/' + name, subdir=False, max_dbs=10000, map_size=(10 * 1000 * 1000 * 1000))

    def get_frontier(self, account):
        with self.lmdb_env.begin(write=False) as tx:
            front_hash = tx.get(account)
            return frontier_request.frontier_entry(account, front_hash)

    def get_all(self):
        with self.lmdb_env.begin(write=False) as tx:
            frontiers = []
            for key, value in tx.cursor():
                front = frontier_request.frontier_entry(key, value)
                frontiers.append(front)
        return frontiers

    def remove_frontier(self, frontier, peer) -> None:
        raise NotImplementedError()

    def count_frontiers(self) -> int:
        raise NotImplementedError()


class blacklist_entry:
    def __init__(self, item, time_added):
        self.item = item
        self.time = time_added

    def has_expired(self, expiry_time):
        if time.time() - self.time > expiry_time:
            return True
        return False


class blacklist_manager:
    def __init__(self, object_type, expiry_time = None):
        self.blacklist = []
        self.object_type = object_type
        self.expiry_time = expiry_time

    def add_item(self, item):
        if not isinstance(item, self.object_type):
            raise BlacklistItemTypeError("This black list holds items of item type : %s, type %s given" %
                                         (str(self.object_type), str(type(item))))
        elif self.get_entry(item) is None:
            self.blacklist.append(blacklist_entry(item, time.time()))

    def is_blacklisted(self, item):
        entry = self.get_entry(item)
        if entry is None:
            return False
        elif self.expiry_time is not None:
            if entry.has_expired(self.expiry_time):
                self.remove_entry(entry)
                return False
            else:
                return True
        else:
            return True

    def remove_entry(self, entry):
        self.blacklist.remove(entry)

    def remove_item(self, item):
        entry = self.get_entry(item)
        if entry is not None:
            self.remove_entry(entry)

    def set_expiry_time(self, expiry_time):
        assert(isinstance(expiry_time, int))
        self.expiry_time = expiry_time

    def get_entry(self, item):
        for b in self.blacklist:
            if item == b.item:
                return b
        return None


class frontiers_record:
    def __init__(self, peer_hash, frontier_hash, account):
        self.peer_hash = peer_hash
        self.frontier_hash = frontier_hash
        self.account = account

    # This method exists because cursor.fetchall() returns the data in the form of tuples
    @classmethod
    def from_tuple(cls, data):
        assert(isinstance(data, tuple))
        return frontiers_record(data[0], data[1], data[2])

    def __str__(self):
        string = "Peer: %s\n" % self.peer_hash
        string += "Frontier Hash: %s\n" % self.frontier_hash
        string += "Account: %s\n" % self.account
        return string


class peer_frontiers:
    def __init__(self, p, frontiers):
        assert(isinstance(p, Peer))
        assert(isinstance(frontiers, list))
        self.p = p
        self.frontiers = frontiers


def parse_args():
    parser = argparse.ArgumentParser()
    add_network_switcher_args(parser)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--sql', action='store_true', default=False,
                       help='Use this argument to use the SQL interface')
    group.add_argument('--ram', action='store_true', default=False,
                       help='Use this argument to store frontiers in RAM')
    group.add_argument('--lmdb', action='store_true', default=False,
                       help='Use this argument to store frontiers in LMDB database')

    parser.add_argument('-f', '--forever', action="store_true", default=False,
                        help='"forever" argument for the peercrawler thread')
    parser.add_argument('-v', '--verbosity', type=int, default=0,
                        help='verbosity for the peercrawler')

    parser.add_argument('--rmdb', action='store_true', default=False,
                        help='determines whether the frontier service tables should be reset')
    parser.add_argument('--db', type=str, default=None,
                        help='the name of the database that will be either created or connected to')
    parser.add_argument('-u', '--username', type=str, default='root',
                        help='the username for the connection')
    parser.add_argument('-p', '--password', type=str, default='password123',
                        help='password for the database connection')
    parser.add_argument('-H', '--host', type=str, default='localhost',
                        help='the ip of the sql server')

    parser.add_argument('--peer', type=str, default=None,
                        help='the ip address of the single peer which the service will connect to')
    parser.add_argument('--peer-port', type=int, default=7075,
                        help='the port of the single peer which the service will connect to')

    parser.add_argument('-D', '--differences', action='store_true', default=False,
                        help='If you want the service to get differences or not')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='runs the service, can be forever depending on the -f argument')
    parser.add_argument('--dumpdb', action='store_true', default=False,
                        help='option to dump all the data in the database')

    return parser.parse_args()


def frontier_read_iter(s):

    while True:
        front = frontier_request.read_frontier_response(s)
        if front.is_end_marker():
            return
        yield front


def find_average_time(times):
    n = 0.0
    for t in times:
        n += t
    return n / len(times)


def get_all_frontiers_packet_from_service(addr = '::1', port = 7080):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((addr, port))

        c_packet1 = client_packet(b'\x00' * 32)

        s.sendall((c_packet1.serialise()))

        hdr_data = read_socket(s, 9)
        s_hdr = server_packet_header.parse(hdr_data)

        front_data = read_socket(s, 64 * s_hdr.no_of_frontiers + 64)
        s_packet = server_packet.parse(s_hdr, front_data)
        return s_packet


def get_accounts_frontier_packet_from_service(account, addr = '::1', port = 7080):
    assert len(account) == 32
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((addr, port))

        c_packet = client_packet(account)

        s.sendall(c_packet.serialise())

        hdr_data = read_socket(s, 9)
        s_hdr = server_packet_header.parse(hdr_data)

        front_data = read_socket(s, 128)
        s_packet = server_packet.parse(s_hdr, front_data)

        return s_packet


def main():
    # Defaults:
    # - MySQL IP: 127.0.0.1
    # - MySQL Port: 3306
    # - MySQL Pass: password123

    # TODO: Remove the -c, replace with code which will create a new db if one doesn't exist
    # TODO: Add dumpdb option

    args = parse_args()
    setup_logger(logger, get_logging_level_from_int(args.verbosity))

    if args.beta:
        ctx = betactx
        db_name = "beta_net_frontiers"
    elif args.test:
        ctx = testctx
        db_name = "test_net_frontiers"
    else:
        ctx = livectx
        db_name = "live_net_frontiers"

    if args.db is None:
        args.db = db_name

    if args.rmdb:  # drop database and exit program
        db = setup_db_connection(host=args.host, user=args.username, passwd=args.password)
        db.cursor().execute(f"DROP DATABASE {args.db}")
        sys.exit(0)

    if args.ram:
        inter = store_in_ram_interface()
    elif args.lmdb:
        inter = store_in_lmdb(file_name=args.db)

    else:
        try:
            db = setup_db_connection(host=args.host, user=args.username, passwd=args.password, db=args.db)
            cursor = db.cursor()
            inter = my_sql_db(cursor, db)
        except mysql.connector.errors.ProgrammingError:
            db = setup_db_connection(host=args.host, user=args.username, passwd=args.password)
            create_new_database(db.cursor(), name=args.db)
            create_db_structure_frontier_service(db.cursor())
            db.close()
            db = setup_db_connection(host=args.host, user=args.username, passwd=args.password, db=args.db)
            cursor = db.cursor()
            inter = my_sql_db(cursor, db)

    service = frontier_service(ctx, inter, args.verbosity)

    if args.peer:
        peer = Peer(ip=ip_addr.from_string(args.peer), port=args.peer_port)
        service.merge_peers([peer])
        service.single_pass()
    elif args.service:  # this will run forever
        if args.forever:
            service.start_service()
        else:
            service.fetch_peers()
            service.single_pass()

    # This is a piece of code which can find accounts with different frontier hashes
    # if args.differences:
    #     records = frontserv.find_accounts_different_hashes()
    #     for rec in records:
    #         print(rec)
    #
    # if args.dumpdb:
    #     records = frontserv.get_all_records()
    #     for rec in records:
    #         print(rec)


if __name__ == "__main__":
    main()
