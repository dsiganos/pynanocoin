#!/usr/bin/env python3
#
# These unit tests test the following aspects of the code:
#
# - All functionalities required for packets on the nano protocol, for
#   example serialisation and deserialisation.
#
# - Serialisation, deserialisation and equality check for Peer objects
#
# - Serialisation, hashing and equality checks for all block types
#
# - Block manager block processing for an account
#
# - All blacklist functionalities
#
# - Voting peer check
#
# - Block and epoch, POW and signature verification
#
# - Endpoint parsing
#
# - Signing and verifying key pair functionality
#
# - Handshake exchange peer to peer communication
#
# - Account hash to address conversion
#
# - Frontier service client-server communicationimport time

import unittest
import binascii

from block import *
from msg_handshake import handshake_response, handshake_query, handshake_response_query, \
    handshake_exchange_server
from pynanocoin import *
from ipaddress import IPv6Address
from frontier_service import *
from peercrawler import send_confirm_req_genesis, get_peers_from_service
from frontier_request import *
from bulk_pull_account import *
from peer import Peer, ip_addr


class TestComms(unittest.TestCase):
    def setUp(self):
        data = "524222222202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"
        self.data = binascii.unhexlify(data)
        ip1 = Peer(ip_addr(IPv6Address("::ffff:9df5:d11e")), 54000)
        ip2 = Peer(ip_addr(IPv6Address("::ffff:18fb:4f64")), 54000)
        ip3 = Peer(ip_addr(IPv6Address("::ffff:405a:48c2")), 54000)
        ip4 = Peer(ip_addr(IPv6Address("::ffff:9538:2eec")), 54000)
        ip5 = Peer(ip_addr(IPv6Address("::ffff:2e04:4970")), 54000)
        ip6 = Peer(ip_addr(IPv6Address("::ffff:68cd:cd53")), 54000)
        ip7 = Peer(ip_addr(IPv6Address("::ffff:b3a2:bdef")), 54000)
        ip8 = Peer(ip_addr(IPv6Address("::ffff:74ca:6b61")), 54000)
        self.peer_list = [ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8]

    def test_header_serialisation(self):
        h = message_header(network_id(66), [34, 34, 34], message_type(2), 0)
        self.assertEqual(h.serialise_header(), self.data[:8])

    def test_header_deserialisation(self):
        h = message_header(network_id(66), [34, 34, 34], message_type(2), 0)
        h2 = message_header.parse_header(h.serialise_header())
        self.assertEqual(h2, h)

    def test_header_set_query_set_response(self):
        h1 = message_header(network_id(66), [18, 18, 18], message_type(10), 0)
        h2 = message_header(network_id(66), [18, 18, 18], message_type(10), 0)
        h3 = message_header(network_id(66), [18, 18, 18], message_type(10), 0)

        h1.set_is_query(True)
        self.assertTrue(h1.is_query())

        h2.set_is_response(True)
        self.assertTrue(h2.is_response())

        h3.set_is_response(True)
        h3.set_is_query(True)
        self.assertTrue(h3.is_response() and h3.is_query())

        h3.set_is_query(False)
        self.assertTrue(h3.is_response() and not h3.is_query())

        h3.set_is_query(True)
        h3.set_is_response(False)
        self.assertTrue(h3.is_query() and not h3.is_response())

    def test_peer_deserialisation(self):
        p = Peer(ip_addr(IPv6Address("::ffff:9df5:d11e")), 54000)
        p1 = Peer.parse_peer(self.data[8:26])
        self.assertTrue(p.compare(p1))

    def test_peer_serialisation(self):
        p = Peer(ip_addr(IPv6Address("::ffff:9df5:d11e")), 54000)
        self.assertEqual(self.data[8:26], p.serialise())

    def test_full_keepalive_serialisation(self):
        h = message_header(network_id(66), [34, 34, 34], message_type(2), 0)
        keepalive = message_keepalive(h, self.peer_list)
        self.assertEqual(self.data, keepalive.serialise())

    def test_equality_headers(self):
        h = message_header(network_id(66), [34, 34, 34], message_type(2), 0)
        h1 = message_header(network_id(66), [34, 34, 34], message_type(2), 0)
        self.assertTrue(h1 == h)

    def test_equality_peer(self):
        p = Peer(ip_addr(IPv6Address("::ffff:9df5:d11e")), 54000)
        p2 = Peer(ip_addr(IPv6Address("::ffff:9df5:d11e")), 54000)
        p3 = Peer(ip_addr(IPv6Address("::ffff:9df5:d113")), 54000)
        p4 = Peer(ip_addr(IPv6Address("::ffff:9df5:d11e")), 54001)
        self.assertTrue(p.compare(p2))
        self.assertTrue(not p.compare(p3))
        self.assertTrue(not p.compare(p4))

    def test_keepalive_full_loop1(self):
        h = message_header.parse_header(self.data[0:8])
        keepalive = message_keepalive.parse_payload(h, self.data[8:])
        self.assertEqual(self.data, keepalive.serialise())

    def test_keepalive_full_loop2(self):
        h = message_header(network_id(66), [34, 34, 34], message_type(2), 0)
        keepalive = message_keepalive(h, self.peer_list)
        data = keepalive.serialise()
        h = message_header.parse_header(data[0:8])
        keepalive2 = message_keepalive.parse_payload(h, data[8:])
        self.assertTrue(keepalive == keepalive2)


    def test_msg_bulk_pull_serialisation(self):
        ctx = livectx
        header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
        bulk_pull = message_bulk_pull(ctx, binascii.unhexlify(ctx['genesis_pub']))
        expected = b'RC\x12\x12\x12\x06\x00\x00\xe8\x92\x08\xdd\x03\x8f\xbb&\x99\x87h\x96!\xd5"\x92\xae\x9c5\x94\x1at\x84un\xcc\xed\x92\xa6P\x93\xba\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.assertEqual(bulk_pull.serialise(), expected)

    def test_block_send_serialisation(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        dest = binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
        bal = 325586539664609129644855132177
        sign = binascii.unhexlify('047115CB577AC78F5C66AD79BBF47540DE97A441456004190F22025FE4255285F57010D962601AE64C266C98FA22973DD95AC62309634940B727AC69F0C86D03')
        work = int.from_bytes(binascii.unhexlify('7202DF8A7C380578'), "little")
        expected = prev + dest + bal.to_bytes(16, "big") + sign + work.to_bytes(8, "little")
        b = block_send(prev, dest, bal, sign, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_send_hash(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        dest = binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
        bal = 325586539664609129644855132177
        sign = binascii.unhexlify('047115CB577AC78F5C66AD79BBF47540DE97A441456004190F22025FE4255285F57010D962601AE64C266C98FA22973DD95AC62309634940B727AC69F0C86D03')
        work = int.from_bytes(binascii.unhexlify('7202DF8A7C380578'), "little")

        b = block_send(prev, dest, bal, sign, work)
        expected = 'ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_send_equality(self):
        block1 = {
            "prev": binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 337010421085160209006996005437231978653,
            "sig": binascii.unhexlify(
                '5B11B17DB9C8FE0CC58CAC6A6EECEF9CB122DA8A81C6D3DB1B5EE3AB065AA8F8CB1D6765C8EB91B58530C5FF5987AD95E6D34BB57F44257E20795EE412E61600'),
            "work": int.from_bytes(binascii.unhexlify('3C82CC724905EE95'), "little")
        }
        b1 = block_send(block1["prev"], block1["dest"], block1["bal"], block1["sig"], block1["work"])
        b2 = block_send(block1["prev"], block1["dest"], block1["bal"], block1["sig"], block1["work"])

        self.assertEqual(b1, b2)

        b2.ancillary["next"] = b'\x00'
        try:
            self.assertEqual(b1, b2)
            self.assertTrue(False)
        except AssertionError:
            self.assertTrue(True)

    def test_block_receive_serialisation(self):
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        source = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('7202DF8A7C380578'), "little")
        b = block_receive(prev, source, sig, work)
        expected = prev + source + sig + work.to_bytes(8, "little")
        self.assertEqual(expected, b.serialise(False))

    def test_block_receive_hash(self):
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        source = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('7202DF8A7C380578'), "little")
        b = block_receive(prev, source, sig, work)
        expected = '617703C3D7343138CADFCAE391CA863E46BB5661AA74C93635A104141600D46D'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_receive_equality(self):
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        source = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('7202DF8A7C380578'), "little")

        b1 = block_receive(prev, source, sig, work)
        b2 = block_receive(prev, source, sig, work)
        self.assertEqual(b1, b2)
        b2.ancillary["next"] = b'\x00'

        try:
            self.assertEqual(b1, b2)
            self.assertTrue(False)

        except AssertionError:
            self.assertTrue(True)

    def test_block_open_serialisation(self):
        source = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02')
        work = int.from_bytes(binascii.unhexlify('62F05417DD3FB691'), "little")
        expected = source + rep + acc + sig + work.to_bytes(8, "little")
        b = block_open(source, rep, acc, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_open_hash(self):
        source = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02')
        work = int.from_bytes(binascii.unhexlify('62F05417DD3FB691'), "little")
        b = block_open(source, rep, acc, sig, work)
        expected = '991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_open_equality(self):
        source = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02')
        work = int.from_bytes(binascii.unhexlify('62F05417DD3FB691'), "little")

        b1 = block_open(source, rep, acc, sig, work)
        b2 = block_open(source, rep, acc, sig, work)
        self.assertEqual(b1, b2)
        b2.ancillary["next"] = b'\x00'

        try:
            self.assertEqual(b1, b2)
            self.assertTrue(False)
        except AssertionError:
            self.assertTrue(True)

    def test_block_change_serialisation(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('0F78168D5B30191D'), "little")
        expected = prev + rep + sig + work.to_bytes(8, "little")
        b = block_change(prev, rep, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_change_hash(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('0F78168D5B30191D'), "little")
        b = block_change(prev, rep, sig, work)
        expected = '01A8479535B4C10238F9B637ABB33B3271575F0918F748B4B6B01020073206AF'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_change_equality(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('0F78168D5B30191D'), "little")
        b1 = block_change(prev, rep, sig, work)
        b2 = block_change(prev, rep, sig, work)

        self.assertEqual(b1, b2)
        b2.ancillary["next"] = b'\x00'
        try:
            self.assertEqual(b1, b2)
            self.assertTrue(False)
        except AssertionError:
            self.assertTrue(True)

    def test_block_state_serialisation(self):
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        bal = 325586539664609129644855132177
        link = binascii.unhexlify('65706F636820763120626C6F636B000000000000000000000000000000000000')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        # State blocks POW  is big endian
        work = int.from_bytes(binascii.unhexlify('0F78168D5B30191D'), "big")
        expected = acc + prev + rep + bal.to_bytes(16, "big") + link + sig + work.to_bytes(8, "big")
        b = block_state(acc, prev, rep, bal, link, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_state_hash(self):
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        bal = 325586539664609129644855132177
        link = binascii.unhexlify('65706F636820763120626C6F636B000000000000000000000000000000000000')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('0F78168D5B30191D'), "big")
        b = block_state(acc, prev, rep, bal, link, sig, work)
        expected = '6875C0DBFE5C44D8F8CFF431BC69ED5587C68F89F0663F2BC1FBBFCB46DC5989'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_state_equality(self):
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        bal = 325586539664609129644855132177
        link = binascii.unhexlify('65706F636820763120626C6F636B000000000000000000000000000000000000')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = int.from_bytes(binascii.unhexlify('0F78168D5B30191D'), "big")

        b1 = block_state(acc, prev, rep, bal, link, sig, work)
        b2 = block_state(acc, prev, rep, bal, link, sig, work)

        self.assertEqual(b1, b2)
        b2.ancillary["next"] = b'\x00'

        try:
            self.assertEqual(b1, b2)
            self.assertTrue(False)

        except AssertionError:
            self.assertTrue(True)

    def test_block_manager_processing(self):
        block1 = {
            "prev" : binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'),
            "dest" : binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal" : 337010421085160209006996005437231978653,
            "sig" : binascii.unhexlify('5B11B17DB9C8FE0CC58CAC6A6EECEF9CB122DA8A81C6D3DB1B5EE3AB065AA8F8CB1D6765C8EB91B58530C5FF5987AD95E6D34BB57F44257E20795EE412E61600'),
            "work" : int.from_bytes(binascii.unhexlify('3C82CC724905EE95'), "little")
        }

        block2 = {
            "prev": binascii.unhexlify('A170D51B94E00371ACE76E35AC81DC9405D5D04D4CEBC399AEACE07AE05DD293'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 333738475249381954550617403442695745851,
            "sig": binascii.unhexlify('D6CAB5845050A058806D18C38E022322664A7E169498206420619F2ED031E7ED6FC80D5F33701B54B34B4DF2B65F02ECD8B5E26E44EC11B17570E1EE008EEC0E'),
            "work": int.from_bytes(binascii.unhexlify('96B201F33F0394AE'), "little")
        }

        block3 = {
            "prev": binascii.unhexlify('28129ABCAB003AB246BA22702E0C218794DFFF72AD35FD56880D8E605C0798F6'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 330466529413603700094238801448159513049,
            "sig": binascii.unhexlify('7F5ABE59D6C25EEEFE28174A6646D6E228FFDE3ACBA1293EDFFA057CE739AF9DAC89A4D1783BD30E2B4F0154815A959A57424C5EA35EA3ADF0CD2AF981BF7103'),
            "work": int.from_bytes(binascii.unhexlify('6B8567274385A390'), "little")
        }
        b1 = block_send(block1["prev"], block1["dest"], block1["bal"], block1["sig"], block1["work"])
        b2 = block_send(block2["prev"], block2["dest"], block2["bal"], block2["sig"], block2["work"])
        b3 = block_send(block3["prev"], block3["dest"], block3["bal"], block3["sig"], block3["work"])
        manager = block_manager(livectx, None, None)
        manager.process(b1)
        manager.process(b2)
        manager.process(b3)
        self.assertEqual(manager.accounts[0].blocks[b1.hash()], b1)
        self.assertEqual(manager.accounts[0].blocks[b2.hash()], b2)
        self.assertEqual(manager.accounts[0].blocks[b3.hash()], b3)

    def test_blacklist_add_duplicate_item(self):
        peer = self.peer_list[0]
        manager = blacklist_manager(Peer)

        manager.add_item(peer)
        manager.add_item(peer)
        self.assertEqual(len(manager.blacklist), 1)

    def test_blacklist_different_item_types(self):
        manager = blacklist_manager(Peer)
        net_id = network_id(67)
        peer = self.peer_list[0]
        manager.add_item(peer)

        try:
            manager.add_item(net_id)
            self.assertTrue(False)
        except BlacklistItemTypeError:
            self.assertTrue(True)

    def test_blacklist_is_blacklisted(self):
        manager1 = blacklist_manager(Peer)
        manager2 = blacklist_manager(Peer, 5)
        peer = self.peer_list[0]
        manager1.add_item(peer)
        self.assertTrue(manager1.is_blacklisted(peer))

        manager2.add_item(peer)
        self.assertTrue(manager2.is_blacklisted(peer))
        time.sleep(5)
        self.assertTrue(not manager2.is_blacklisted(peer))
        self.assertEqual(len(manager2.blacklist), 0)

    def test_is_voting_peers(self):
        ctx = livectx
        signing_key, verifying_key = ed25519_blake2b.create_keypair()
        p = Peer(ip_addr(ipaddress.IPv6Address("::ffff:94.130.135.50")), 7075)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(3)
            try:
                s.connect((str(p.ip), 7075))
                node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
                self.assertTrue(send_confirm_req_genesis(ctx, p, s))
                s.close()
            except OSError:
                s.close()
                self.assertTrue(False)

    def test_verify_block(self):
        block1 = {
            "prev": binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 337010421085160209006996005437231978653,
            "sig": binascii.unhexlify(
                '5B11B17DB9C8FE0CC58CAC6A6EECEF9CB122DA8A81C6D3DB1B5EE3AB065AA8F8CB1D6765C8EB91B58530C5FF5987AD95E6D34BB57F44257E20795EE412E61600'),
            "work": 0x3C82CC724905EE95
        }

        block2 = {
            "prev": binascii.unhexlify('A170D51B94E00371ACE76E35AC81DC9405D5D04D4CEBC399AEACE07AE05DD293'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 333738475249381954550617403442695745851,
            "sig": binascii.unhexlify(
                'D6CAB5845050A058806D18C38E022322664A7E169498206420619F2ED031E7ED6FC80D5F33701B54B34B4DF2B65F02ECD8B5E26E44EC11B17570E1EE008EEC0E'),
            "work": 0x96B201F33F0394AE
        }

        block3 = {
            "prev": binascii.unhexlify('28129ABCAB003AB246BA22702E0C218794DFFF72AD35FD56880D8E605C0798F6'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 330466529413603700094238801448159513049,
            "sig": binascii.unhexlify(
                '7F5ABE59D6C25EEEFE28174A6646D6E228FFDE3ACBA1293EDFFA057CE739AF9DAC89A4D1783BD30E2B4F0154815A959A57424C5EA35EA3ADF0CD2AF981BF7103'),
            "work": 0x6B8567274385A390
        }
        b1 = block_send(block1["prev"], block1["dest"], block1["bal"], block1["sig"], block1["work"])
        b2 = block_send(block2["prev"], block2["dest"], block2["bal"], block2["sig"], block2["work"])
        b3 = block_send(block3["prev"], block3["dest"], block3["bal"], block3["sig"], block3["work"])
        b1.ancillary["account"] = binascii.unhexlify(livectx["genesis_pub"])
        b2.ancillary["account"] = binascii.unhexlify(livectx["genesis_pub"])
        b3.ancillary["account"] = binascii.unhexlify(livectx["genesis_pub"])
        self.assertTrue(valid_block(livectx, b1, False))
        self.assertTrue(valid_block(livectx, b2, False))
        self.assertTrue(valid_block(livectx, b3, False))

    def test_epoch_validation(self):
        epochv2 = {
            'account': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'prev': binascii.unhexlify('6875C0DBFE5C44D8F8CFF431BC69ED5587C68F89F0663F2BC1FBBFCB46DC5989'),
            'rep': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'bal': 325586539664609129644855132177,
            'link': binascii.unhexlify('65706F636820763220626C6F636B000000000000000000000000000000000000'),
            'sign': binascii.unhexlify('B0FD724D1B341C7FB117AC51EB6B8D0BD56F424E7188F31718321C8B0CAEC92AE402D382917D65E9ECC741B3B31203569E9FB7B898EC4A08BEBCE859EA24BB0E'),
            'work': 0x494DBB4E8BD688AA
        }

        epochv1 = {
            'account': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'prev': binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113'),
            'rep': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'bal': 325586539664609129644855132177,
            'link': binascii.unhexlify('65706F636820763120626C6F636B000000000000000000000000000000000000'),
            'sign': binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201'),
            'work': 0x0F78168D5B30191D
        }
        ev1 = block_state(epochv1['account'], epochv1['prev'], epochv1['rep'], epochv1['bal'],
                          epochv1['link'], epochv1['sign'], epochv1['work'])
        ev2 = block_state(epochv2['account'], epochv2['prev'], epochv2['rep'], epochv2['bal'],
                          epochv2['link'], epochv2['sign'], epochv2['work'])
        ev1.set_type(block_type_enum.open)
        ev2.set_type(block_type_enum.open)

        self.assertTrue(valid_block(livectx, ev1, post_v2=False))
        self.assertTrue(valid_block(livectx, ev2))

    def test_parse_endpoint(self):
        string1 = '[::1234:1234]:12345'
        string2 = '1.2.3.4:12345'
        string3 = 'server.google.com:12345'
        string4 = '192.168.1.1'
        string5 = '::1234:1234'
        string6 = '4444:CCCC:DDDD:EEEE:FFFF'

        ip1, port1 = parse_endpoint(string1)
        ip2, port2 = parse_endpoint(string2)
        ip3, port3 = parse_endpoint(string3)
        ip4, port4 = parse_endpoint(string4)
        ip5, port5 = parse_endpoint(string5)
        ip6, port6 = parse_endpoint(string6)

        self.assertEqual(ip1, '::1234:1234')
        self.assertEqual(port1, 12345)

        self.assertEqual(ip2, '::FFFF:1.2.3.4')
        self.assertEqual(port2, 12345)

        self.assertEqual(ip3, 'server.google.com')
        self.assertEqual(port3, 12345)

        self.assertEqual(ip4, '::FFFF:192.168.1.1')
        self.assertEqual(port4, None)

        self.assertEqual(ip5, '::1234:1234')
        self.assertEqual(port5, None)

        self.assertEqual(ip6, '4444:CCCC:DDDD:EEEE:FFFF')
        self.assertEqual(port6, None)

    def test_peer_from_endpoint(self):
        string1 = '[::1234:1234]:12345'
        string2 = '1.2.3.4:12345'

        ip1, port1 = parse_endpoint(string1)
        ip2, port2 = parse_endpoint(string2)

        peer1 = peer_from_endpoint(ip1, port1)
        peer2 = peer_from_endpoint(ip2, port2)

        self.assertTrue(peer1.compare(Peer(ip_addr('::1234:1234'), 12345)))
        self.assertTrue(peer2.compare(Peer(ip_addr('::FFFF:1.2.3.4'), 12345)))

    def test_signing_verifying(self):
        signing_key, verifying_key = ed25519_blake2b.create_keypair()
        my_cookie = os.urandom(32)
        sig = signing_key.sign(my_cookie)
        self.assertEqual(verifying_key.verify(sig, my_cookie), None)

    def test_handshake_server_client(self):
        thread1 = threading.Thread(target=self.handshake_server, daemon=True)
        thread1.start()
        signing_key, verifying_key = ed25519_blake2b.create_keypair()
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(1000)
            s.connect(('::1', 6060))
            node_handshake_id.perform_handshake_exchange(livectx, s, signing_key, verifying_key)
        thread1.join()
        self.assertTrue(True)

    def handshake_server(self):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(1000)
            s.bind(('::1', 6060))
            s.listen()
            conn, _ = s.accept()
            with conn:
                data = read_socket(conn, 40)
                hdr = message_header.parse_header(data[0:8])
                query = handshake_query.parse_query(hdr, data[8:])
                signing_key, verifying_key = ed25519_blake2b.create_keypair()
                handshake_exchange_server(livectx, conn, query, signing_key, verifying_key)

    def test_account_key(self):
        acc_id = acctools.to_account_addr(binascii.unhexlify(livectx["genesis_pub"]))
        key = acctools.account_key(acc_id).hex()
        self.assertEqual(key, livectx["genesis_pub"].lower())

    def test_bulk_push_serialise_deserialise(self):
        block1 = {
            "prev": binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 337010421085160209006996005437231978653,
            "sig": binascii.unhexlify(
                '5B11B17DB9C8FE0CC58CAC6A6EECEF9CB122DA8A81C6D3DB1B5EE3AB065AA8F8CB1D6765C8EB91B58530C5FF5987AD95E6D34BB57F44257E20795EE412E61600'),
            "work": int.from_bytes(binascii.unhexlify('3C82CC724905EE95'), "little")
        }

        block2 = {
            "prev": binascii.unhexlify('A170D51B94E00371ACE76E35AC81DC9405D5D04D4CEBC399AEACE07AE05DD293'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 333738475249381954550617403442695745851,
            "sig": binascii.unhexlify(
                'D6CAB5845050A058806D18C38E022322664A7E169498206420619F2ED031E7ED6FC80D5F33701B54B34B4DF2B65F02ECD8B5E26E44EC11B17570E1EE008EEC0E'),
            "work": int.from_bytes(binascii.unhexlify('96B201F33F0394AE'), "little")
        }

        block3 = {
            "prev": binascii.unhexlify('28129ABCAB003AB246BA22702E0C218794DFFF72AD35FD56880D8E605C0798F6'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 330466529413603700094238801448159513049,
            "sig": binascii.unhexlify(
                '7F5ABE59D6C25EEEFE28174A6646D6E228FFDE3ACBA1293EDFFA057CE739AF9DAC89A4D1783BD30E2B4F0154815A959A57424C5EA35EA3ADF0CD2AF981BF7103'),
            "work": int.from_bytes(binascii.unhexlify('6B8567274385A390'), "little")
        }
        b1 = block_send(block1["prev"], block1["dest"], block1["bal"], block1["sig"], block1["work"])
        b2 = block_send(block2["prev"], block2["dest"], block2["bal"], block2["sig"], block2["work"])
        b3 = block_send(block3["prev"], block3["dest"], block3["bal"], block3["sig"], block3["work"])
        blocks = [b1, b2, b3]
        hdr = message_header(network_id(67), [18, 18, 18], message_type(7), 0)
        bp = bulk_push(hdr, blocks)
        serialised = bp.serialise()
        hdr1 = message_header.parse_header(serialised[0:8])
        bp1 = bulk_push.parse(hdr1, serialised[8:])

        self.assertEqual(bp1, bp)

    def test_frontier_req_serialise_deserialise(self):
        ctx = livectx
        fr_hdr = frontier_request.generate_header(ctx)
        fr = frontier_request(fr_hdr)
        serialised = fr.serialise()
        hdr = message_header.parse_header(serialised[:8])
        fr1 = frontier_request.parse(hdr, serialised[8:])

        self.assertEqual(fr, fr1)

    def test_bulk_pull_account_serialise_deserialise(self):
        ctx = livectx

        account = binascii.unhexlify(ctx['genesis_pub'])
        hdr = message_header(network_id(67), [18, 18, 18], message_type(11), 0)
        flag = 1
        bpa1 = bulk_pull_account(hdr, account, flag)
        serialised = bpa1.serialise()
        hdr1 = message_header.parse_header(serialised[0:8])
        bpa2 = bulk_pull_account.parse(hdr1, serialised[8:])
        self.assertEqual(bpa1, bpa2)

    def test_handshake_query_serialise_deserialise(self):
        ctx = livectx
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(10), 1)
        query1 = handshake_query(hdr)
        serialised = query1.serialise()
        hdr = message_header.parse_header(serialised[0:8])
        query2 = handshake_query.parse_query(hdr, serialised[8:])

        self.assertEqual(query1, query2)

    def test_handshake_response_serialise_deserialise(self):
        ctx = livectx
        account = os.urandom(32)
        sig = os.urandom(64)
        hdr1 = message_header(ctx['net_id'], [18, 18, 18], message_type(10), 0)
        hdr1.set_is_response(True)
        resp1 = handshake_response(hdr1, account, sig)
        serialised = resp1.serialise()
        hdr2 = message_header.parse_header(serialised[0:8])

        resp2 = handshake_response.parse_response(hdr2, serialised[8:])

        self.assertEqual(hdr1, hdr2)
        self.assertEqual(resp1, resp2)

    def test_handshake_query_response_serialise_deserialise(self):
        ctx = livectx
        cookie = os.urandom(32)
        account = os.urandom(32)
        sig = os.urandom(64)
        hdr1 = message_header(ctx['net_id'], [18, 18, 18], message_type(10), 0)
        hdr1.set_is_query(True)
        hdr1.set_is_response(True)
        hs1 = handshake_response_query(hdr1, cookie, account, sig)
        serialised = hs1.serialise()
        hdr2 = message_header.parse_header(serialised[0:8])

        hs2 = handshake_response_query.parse_query_response(hdr2, serialised[8:])

        self.assertEqual(hdr1, hdr2)
        self.assertEqual(hs1, hs2)

    def test_frontier_service_client(self):
        inter = store_in_ram_interface()
        frontserv = frontier_service(livectx, inter, 0)
        thread1 = threading.Thread(target=frontserv.start_service, daemon=True)
        thread1.start()
        time.sleep(5)
        s_packet = get_all_frontiers_packet_from_service()
        self.assertTrue(len(s_packet.frontiers) > 0)

    def test_get_peers_from_service(self):
        ctx = livectx
        peers = get_peers_from_service(ctx)
        self.assertTrue(len(peers) > 0)

    def test_sign_block(self):
        private_key = "9DFDAF721A0C3CEED3AC09E8667CDC073600B35E6E5A728816C0ABFCAFDC4D47"
        account = "7668CEA16DEB0BC3E8D08E2B78BD105C213EBDB9189C0C895F0E5462D86FB6BC"
        previous = "4E5004CA14899B8F9AABA7A76D010F73E6BAE54948912588B8C4FE0A3B558CA5"
        representative = "E382DD09EC8CAFC2427CF817E9AFE1F372CE81085AB4FEB1F3DE1F25EE818E5D"
        balance = 100000000000000000000000000
        link = "7668CEB0C62FBC6BED2D5FB6B71DCE3D7D0588F86656E163A3387E01E4FF7826"
        expected_signature = "92C3D9FD2C7E10F58E31C098F0815980B4D01776ACA75EE00E23777D09D973AB6BFA79A942A2688EE29C085AF3DA36A64741ECC4FC70E7ECBCCF6066C4BD160C"

        _block = block_state(binascii.unhexlify(account),
                             binascii.unhexlify(previous),
                             binascii.unhexlify(representative),
                             balance,
                             binascii.unhexlify(link), None, 0)

        private_key_bytes = binascii.unhexlify(private_key)
        _block.sign(ed25519_blake2b.SigningKey(private_key_bytes))

        self.assertTrue(_block.signature == binascii.unhexlify(expected_signature))


if __name__ == '__main__':
    unittest.main()


######################## Summary ########################
# These unit tests test the following aspects of the code:
#
# - All functionalities required for packets on the nano protocol, for
#   example serialisation and deserialisation.
#
# - Serialisation, deserialisation and equality check for Peer objects
#
# - Serialisation, hashing and equality checks for all block types
#
# - Block manager block processing for an account
#
# - All blacklist functionalities
#
# - Voting peer check
#
# - Block and epoch, POW and signature verification
#
# - Endpoint parsing
#
# - Signing and verifying key pair functionality
#
# - Handshake exchange peer to peer communication
#
# - Account hash to address conversion
#
# - Frontier service client-server communication
