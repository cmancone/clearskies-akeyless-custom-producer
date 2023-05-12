import json
import unittest
from unittest.mock import MagicMock
import clearskies
from clearskies.column_types import string
from clearskies.input_requirements import required
from .no_input import NoInput
class NoInputTest(unittest.TestCase):
    new_key = '12345-67890'
    new_secret = 'hushhush'

    def create(self, key, secret, payload):
        self.create_call = {
            'key': key,
            'secret': secret,
            'payload': payload,
        }
        return {
            'key': self.new_key,
            'secret': self.new_secret,
        }

    def revoke(self, key, secret, id_to_delete, payload):
        self.delete_call = {
            'key': key,
            'secret': secret,
            'payload': payload,
            'id_to_delete': id_to_delete,
        }
        return True

    def rotate(self, key, secret, payload):
        self.rotate_call = {
            'key': key,
            'secret': secret,
            'payload': payload,
        }
        return {
            'key': self.new_key,
            'secret': self.new_secret,
        }

    def setUp(self):
        self.create_call = None
        self.delete_call = None
        self.rotate_call = None
        self.di = clearskies.di.StandardDependencies()

        self.no_input = NoInput(self.di)
        self.no_input.configure({
            'create_callable':
            self.create,
            'revoke_callable':
            self.revoke,
            'id_column_name':
            'key',
            'payload_schema': [
                string('key', input_requirements=[required()]),
                string('secret', input_requirements=[required()]),
            ],
        })

    def test_create(self):
        create_call = clearskies.mocks.InputOutput(
            request_url='/sync/create', body={'payload': json.dumps({
                "key": "1111-2222",
                "secret": "shhhhh",
            })}
        )
        response = self.no_input.handle(create_call)
        self.assertEquals(200, response[1])
        self.assertDictEqual({
            'id': self.new_key,
            'response': {
                'key': self.new_key,
                'secret': self.new_secret,
            }
        }, response[0])
        self.assertDictEqual({
            'key': '1111-2222',
            'secret': 'shhhhh',
            'payload': {
                'key': '1111-2222',
                'secret': 'shhhhh',
            }
        }, self.create_call)

    def test_revoke(self):
        revoke_call = clearskies.mocks.InputOutput(
            request_url='/sync/revoke',
            body={
                'payload': json.dumps({
                    "key": "1111-2222",
                    "secret": "shhhhh",
                }),
                'ids': ['2222-3333'],
            }
        )
        response = self.no_input.handle(revoke_call)
        self.assertEquals(200, response[1])
        self.assertDictEqual({
            'message': '',
            'revoked': ['2222-3333'],
        }, response[0])
        self.assertDictEqual({
            'key': '1111-2222',
            'secret': 'shhhhh',
            'payload': {
                'key': '1111-2222',
                'secret': 'shhhhh',
            },
            'id_to_delete': '2222-3333',
        }, self.delete_call)

    def test_rotate(self):
        rotate_call = clearskies.mocks.InputOutput(
            request_url='/sync/rotate', body={
                'payload': json.dumps({
                    "key": "1111-2222",
                    "secret": "shhhhh",
                }),
            }
        )
        response = self.no_input.handle(rotate_call)
        self.assertEquals(200, response[1])
        self.assertDictEqual({'payload': '{"key": "' + self.new_key + '", "secret": "' + self.new_secret + '"}'},
                             response[0])
        self.assertDictEqual({
            'key': self.new_key,
            'secret': self.new_secret,
            'payload': {
                'key': self.new_key,
                'secret': self.new_secret,
            },
            'id_to_delete': '1111-2222',
        }, self.delete_call)
        self.assertDictEqual({
            'key': '1111-2222',
            'secret': 'shhhhh',
            'payload': {
                'key': '1111-2222',
                'secret': 'shhhhh',
            },
        }, self.create_call)

    def test_dedicated_rotate(self):
        no_input = NoInput(self.di)
        no_input.configure({
            'create_callable':
            self.create,
            'revoke_callable':
            self.revoke,
            'rotate_callable':
            self.rotate,
            'id_column_name':
            'key',
            'payload_schema': [
                string('key', input_requirements=[required()]),
                string('secret', input_requirements=[required()]),
            ],
        })
        rotate_call = clearskies.mocks.InputOutput(
            request_url='/sync/rotate', body={
                'payload': json.dumps({
                    "key": "1111-2222",
                    "secret": "shhhhh",
                }),
            }
        )
        response = no_input.handle(rotate_call)
        self.assertEquals(200, response[1])
        self.assertDictEqual({'payload': '{"key": "' + self.new_key + '", "secret": "' + self.new_secret + '"}'},
                             response[0])
        self.assertDictEqual({
            'key': '1111-2222',
            'secret': 'shhhhh',
            'payload': {
                'key': '1111-2222',
                'secret': 'shhhhh',
            },
        }, self.rotate_call)

    def test_no_revoke_for_you(self):
        no_input = NoInput(self.di)
        no_input.configure({
            'create_callable':
            self.create,
            'rotate_callable':
            self.rotate,
            'can_revoke':
            False,
            'id_column_name':
            'key',
            'payload_schema': [
                string('key', input_requirements=[required()]),
                string('secret', input_requirements=[required()]),
            ],
        })
        revoke_call = clearskies.mocks.InputOutput(
            request_url='/sync/revoke',
            body={
                'payload': json.dumps({
                    "key": "1111-2222",
                    "secret": "shhhhh",
                }),
                "ids": ["12345-12345"]
            }
        )
        response = no_input.handle(revoke_call)
        self.assertEquals(200, response[1])
        self.assertDictEqual({'message': '', "revoked": ["12345-12345"]}, response[0])
        self.assertTrue(self.delete_call == None)

    def test_no_rotate_for_you(self):
        no_input = NoInput(self.di)
        no_input.configure({
            'create_callable':
            self.create,
            'can_rotate':
            False,
            'id_column_name':
            'key',
            'payload_schema': [
                string('key', input_requirements=[required()]),
                string('secret', input_requirements=[required()]),
            ],
        })
        rotate_call = clearskies.mocks.InputOutput(request_url='/sync/rotate', )
        response = no_input.handle(rotate_call)
        self.assertEquals(404, response[1])
        self.assertTrue(self.delete_call == None)
        self.assertTrue(self.create_call == None)
