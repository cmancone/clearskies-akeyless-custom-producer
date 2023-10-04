import json
import clearskies
from clearskies.handlers.exceptions import InputError
from .exceptions import ProducerError
from .no_input import NoInput
class WithInput(NoInput):
    _configuration_defaults = {
        'base_url': '',
        'can_rotate': True,
        'can_revoke': True,
        'create_callable': None,
        'revoke_callable': None,
        'rotate_callable': None,
        'payload_schema': None,
        'input_schema': None,
        'id_column_name': None,
        'create_endpoint': 'sync/create',
        'revoke_endpoint': 'sync/revoke',
        'rotate_endpoint': 'sync/rotate',
    }

    def __init__(self, di):
        super().__init__(di)

    def _finalize_configuration(self, configuration):
        if configuration.get('input_schema'):
            configuration['input_schema'] = self._schema_to_columns(configuration['input_schema'])
        return super()._finalize_configuration(configuration)

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        if configuration.get('input_schema') is not None:
            self._check_schema(configuration['input_schema'], None, error_prefix)

    def _get_input(self, input_output):
        request_json = input_output.request_data(required=True)
        # Normally I like strict input validation, but I don't actually know if Akeyless always provides
        # this, or if they skip this if it is not present.
        if not request_json.get('input'):
            return {}
        if type(request_json['input']) != dict:
            raise InputError("'input' from request body was not a dictionary and I don't know what to do!")
        return request_json.get('input')

    def _check_input(self, input_args):
        if not self.configuration('input_schema'):
            return {}
        schema = self.configuration('input_schema')
        return {
            **self._extra_column_errors(input_args, schema),
            **self._find_input_errors(input_args, schema),
        }

    def create(self, input_output):
        try:
            payload = self._get_payload(input_output)
        except InputError as e:
            return self.error(input_output, str(e), 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, input_errors)

        try:
            input_args = self._get_input(input_output)
        except InputError as e:
            return self.error(input_output, str(e), 400)

        errors = self._check_input(input_args)
        if errors:
            return self.input_errors(input_output, input_errors)

        try:
            credentials = self._di.call_function(
                self.configuration('create_callable'),
                **payload,
                **input_args,
                input_args=input_args,
                payload=payload,
                for_rotate=False,
            )
        except InputError as e:
            return self.error(input_output, str(e), 400)
        except ProducerError as e:
            return self.error(input_output, str(e), 400)

        # we need to return a meaningful id if we are going to revoke at the end
        if self.configuration('can_revoke'):
            id_column_name = self.configuration('id_column_name')
            if id_column_name not in credentials:
                raise ValueError(
                    f"Response from create callable did not include the required id column: '{id_column_name}'"
                )
            # akeyless only accepts strings for the id - no integers, etc...
            credential_id = str(credentials[id_column_name])
        else:
            credential_id = 'i_dont_need_an_id'

        return input_output.respond({
            'id': credential_id,
            'response': credentials,
        }, 200)
