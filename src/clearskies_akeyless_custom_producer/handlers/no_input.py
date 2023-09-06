import json
import clearskies
from clearskies.handlers.exceptions import ClientError, InputError
from clearskies.handlers.base import Base
from .exceptions import ProducerError
class NoInput(clearskies.handlers.SchemaHelper, Base):
    _configuration_defaults = {
        'base_url': '',
        'can_rotate': True,
        'can_revoke': True,
        'create_callable': None,
        'revoke_callable': None,
        'rotate_callable': None,
        'payload_schema': None,
        'id_column_name': None,
        'create_endpoint': 'sync/create',
        'revoke_endpoint': 'sync/revoke',
        'rotate_endpoint': 'sync/rotate',
    }

    def __init__(self, di):
        super().__init__(di)

    def configure(self, configuration):
        # we don't need authentication but clearskies requires it, so provide one if it doesn't exist
        if 'authentication' not in configuration:
            configuration['authentication'] = clearskies.authentication.public()
        super().configure(configuration)

    def _finalize_configuration(self, configuration):
        # add in our base url and make sure the final result doesn't start or end with a slash
        base_url = configuration['base_url'].strip('/')
        for endpoint in ['create_endpoint', 'revoke_endpoint', 'rotate_endpoint']:
            configuration[endpoint] = (base_url + '/' + configuration[endpoint].strip('/')).lstrip('/')
        if configuration.get('payload_schema'):
            configuration['payload_schema'] = self._schema_to_columns(configuration['payload_schema'])
        return super()._finalize_configuration(configuration)

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = f"Configuration error for handler '{self.__class__.__name__}':"
        if not configuration.get('id_column_name'):
            raise ValueError(
                f"{error_prefix} you must provide 'id_column_name' - the name of a key from the response of the create callable that will be passed along to the revoke callable"
            )
        for action in ['revoke']:
            if not configuration.get(f'can_{action}'):
                continue
            if not configuration.get(f'{action}_callable'):
                raise ValueError(f"{error_prefix} you must provide '{action}_callable' or set 'can_{action}' to False")
            if not callable(configuration.get(f'{action}_callable')):
                raise ValueError(f"{error_prefix} '{action}_callable' must be a callable but was something else")
        if not configuration.get('create_callable'):
            raise ValueError(f"{error_prefix} you must provide 'create_callable'")
        if not callable(configuration.get('create_callable')):
            raise ValueError(f"{error_prefix} 'create_callable' must be a callable but was something else")
        if configuration.get('rotate_callable'):
            if 'can_rotate' in configuration and not configuration.get('can_rotate'):
                raise ValueError(
                    f"{error_prefix} 'rotate_callable' was provided, but can_rotate is set to False.  To avoid undefined behavior, this is not allowed."
                )
            if not callable(configuration['rotate_callable']):
                raise ValueError(
                    f"{error_prefix} 'rotate_callable' must be a callable (or None) but was something else"
                )
        if configuration.get('payload_schema') is not None:
            self._check_schema(configuration['payload_schema'], None, error_prefix)

    def handle(self, input_output):
        full_path = input_output.get_full_path().strip('/')
        if full_path == self.configuration('create_endpoint'):
            return self.create(input_output)
        elif full_path == self.configuration('revoke_endpoint'):
            if self.configuration('can_revoke'):
                return self.revoke(input_output)
            else:
                return self.dummy_revoke(input_output)
        elif full_path == self.configuration('rotate_endpoint') and self.configuration('can_rotate'):
            return self.rotate(input_output)
        return self.error(input_output, 'Page not found', 404)

    def _check_payload(self, payload):
        if not self.configuration('payload_schema'):
            return {}
        schema = self.configuration('payload_schema')
        return {
            **self._extra_column_errors(payload, schema),
            **self._find_input_errors(payload, schema),
        }

    def _get_payload(self, input_output):
        request_json = input_output.request_data(required=True)
        if 'payload' not in request_json:
            raise InputError("Missing 'payload' in JSON POST body")
        if not request_json['payload']:
            raise InputError("Provided 'payload' in JSON POST body was empty")
        if not isinstance(request_json['payload'], str):
            if isinstance(request_json['payload'], dict):
                raise InputError(
                    "'payload' in the JSON POST body was a JSON object, but it should be a serialized JSON string"
                )
            raise InputError("'payload' in JSON POST must be a string containing JSON")
        try:
            payload = json.loads(request_json['payload'])
        except json.JSONDecodeError:
            raise InputError("'payload' in JSON POST body was not a valid JSON string")
        return payload

    def _get_ids(self, input_output):
        request_json = input_output.request_data(required=True)
        if 'ids' not in request_json:
            raise InputError("Missing 'ids' in JSON POST body")
        return request_json['ids']

    def create(self, input_output):
        try:
            payload = self._get_payload(input_output)
        except InputError as e:
            return self.error(input_output, e.errors, 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, errors)

        try:
            credentials = self._di.call_function(
                self.configuration('create_callable'),
                **payload,
                payload=payload,
                for_rotate=False,
            )
        except (InputError, ClientError, ProducerError) as e:
            return self.error(input_output, str(e), 400)

        # we need to return a meaningful id if we are going to revoke at the end
        if self.configuration('can_revoke'):
            id_column_name = self.configuration('id_column_name')
            if id_column_name not in credentials:
                raise ValueError(
                    f"Response from create callable did not include the required id column: '{id_column_name}'"
                )
            # akeyless will only accept strings as the id value - no integers/etc
            credential_id = str(credentials[id_column_name])
        else:
            credential_id = 'i_dont_need_an_id'

        return input_output.respond({
            'id': credential_id,
            'response': credentials,
        }, 200)

    def dummy_revoke(self, input_output):
        """
        Revoke, but don't revoke

        This is here because Akeyless always requires a revoke endpoint, but revokation is not always
        possible. So, if revoke is disabled, we still need to respond to the revoke endpoint.
        """
        try:
            payload = self._get_payload(input_output)
            ids = self._get_ids(input_output)
        except InputError as e:
            return self.error(input_output, e.errors, 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, errors)

        return input_output.respond({
            'revoked': ids,
            'message': '',
        }, 200)

    def revoke(self, input_output):
        try:
            payload = self._get_payload(input_output)
            ids = self._get_ids(input_output)
        except InputError as e:
            return self.error(input_output, e.errors, 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, errors)

        for id in ids:
            try:
                self._di.call_function(
                    self.configuration('revoke_callable'),
                    **payload,
                    payload=payload,
                    id_to_delete=id,
                )
            except (InputError, ClientError, ProducerError) as e:
                return self.error(input_output, str(e), 400)

        return input_output.respond({
            'revoked': ids,
            'message': '',
        }, 200)

    def rotate(self, input_output):
        try:
            payload = self._get_payload(input_output)
        except InputError as e:
            return self.error(input_output, e.errors, 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, errors)

        # The user may have provided a rotate callable, in which case just use that.
        if self.configuration('rotate_callable'):
            new_payload = self._di.call_function(
                self.configuration('rotate_callable'),
                **payload,
                payload=payload,
            )
        # otherwise, perform a standard create+revoke
        else:
            try:
                new_payload = self._di.call_function(
                    self.configuration('create_callable'),
                    **payload,
                    payload=payload,
                    for_rotate=True,
                )
                if self.configuration('can_revoke'):
                    self._di.call_function(
                        self.configuration('revoke_callable'),
                        **new_payload,
                        payload=new_payload,
                        id_to_delete=payload.get(self.configuration('id_column_name')),
                    )
            except (InputError, ClientError, ProducerError) as e:
                return self.error(input_output, str(e), 400)

        return input_output.respond({
            'payload': json.dumps(new_payload),
        }, 200)

    def documentation(self):
        return []

    def documentation_security_schemes(self):
        return {}

    def documentation_models(self):
        return {}
