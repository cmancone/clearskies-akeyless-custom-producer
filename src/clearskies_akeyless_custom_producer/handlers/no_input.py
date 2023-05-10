import json
import clearskies
from clearskies.handlers.exceptions import InputError
class NoInput(clearskies.handlers.Base, clearskies.handlers.SchemaHelper):
    _configuration_defaults = {
        'base_url': '',
        'can_rotate': True,
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
        return super().configure(configuration)

    def _finalize_configuration(self, configuration):
        # add in our base url and make sure the final result doesn't start or end with a slash
        base_url = configuration['base_url'].strip('/')
        for endpoint in ['create_endpoint', 'revoke_endpoint', 'rotate_endpoint']:
            configuration[endpoint] = (base_url + '/' + configuration[endpoint].strip('/')).lstrip('/')
        if configuration.get('schema'):
            configuration['schema'] = self._schema_to_columns(configuration['schema'])
        super()._finalize_configuration(configuration)

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = f"Configuration error for handler '{self.__class__.__name__}':"
        if not configuration.get('id_column_name'):
            raise ValueError(
                f"{error_prefix} you must provide 'id_column_name' - the name of a key from the response of the create callable that will be passed along to the revoke callable"
            )
        if configuration.get('can_rotate'):
            if not configuration.get('rotate_callable'):
                raise ValueError(f"{error_prefix} you must provide the rotate callable or set 'can_rotate' to False")
            if not callable(configuration.get('rotate_callable')):
                raise ValueError(f"{error_prefix} 'rotate_callable' must be a callable but was something else")
        for callable_name in ['create_callable', 'revoke_callable']:
            if not configuration.get(callable_name):
                raise ValueError(f"{error_prefix} you must provide '{callable_name}'")
            if not callable(configuration.get(callable_name)):
                raise ValueError(f"{error_prefix} '{callable_name}' must be a callable but was something else")
        if configuration.get('schema') is not None:
            self._check_schema(configuration['schema'], [], error_prefix)

    def handle(self, input_output):
        if full_path == self.configuration('create_endpoint'):
            return self.create(input_output)
        elif full_path == self.configuration('revoke_endpoint'):
            return self.revoke(input_output)
        elif full_path == self.configuration('rotate_endpoint') and self.configuration('can_rotate'):
            return self.rotate(input_output)
        return self.error(input_output, 'Page not found', 404)

    def _check_payload(self, payload):
        if not self.configuration('schema'):
            return {}
        return {
            **self._extra_column_errors(payload),
            **self._find_input_errors(payload),
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

    def create(self, input_output):
        try:
            payload = self._get_payload(input_output)
        except InputError as e:
            return self.error(input_output, str(e), 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, input_errors)

        credentials = self._di.call_function(
            self.configuration('create_callable'),
            **payload,
            payload=payload,
            for_rotate=False,
        )

        id_column_name = self.configuration('id_column_name')
        if id_column_name not in credentials:
            raise ValueError(
                f"Response from create callable did not include the required id column: '{id_column_name}'"
            )

        return input_output.respond({
            'id': credentials[id_column_name],
            'response': credentials,
        }, 200)

    def documentation(self):
        return []

    def documentation_security_schemes(self):
        return {}

    def documentation_models(self):
        return {}
