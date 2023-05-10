import clearskies
class NoInput(clearskies.handlers.Base, clearskies.handlers.SchemaHelper):
    _configuration_defaults = {
        'base_url': '',
        'can_rotate': True,
        'create_callable': None,
        'revoke_callable': None,
        'rotate_callable': None,
        'payload_schema': None,
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

    def check_payload(self, payload):
        if not self.configuration('schema'):
            return

    def documentation(self):
        return []

    def documentation_security_schemes(self):
        return {}

    def documentation_models(self):
        return {}
