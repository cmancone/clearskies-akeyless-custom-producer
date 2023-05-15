import json
import clearskies
from clearskies.handlers.exceptions import InputError
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

        # we need to return a meaningful id if we are going to revoke at the end
        if self.configuration('can_revoke'):
            id_column_name = self.configuration('id_column_name')
            if id_column_name not in credentials:
                raise ValueError(
                    f"Response from create callable did not include the required id column: '{id_column_name}'"
                )
            # this is stupid but I'm doing it - see the revoke function for reasons
            credential_id = credentials[id_column_name].replace('_', 'ZZZZ----AAAA')
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
            return self.error(input_output, str(e), 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, input_errors)

        return input_output.respond({
            'revoked': ids,
            'message': '',
        }, 200)

    def revoke(self, input_output):
        try:
            payload = self._get_payload(input_output)
            ids = self._get_ids(input_output)
        except InputError as e:
            return self.error(input_output, str(e), 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, input_errors)

        for raw_id in ids:
            # Akeyless prepends some stuff to the id to make it unique, which we have to remove.
            # They will stick some parts and separate things with an underscore.  We therefore want
            # to split on an underscore and grab the part at the end.  This can cause trouble if the
            # id itself contains an underscore.  To avoid this, the create function replaces underscores
            # with a string that is very unlikely to exist in the actual id, so we have to reverse that.
            id = raw_id.split('_')[-1].replace('ZZZZ----AAAA', '_')
            self._di.call_function(
                self.configuration('revoke_callable'),
                **payload,
                payload=payload,
                id_to_delete=id,
            )

        return input_output.respond({
            'revoked': ids,
            'message': '',
        }, 200)

    def rotate(self, input_output):
        try:
            payload = self._get_payload(input_output)
        except InputError as e:
            return self.error(input_output, str(e), 400)

        errors = self._check_payload(payload)
        if errors:
            return self.input_errors(input_output, input_errors)

        # The user may have provided a rotate callable, in which case just use that.
        if self.configuration('rotate_callable'):
            new_payload = self._di.call_function(
                self.configuration('rotate_callable'),
                **payload,
                payload=payload,
            )
        # otherwise, perform a standard create+revoke
        else:
            new_payload = self._di.call_function(
                self.configuration('create_callable'),
                **payload,
                payload=payload,
                for_rotate=True,
            )
            if self.configuration('can_revoke'):
                self._di.call_function(
                    self.configuration('revoke_callable'),
                    **payload,
                    payload=payload,
                    id_to_delete=payload.get(self.configuration('id_column_name')),
                )

        return input_output.respond({
            'payload': json.dumps(new_payload),
        }, 200)

    def documentation(self):
        return []

    def documentation_security_schemes(self):
        return {}

    def documentation_models(self):
        return {}
