import logging
import urllib

from .base import RequestMicroService
from ..exception import SATOSAConfigurationError
from ..exception import SATOSAError


logger = logging.getLogger(__name__)


class IdpHintingError(SATOSAError):
    """
    SATOSA exception raised by IdpHinting microservice
    """
    pass


class IdpHinting(RequestMicroService):
    """
    Detect if an idp hinting feature have been requested
    """

    def __init__(self, config, *args, **kwargs):
        """
        Constructor.
        :param config: microservice configuration
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__(*args, **kwargs)
        try:
            self.idp_hint_param_names = config['allowed_params']
        except KeyError:
            raise SATOSAConfigurationError(
                f"{self.__class__.__name__} can't find allowed_params"
            )

    def process(self, context, data):
        """
        This intercepts if idp_hint paramenter is in use
        :param context: request context
        :param data: the internal request
        """
        if not all((not context.internal_data.get('target_entity_id'),
                    context._http_headers.get('QUERY_STRING'))):
            return super().process(context, data)

        qs = urllib.parse.parse_qs(context._http_headers['QUERY_STRING'])
        for pn in self.idp_hint_param_names:
            if pn in qs and qs.get(pn):
                # exit on first match
                entity_id = qs[pn][0]
                context.internal_data['target_entity_id'] = entity_id
                context.request['entityID'] = entity_id
                break
        return super().process(context, data)
