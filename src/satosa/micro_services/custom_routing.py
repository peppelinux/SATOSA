import logging
from base64 import urlsafe_b64encode

from satosa.context import Context
from satosa.logging_util import satosa_logging

from .base import RequestMicroService
from ..exception import SATOSAConfigurationError
from ..exception import SATOSAError


logger = logging.getLogger(__name__)


class DecideBackendByTarget(RequestMicroService):
    """
    Select which backend should be used based on who is the SAML IDP
    """

    def __init__(self, config, *args, **kwargs):
        """
        Constructor.
        :param config: mapping from requester identifier to
        backend module name under the key 'requester_mapping'
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__(*args, **kwargs)
        self.target_mapping = config['target_mapping']


    def get_backend_by_endpoint_path(self, context, native_backend,
                                     backends):
        """
        Returns a new path and target_backend according to its maps

        :type context: satosa.context.Context
        :rtype: ((satosa.context.Context, Any) -> Any, Any)

        :param context: The request context
        :param native_backed: the backed that the proxy normally have been used
        :param backends: list of all the backend configured in the proxy

        :return: tuple or None
        """
        entity_id = context.request.get('entityID')
        if not entity_id:
            return
        if entity_id not in self.target_mapping.keys():
            return

        tr_backend = self.target_mapping[entity_id]
        tr_path = context.path.replace(native_backend, tr_backend)
        for endpoint in backends[tr_backend]['endpoints']:
            # remove regex trailing chars
            if tr_path == endpoint[0].strip('^').strip('$'):
                msg = ('Found DecideBackendByTarget ({} microservice ) '
                       'redirecting {} backend to {}').format(self.name,
                                                              native_backend,
                                                              tr_backend)
                satosa_logging(logger, logging.DEBUG, msg, context.state)
                return (tr_backend, tr_path)
        return


class DecideBackendByRequester(RequestMicroService):
    """
    Select which backend should be used based on who the requester is.
    """

    def __init__(self, config, *args, **kwargs):
        """
        Constructor.
        :param config: mapping from requester identifier to
        backend module name under the key 'requester_mapping'
        :type config: Dict[str, Dict[str, str]]
        """
        super().__init__(*args, **kwargs)
        self.requester_mapping = config['requester_mapping']

    def process(self, context, data):
        """
        Will modify the context.target_backend attribute based on the requester identifier.
        :param context: request context
        :param data: the internal request
        """
        context.target_backend = self.requester_mapping[data.requester]
        return super().process(context, data)


class DecideIfRequesterIsAllowed(RequestMicroService):
    """
    Decide whether a requester is allowed to send an authentication request to the target entity.

    This micro service currently only works when a target entityid is set.
    Currently, a target entityid is set only when the `SAMLMirrorFrontend` is
    used.
    """
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for target_entity, rules in config["rules"].items():
            conflicting_rules = set(rules.get("deny", [])).intersection(rules.get("allow", []))
            if conflicting_rules:
                raise SATOSAConfigurationError("Conflicting requester rules for DecideIfRequesterIsAllowed,"
                                               "{} is both denied and allowed".format(conflicting_rules))

        # target entity id is base64 url encoded to make it usable in URLs,
        # so we convert the rules the use those encoded entity id's instead
        self.rules = {self._b64_url(k): v for k, v in config["rules"].items()}

    def _b64_url(self, data):
        return urlsafe_b64encode(data.encode("utf-8")).decode("utf-8")

    def process(self, context, data):
        target_entity_id = context.get_decoration(Context.KEY_TARGET_ENTITYID)
        if None is target_entity_id:
            msg_tpl = "{name} can only be used when a target entityid is set"
            msg = msg_tpl.format(name=self.__class__.__name__)
            logger.error(msg)
            raise SATOSAError(msg)

        target_specific_rules = self.rules.get(target_entity_id)
        # default to allowing everything if there are no specific rules
        if not target_specific_rules:
            logging.debug("Requester '%s' allowed by default to target entity '%s' due to no entity specific rules",
                          data.requester, target_entity_id)
            return super().process(context, data)

        # deny rules takes precedence
        deny_rules = target_specific_rules.get("deny", [])
        if data.requester in deny_rules:
            logging.debug("Requester '%s' is not allowed by target entity '%s' due to deny rules '%s'", data.requester,
                          target_entity_id, deny_rules)
            raise SATOSAError("Requester is not allowed by target provider")

        allow_rules = target_specific_rules.get("allow", [])
        allow_all = "*" in allow_rules
        if data.requester in allow_rules or allow_all:
            logging.debug("Requester '%s' allowed by target entity '%s' due to allow rules '%s",
                          data.requester, target_entity_id, allow_rules)
            return super().process(context, data)

        logging.debug("Requester '%s' is not allowed by target entity '%s' due to no deny all rule in '%s'",
                      data.requester, target_entity_id, deny_rules)
        raise SATOSAError("Requester is not allowed by target provider")
