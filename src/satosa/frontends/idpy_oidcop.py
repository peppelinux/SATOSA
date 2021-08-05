"""
The OpenID Connect frontend module for the satosa proxy
"""
import json
import logging
from collections import defaultdict
from urllib.parse import urlencode, urlparse

from oidcop.authn_event import create_authn_event
from oidcop.exception import InvalidClient
from oidcop.exception import UnAuthorizedClient
from oidcop.exception import UnknownClient
from oidcmsg.oidc import AuthorizationErrorResponse
from oidcop.oidc.token import Token
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

from .base import FrontendModule
from .oidcop.application import oidcop_application as oidcop_app
from .oidcop.models import get_client_by_id
from ..response import BadRequest, Created
from ..response import SeeOther, JsonResponse
from ..response import Unauthorized
from ..util import rndstr

import satosa.logging_util as lu
from satosa.context import Context
from satosa.internal import InternalData

from urllib.parse import urlparse

# from .oidcop.decorators import prepare_oidc_endpoint
# from . exceptions import InconsinstentSessionDump
# from . models import OidcRelyingParty, OidcSession, OidcIssuedToken

IGNORED_HEADERS = ["cookie", "user-agent"]
logger = logging.getLogger(__name__)


class OidcOpFrontend(FrontendModule):
    """
    The OpenID Connect frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf, base_url, name):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.app = oidcop_app(conf)
        self.config = self.app.srv_config
        jwks_public_path = self.config['keys']['public_path']
        with open(jwks_public_path) as f:
            self.jwks_public = f.read()

        # registered endpoints will be filled by self.register_endpoints
        self.endpoints = None

    def _load_storage(self):
        """
        Loads SATOSA custom oidcop storage
        """
        self.storage = self.app["storage"]

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        url_map = [
            (v['path'], getattr(self, f"{k}_endpoint"))
            for k,v in self.config.endpoint.items()
        ]

        # add jwks.json webpath
        uri_path = self.config['keys']['uri_path']
        url_map.append(
            (uri_path, self.jwks_endpoint)
        )

        logger.debug(f"Loaded OIDC Provider endpoints: {url_map}")
        self.endpoints = url_map
        return url_map

    def _get_http_info(self, context: Context):
        _cookies = []
        for i in context.cookie.split(';'):
            splitted = i.split('=')
            if len(splitted) > 1:
                _cookies.append(
                    {
                        "name": splitted[0].strip(),
                        "value": splitted[1].strip()
                    }
                )

        http_info = {
            "headers": {
                k.lower(): v
                for k, v in context._http_headers.items()
                if k not in IGNORED_HEADERS
            },
            "method": context._http_headers['REQUEST_METHOD'],
            "url": context._http_headers['REQUEST_URI'],
            # name is not unique
        }
        if _cookies:
            http_info['cookie'] = _cookies
        return http_info

    def _get_http_data(self, context: Context):
        data = {}
        _method = context._http_headers['REQUEST_METHOD']
        # TODO
        # if _method == 'GET':
            # data = {k: v for k, v in context.request}
        # elif _method == 'POST':
            # data = {k: v for k, v in context.request}

        # if not data and request.body:
            # data = json.loads(context.request)

        return context.request

    def jwks_endpoint(self, context: Context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return JsonResponse(
            self.jwks_public
        )

    def provider_info_endpoint(self, context: Context):
        """
        Construct the provider configuration information
        served at /.well-known/openid-configuration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.app.endpoint_context.endpoint['provider_config']
        logger.info(f'Request at the "{endpoint.name}" endpoint')
        http_info = self._get_http_info(context)

        data = self._get_http_data(context)
        req_args = endpoint.parse_request(data, http_info=http_info)
        args = endpoint.process_request(req_args, http_info=http_info)

        info = endpoint.do_response(
            request=context.request, **args
        )
        # http_headers = info['http_headers']
        response = info['response']
        return JsonResponse(response)


    def _fill_cdb(self, context: Context) -> None:
        client_id = context.request.get('client_id')
        _msg = f'Client {client_id} not found!'
        if client_id:
            client = get_client_by_id(client_id)
            if client:
                ec = self.app.endpoint_context
                ec.endpoint_context.cdb = {
                    client_id: client
                }
        else:
            logger.warning(_msg)
            raise InvalidClient(_msg)

    def _handle_authn_request(self, context: Context, endpoint):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: satosa.internal.InternalData

        :param context: the current context
        :return: the internal request
        """
        request = urlencode(context.request)
        msg = "Authn req from client: {}".format(request)
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(context.state), message=msg
        )
        logger.debug(logline)

        http_info = self._get_http_info(context)
        data = self._get_http_data(context)
        req_args = endpoint.parse_request(data, http_info=http_info)
        args = endpoint.process_request(req_args, http_info=http_info)

        info = endpoint.do_response(
            request=context.request, **args
        )
        # http_headers = info['http_headers']
        response = info['response']

        # TODO logging and error handling
        # something to be done with the help of some unit test

        # try:
            # authn_req = self.provider.parse_authentication_request(request)
        # except InvalidAuthenticationRequest as e:
            # msg = "Error in authn req: {}".format(str(e))
            # logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            # logger.error(logline)
            # error_url = e.to_error_url()

            # if error_url:
                # return SeeOther(error_url)
            # else:
                # return BadRequest("Something went wrong: {}".format(str(e)))

        # clients
        # endpoint.server_get('endpoint_context').cdb
        client_id = req_args.get('client_id')
        context.state[self.name] = {"oidc_request": request}

        _client_conf = endpoint.server_get('endpoint_context').cdb[client_id]
        subject_type = _client_conf.get("subject_type", "pairwise")

        client_name = _client_conf.get("client_name")
        if client_name:
            requester_name = [{"lang": "en", "text": client_name}]
        else:
            requester_name = None

        internal_req = InternalData(
            subject_type=subject_type,
            requester=client_id,
            requester_name=requester_name,
        )

        _claims_supported = self.config['capabilities']['claims_supported']
        # _approved_attributes = self._get_approved_attributes(
                # _claims_supported, authn_req
        # )
        internal_req.attributes = self.converter.to_internal_filter(
            "openid", _claims_supported
        )

        # otherwise exception here ...
        context.target_backend = self.app.default_target_backend

        context.internal_data = internal_req
        return internal_req

    #@prepare_oidc_endpoint
    def authorization_endpoint(self, context: Context):
        self._fill_cdb(context)
        _endpoint = self.app.endpoint_context.endpoint['authorization']
        internal_req = self._handle_authn_request(context, _endpoint)
        if not isinstance(internal_req, InternalData):
            return internal_req

        return self.auth_req_callback_func(context, internal_req)

    def introspection_endpoint(self, context: Context):
        pass

    def handle_authn_request(self, context: Context):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        internal_req = self._handle_authn_request(context)
        if not isinstance(internal_req, InternalData):
            return internal_req
        return self.auth_req_callback_func(context, internal_req)

    def handle_authn_response(self, context: Context, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype oic.utils.http_util.Response
        """

        auth_req = self._get_authn_request_from_state(context.state)

        claims = self.converter.from_internal("openid", internal_resp.attributes)
        # Filter unset claims
        claims = {k: v for k, v in claims.items() if v}
        self.user_db[internal_resp.subject_id] = dict(combine_claim_values(claims.items()))
        auth_resp = self.provider.authorize(
            auth_req,
            internal_resp.subject_id,
            extra_id_token_claims=lambda user_id, client_id:
                self._get_extra_id_token_claims(user_id, client_id),
        )

        del context.state[self.name]
        http_response = auth_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req))
        return SeeOther(http_response)

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        auth_req = self._get_authn_request_from_state(exception.state)
        # If the client sent us a state parameter, we should reflect it back according to the spec
        if 'state' in auth_req:
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message,
                                                    state=auth_req['state'])
        else:
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message)
        msg = exception.message
        logline = lu.LOG_FMT.format(id=lu.get_session_id(exception.state), message=msg)
        logger.debug(logline)
        return SeeOther(error_resp.request(auth_req["redirect_uri"], should_fragment_encode(auth_req)))


    def client_registration(self, context: Context):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        raise NotImplementedError()

    def token_endpoint(self, context: Context):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        headers = {"Authorization": context.request_authorization}
        try:
            response = self.provider.handle_token_request(
                urlencode(context.request),
                headers,
                lambda user_id, client_id: self._get_extra_id_token_claims(user_id, client_id))
            return Response(response.to_json(), content="application/json")
        except InvalidClientAuthentication as e:
            logline = "invalid client authentication at token endpoint"
            logger.debug(logline, exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
            response = Unauthorized(error_resp.to_json(), headers=[("WWW-Authenticate", "Basic")],
                                    content="application/json")
            return response
        except OAuthError as e:
            logline = "invalid request: {}".format(str(e))
            logger.debug(logline, exc_info=True)
            error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
            return BadRequest(error_resp.to_json(), content="application/json")

    def userinfo_endpoint(self, context: Context):
        headers = {"Authorization": context.request_authorization}

        try:
            response = self.provider.handle_userinfo_request(
                request=urlencode(context.request),
                http_headers=headers,
            )
            return Response(response.to_json(), content="application/json")
        except (BearerTokenError, InvalidAccessToken) as e:
            error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
            response = Unauthorized(error_resp.to_json(), headers=[("WWW-Authenticate", AccessToken.BEARER_TOKEN_TYPE)],
                                    content="application/json")
            return response
