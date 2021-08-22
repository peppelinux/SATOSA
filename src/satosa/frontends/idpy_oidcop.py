"""
The OpenID Connect frontend module for the satosa proxy
"""
import base64
import json
import logging
import os

from oidcop.authn_event import create_authn_event
from oidcop.exception import InvalidClient
from oidcop.exception import UnAuthorizedClient
from oidcop.exception import UnknownClient
from oidcmsg.oidc import AuthorizationErrorResponse
from oidcop.oidc.token import Token
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from urllib.parse import urlencode, urlparse

from .base import FrontendModule
from .oidcop.application import oidcop_application as oidcop_app
from .oidcop.claims import *
from .oidcop.user_info import SatosaOidcUserInfo
from ..response import BadRequest, Created
from ..response import SeeOther, JsonResponse, Response
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


class OidcOpUtils(object):
    """
    Interoperability class between satosa and oidcop
    """

    def _fill_cdb(self, context: Context) -> None:
        """
            gets client_id from local storage and updates the client DB
        """
        client_id = context.request.get('client_id')
        _msg = f'Client {client_id} not found!'
        if client_id:
            client = self.app.storage.get_client_by_id(client_id)
            if client:
                self.app.server.endpoint_context.cdb = {
                    client_id: client
                }
        else:
            logger.warning(_msg)
            raise InvalidClient(_msg)

    def _load_storage(self):
        """
        Loads SATOSA custom oidcop storage
        """
        self.storage = self.app["storage"]

    def _get_http_info(self, context: Context):
        """
        aligns parameters for oidcop interoperability needs
        """
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

        # for token and userinfo endpoint ... but also for authz endpoint sometimes
        if getattr(context, 'request_authorization', None):
            http_info['headers'] = {
                "authorization": context.request_authorization
            }
        return http_info

    def _check_session_dump_consistency(self, endpoint, session):
        """
        Checks if the session dump matches with the one in the DB
        """
        ec = self.app.server.endpoint_context
        _dump = ec.session_manager.dump()
        if _dump != session:
            logger.critical(_dump, session)
            ec.session_manager.flush()
            raise InconsinstentSessionDump(endpoint.name)

    def load_session_in_db(self, endpoint):
        ec = self.app.server.endpoint_context
        ses_man_dump = ec.session_manager.dump()
        # session db mngmtn
        try:
            #
            pass
            # breakpoint()
        except InconsinstentSessionDump as e:
            logger.critical(e)
            ec.session_manager.flush()
            return JsonResponse(json.dumps({
                'error': 'invalid_request',
                'error_description': str(e),
            }), status="500")
        else:
            pass
            #  logger.warning(endpoint.__class__.__name__)
            #self._check_session_dump_consistency(endpoint, ses_man_dump)
        # ec.session_manager.flush()


class OidcOpFrontend(FrontendModule, OidcOpUtils):
    """
    OpenID Connect frontend module based on idpy oidcop
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
        endpoint = self.app.server.endpoint['provider_config']
        logger.info(f'Request at the "{endpoint.name}" endpoint')
        http_info = self._get_http_info(context)

        parse_req = endpoint.parse_request(context.request, http_info=http_info)
        proc_req = endpoint.process_request(parse_req, http_info=http_info)

        info = endpoint.do_response(request=context.request, **proc_req)
        return JsonResponse(info['response'])

    def handle_error(self, msg: str = None, excp: str = None, status: str = "403"):
        _msg = f'Something went wrong ... {excp or ""}'
        msg = msg or _msg
        logger.error(msg)
        return JsonResponse(msg, status=status)

    def _parse_request(self, endpoint, request_data, context: Context, http_info={}):
        """
        Returns a parsed request
        """
        http_info = http_info or self._get_http_info(context)
        parse_req = endpoint.parse_request(request_data, http_info=http_info)
        return parse_req

    def _process_request(self, context: Context, endpoint, parse_req, http_info):
        """
        Authorization, Token and userinfo
        """
        if isinstance(endpoint, Token):
            try:
                _req = AccessTokenRequest(**parse_req)
            except Exception as err:
                logger.error(err)
                return JsonResponse({
                    'error': 'invalid_request',
                    'error_description': str(err),
                }, status="400")
        else:
            _req = parse_req

        try:
            proc_req = endpoint.process_request(_req, http_info=http_info)
            return proc_req
        except (InvalidClient, UnknownClient, UnAuthorizedClient) as err:
            logger.error(err)
            return JsonResponse({
                'error': 'unauthorized_client',
                'error_description': str(err)
            }, status="400")
        except Exception as err:
            logger.error(err)
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': str(err),
            }, status="400")

    def _log_request(self, context, request, msg:str, level:str = 'debug'):
        _msg = f"{msg}: {request}"
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(context.state), message=msg
        )
        getattr(logger, level)(logline)

    def _handle_authn_request(self, context: Context, endpoint):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: satosa.internal.InternalData

        :param context: the current context
        :return: the internal request
        """
        request = urlencode(context.request)
        self._log_request(context, request, "Authn req from client")

        http_info = self._get_http_info(context)
        parse_req = self._parse_request(
            endpoint, context.request, context, http_info=http_info
        )
        proc_req = self._process_request(context, endpoint, parse_req, http_info)
        if isinstance(proc_req, JsonResponse):
            return proc_req

        # TODO - some tests and specialized exceptions here ...
        try:
            info = endpoint.do_response(
                request=context.request, **proc_req
            )
        except Exception as excp:
            # TODO logging and error handling
            # something to be done with the help of unit test

            # this should be for humans if auth code flow
            # and JsonResponse for other flows ...
            self.handle_error(excp=excp)

        # response = info['response']
        context.state[self.name] = {"oidc_request": request}

        client_id = parse_req.get('client_id')
        _client_conf = endpoint.server_get('endpoint_context').cdb[client_id]
        client_name = _client_conf.get("client_name")
        subject_type = _client_conf.get("subject_type", "pairwise")

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

        # TODO - additional filter here?
        # _approved_attributes = self._get_approved_attributes(
                # _claims_supported, authn_req
        # )

        internal_req.attributes = self.converter.to_internal_filter(
            "openid", _claims_supported
        )

        # TODO - have a default backend, otherwise exception here ...
        context.target_backend = self.app.default_target_backend

        context.internal_data = internal_req
        return internal_req

    def handle_authn_request(self, context: Context):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: satosa.response.SeeOther

        :param context: the current context
        :return: HTTP response to the client
        """
        internal_req = self._handle_authn_request(context)
        if not isinstance(internal_req, InternalData):
            return internal_req
        return self.auth_req_callback_func(context, internal_req)

    #@prepare_oidc_endpoint
    def authorization_endpoint(self, context: Context):
        """
        OAuth2 / OIDC Authorization endpoint
        Checks client_id and handles the authorization request
        """
        self._log_request(context, context.request, "Authorization endpoint request")
        self._fill_cdb(context)
        endpoint = self.app.server.endpoint['authorization']
        internal_req = self._handle_authn_request(context, endpoint)
        if not isinstance(internal_req, InternalData):
            return internal_req

        return self.auth_req_callback_func(context, internal_req)

    def _handle_backend_response(self, context, internal_resp):
        """
        Called by handle_authn_response, once a backend made its work
        :type context: satosa.context.Context
        :type internal_res: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: the current context
        :param internal_resp: satosa internal data
        :return: HTTP response to the client
        """
        http_info = self._get_http_info(context)
        oidc_req = context.state[self.name]['oidc_request']
        endpoint = self.app.server.endpoint['authorization']

        # the same of authz_request ...
        # parse_req = self._parse_request(
            # _endpoint, oidc_req, context, http_info
        # )
        parse_req = AuthorizationRequest().from_urlencoded(oidc_req)
        proc_req = self._process_request(context, endpoint, parse_req, http_info)

        if isinstance(proc_req, JsonResponse):
            return proc_req

        client_id = parse_req["client_id"]
        sub = internal_resp.subject_id

        authn_event = create_authn_event(
            uid=sub,
            salt=base64.b64encode(os.urandom(self.app.salt_size)).decode(),
            # TODO
            # authn_info=auth_args['authn_class_ref'],
            # authn_time=auth_args['iat']
        )

        _token_usage_rules = endpoint.server_get(
            "endpoint_context").authn_broker.get_method_by_id('user')

        session_manager = self.app.server.endpoint_context.session_manager
        _session_id = session_manager.create_session(
            authn_event=authn_event,
            auth_req=parse_req,
            user_id=sub,
            client_id=client_id,
            token_usage_rules=_token_usage_rules
        )

        try:
            # _args is a dict that contains:
            #  - oidcmsg.oidc.AuthorizationResponse
            #  - session_id
            #  - cookie (only need for logout -> not yet supported by Satosa)
            _args = endpoint.authz_part2(user=sub,
                                         session_id=_session_id,
                                         request=parse_req,
                                         authn_event=authn_event)
        except ValueError as excp:
            # TODO - cover with unit test and add some satosa logging ...
            return self.handle_error(excp = excp)
        except Exception as excp:
            return self.handle_error(excp = excp)

        if isinstance(_args, ResponseMessage) and 'error' in _args:
            return JsonResponse(_args, status="400")
        elif isinstance(_args.get('response_args'), AuthorizationErrorResponse):
            rargs = _args.get('response_args')
            logger.error(rargs)
            return JsonResponse(rargs.to_json(), status="400")

        info = endpoint.do_response(request=parse_req, **proc_req)
        info_response = info['response']
        _response_placement = info.get(
            'response_placement', endpoint.response_placement
        )
        if _response_placement == 'body':
            # TODO - not yet tested!
            logger.debug(f'Response [Body]: {info_response}')
            resp = Response(info_response)
        elif _response_placement == 'url':
            data = _args['response_args'].to_dict()
            redirect_url = info_response+f'{urlencode(data)}'
            logger.debug(f'Redirect to: {redirect_url}')
            resp = SeeOther(redirect_url)
        else:
            raise NotImplementedError()

        self.load_session_in_db(endpoint)
        return resp

    def handle_authn_response(self, context: Context, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype satosa.response.SeeOther
        """
        claims = self.converter.from_internal("openid", internal_resp.attributes)
        # Filter unset claims - TODO - less code here ...
        claims = {k: v for k, v in claims.items() if v}
        combined_claims = dict(
            [i for i in combine_claim_values(claims.items())]
        )

        response = self._handle_backend_response(context, internal_resp)

        # TODO - why should we have to delete it?
        del context.state[self.name]

        # TODO - session storage
        # self.user_db[internal_resp.subject_id] = dict(combined_claims)
        # ...
        # store user claims for later fetch through userinfo
        # here a session uid as key ...
        with open('/tmp/data.txt', 'w') as outfile:
            json.dump(combined_claims, outfile)

        return response


    def token_endpoint(self, context: Context):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.app.server.endpoint['token']
        http_info = self._get_http_info(context)
        self._log_request(context, context.request, "Token endpoint request")
        self._fill_cdb(context)

        # TODO
        # detect and fill session db (load)
        req_args = self._parse_request(
            endpoint, context.request, context, http_info=http_info
        )

        proc_req = self._process_request(context, endpoint, req_args, http_info)
        if isinstance(proc_req, JsonResponse):
            return proc_req

        # better return jwt or jwe here!
        self.load_session_in_db(endpoint)
        return JsonResponse(proc_req['response_args'])


    def userinfo_endpoint(self, context: Context):
        endpoint = self.app.server.endpoint['userinfo']
        http_info = self._get_http_info(context)
        self._log_request(context, context.request, "Userinfo endpoint request")
        # TODO
        # self._fill_cdb(context)

        # TODO
        # detect and fill session db (load)
        req_args = self._parse_request(
            endpoint, context.request, context, http_info=http_info)

        # here the bearer access token
        # context.request_authorization
        # TODO
        claims = json.loads(open('/tmp/data.txt', 'r').read())

        # runtime definition of userinfo db configuration
        ec = endpoint.server_get('endpoint_context')
        ec.userinfo.load(claims)

        _args = self._process_request(context, endpoint, req_args, http_info)
        # flush as soon as possible, otherwise in case of an exception it would be
        # stored in the object ... until a next .load would happen ...
        ec.userinfo.flush()

        if isinstance(_args, JsonResponse):
            return _args

        # better return jwt or jwe here!
        self.load_session_in_db(endpoint)
        return JsonResponse(_args['response_args'])

    def client_registration_endpoint(self, context: Context):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        raise NotImplementedError()

    def introspection_endpoint(self, context: Context):
        raise NotImplementedError()
