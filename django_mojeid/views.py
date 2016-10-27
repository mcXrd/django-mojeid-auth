# django-openid-auth -  OpenID integration for django.contrib.auth
#
# Copyright (C) 2013 CZ.NIC
# Copyright (C) 2008-2013 Canonical Ltd.
# Copyright (C) 2007 Simon Willison
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from six.moves.urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template import RequestContext
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView
try:
    from django.views.decorators.csrf import csrf_exempt
except ImportError:
    from django.contrib.csrf.middleware import csrf_exempt

from openid.consumer.consumer import (
    Consumer, SUCCESS, CANCEL, FAILURE)
from openid.consumer.discover import DiscoveryFailure
from openid.extensions import ax

from django_mojeid.mojeid import (
    get_attribute_query,
)

from django_mojeid.store import DjangoOpenIDStore
from django_mojeid.exceptions import (
    DjangoOpenIDException,
)

from django_mojeid import errors


def sanitise_redirect_url(redirect_to):
    """Sanitise the redirection URL."""
    # Light security check -- make sure redirect_to isn't garbage.
    is_valid = True
    if not redirect_to or ' ' in redirect_to:
        is_valid = False
    elif '//' in redirect_to:
        # Allow the redirect URL to be external if it's a permitted domain
        allowed_domains = getattr(settings, "ALLOWED_EXTERNAL_OPENID_REDIRECT_DOMAINS", [])
        s, netloc, p, q, f = urlsplit(redirect_to)
        # allow it if netloc is blank or if the domain is allowed
        if netloc:
            # a domain was specified. Is it an allowed domain?
            if netloc.find(":") != -1:
                netloc, _ = netloc.split(":", 1)
            if netloc not in allowed_domains:
                is_valid = False

    # If the return_to URL is not valid, use the default.
    if not is_valid:
        redirect_to = settings.LOGIN_REDIRECT_URL

    return redirect_to


def make_consumer(request):
    """Create an OpenID Consumer object for the given Django request."""
    # Give the OpenID library its own space in the session object.
    session = request.session.setdefault('OPENID', {})
    store = DjangoOpenIDStore()
    return Consumer(session, store)


def render_openid_request(request, openid_request, return_to, top_url):
    """ Render an OpenID authentication request.
        This request will automatically redirect client to OpenID server.
    """

    # Realm should be always something like 'https://example.org/openid/'
    realm = getattr(settings, 'MOJEID_REALM',
                    request.build_absolute_uri(top_url))

    # Directly redirect to the OpenID server
    if openid_request.shouldSendRedirect():
        redirect_url = openid_request.redirectURL(realm, return_to)
        return HttpResponseRedirect(redirect_url)

    # Render a form wich will redirect the client
    else:
        form_html = openid_request.htmlMarkup(realm, return_to,
                                              form_tag_attrs={'id': 'openid_message'})
        return HttpResponse(form_html, content_type='text/html;charset=UTF-8')


def parse_openid_response(request):
    """Parse an OpenID response from a Django request."""

    current_url = request.build_absolute_uri()

    consumer = make_consumer(request)

    params = dict(request.GET.items())
    params.update(dict(request.POST.items()))
    return consumer.complete(params, current_url)


class MojeIdView(TemplateView):

    def _warning(self, message):
        raise NotImplementedError

    def _render_default_error_response(self):
        raise NotImplementedError

    def _get_attributes(self):
        raise NotImplementedError


class MojeIdCallbackView(MojeIdView):

    def _get_openid_attributes(self, openid_response):
        attributes = [x for x in self._get_attributes() if x.type == 'attribute']
        fetch_response = ax.FetchResponse.fromSuccessResponse(openid_response)

        res = {}
        for attribute in attributes:
            val = attribute.get_value(fetch_response, False)
            res[attribute.modelAttribute] = val
        return res

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(MojeIdCallbackView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
            return self._process_request(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
            return self._process_request(request, *args, **kwargs)

    def _process_mojeid_data(self, openid_attributes):
        raise NotImplementedError

    def _process_request(self, request, *args, **kwargs):
        openid_response = parse_openid_response(request)
        if openid_response and openid_response.status == SUCCESS:
            try:
                return self._process_mojeid_data(self._get_openid_attributes(openid_response))
            except DjangoOpenIDException as e:
                self._warning(errors.AuthenticationFailed(e).msg)
                return self._render_default_error_response()
        else:
            if not openid_response:
                self._warning(errors.EndpointError().msg)
            elif openid_response.status == FAILURE:
                self._warning(errors.OpenIDAuthenticationFailed(openid_response).msg)
            elif openid_response.status == CANCEL:
                self._warning(errors.OpenIDAuthenticationCanceled().msg)
            else:
                self._warning(errors.OpenIDUnknownResponseType(openid_response).msg)
            return self._render_default_error_response()


class MojeIDLoginView(MojeIdView):

    def get(self, request, *args, **kwargs):
        consumer = make_consumer(request)
        try:
            openid_request = consumer.begin(settings.MOJEID_ENDPOINT_URL)
        except DiscoveryFailure as exc:
            self._warning(errors.DiscoveryError(exc).msg)
            return self._render_default_error_response()

        attributes = get_attribute_query(self._get_attributes())
        fetch_request = ax.FetchRequest()
        for attribute, required in attributes:
            fetch_request.add(attribute.generate_ax_attrinfo(required))

        if attributes:
            openid_request.addExtension(fetch_request)

        return render_openid_request(request, openid_request, self._get_return_to(request), self._get_top_url())

    def _get_return_to(self, request):
        return_to = request.build_absolute_uri(self._get_callback_url())
        return_to += '&' if '?' in return_to else '?'
        return_to += urlencode(request.GET)
        return return_to

    def _get_callback_url(self):
        raise NotImplementedError

    def _get_top_url(self):
        raise NotImplementedError


class TopView(TemplateView):

    template_name = 'openid/top.html'

    def get(self, request, *args, **kwargs):
        #url = request.build_absolute_uri(reverse(xrds))
        return render(request, self.template_name, {})
