from datasette import hookimpl
from .utils import (
    build_authorization_url,
    canonicalize_url,
    discover_endpoints,
    display_url,
    verify_profile_url,
)
import httpx
import itsdangerous
from jinja2 import escape
import json
import urllib

DATASETTE_INDIEAUTH_STATE = "datasette-indieauth-state"
DATASETTE_INDIEAUTH_COOKIE = "datasette-indieauth-cookie"


async def indieauth(request, datasette):
    return await indieauth_page(request, datasette)


async def indieauth_page(request, datasette, status=200, error=None):
    from datasette.utils.asgi import Response

    urls = Urls(request, datasette)

    if request.method == "POST":
        post = await request.post_vars()
        me = post.get("me")
        if me:
            me = canonicalize_url(me)

        if not me or not verify_profile_url(me):
            datasette.add_message(
                request, "Invalid IndieAuth identifier", message_type=datasette.ERROR
            )
            return Response.redirect(urls.login)

        # Start the auth process
        authorization_endpoint, token_endpoint = await discover_endpoints(me)
        if not authorization_endpoint:
            # Redirect to IndieAuth.com as a fallback
            # TODO: Only do this if rel=me detected
            # TODO: make this a configurable preference
            indieauth_url = "https://indieauth.com/auth?" + urllib.parse.urlencode(
                {
                    "me": me,
                    "client_id": urls.client_id,
                    "redirect_uri": urls.indie_auth_com_redirect_uri,
                }
            )
            return Response.redirect(indieauth_url)
        else:
            authorization_url, state, verifier = build_authorization_url(
                authorization_endpoint=authorization_endpoint,
                client_id=urls.client_id,
                redirect_uri=urls.redirect_uri,
                me=me,
                signing_function=lambda x: datasette.sign(x, DATASETTE_INDIEAUTH_STATE),
            )
            response = Response.redirect(authorization_url)
            response.set_cookie(
                "ds_indieauth",
                datasette.sign(
                    {
                        "v": verifier,
                    },
                    DATASETTE_INDIEAUTH_COOKIE,
                ),
            )
            return response

    return Response.html(
        await datasette.render_template(
            "indieauth.html",
            {
                "error": error,
                "title": datasette.metadata("title") or "Datasette",
                "absolute_instance_url": datasette.absolute_url(
                    request, datasette.urls.instance()
                ),
            },
            request=request,
        ),
        status=status,
    )


async def indieauth_done(request, datasette):
    from datasette.utils.asgi import Response

    state = request.args.get("state") or ""
    code = request.args.get("code")
    try:
        state_bits = datasette.unsign(state, DATASETTE_INDIEAUTH_STATE)
    except itsdangerous.BadSignature:
        return await indieauth_page(
            request, datasette, error="Invalid state", status=400
        )
    authorization_endpoint = state_bits["a"]

    urls = Urls(request, datasette)

    # code_verifier should be in a signed cookie
    code_verifier = None
    if "ds_indieauth" in request.cookies:
        try:
            cookie_bits = datasette.unsign(
                request.cookies["ds_indieauth"], DATASETTE_INDIEAUTH_COOKIE
            )
            code_verifier = cookie_bits["v"]
        except itsdangerous.BadSignature:
            pass
    if not code_verifier:
        return await indieauth_page(
            request, datasette, error="Invalid ds_indieauth cookie"
        )

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": urls.client_id,
        "redirect_uri": urls.redirect_uri,
        "code_verifier": code_verifier,
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(authorization_endpoint, data=data)

    if response.status_code == 200:
        body = response.text
        try:
            info = json.loads(body)
        except ValueError:
            info = dict(urllib.parse.parse_qsl(body))
        if "me" not in info:
            return await indieauth_page(
                request,
                datasette,
                error="Invalid authorization_code response from authorization server",
            )
        me = info["me"]
        actor = {
            "me": me,
            "display": display_url(me),
        }
        if "scope" in info:
            actor["indieauth_scope"] = info["scope"]

        if "profile" in info and isinstance(info["profile"], dict):
            actor.update(info["profile"])
        response = Response.redirect(datasette.urls.instance())
        response.set_cookie(
            "ds_actor",
            datasette.sign(
                {"a": actor},
                "actor",
            ),
        )
        return response
    else:
        return await indieauth_page(
            request,
            datasette,
            error="Invalid authorization_code response from authorization server",
        )


async def indieauth_com_done(request, datasette):
    from datasette.utils.asgi import Response

    urls = Urls(request, datasette)

    if not (request.args.get("code") and request.args.get("me")):
        return Response.html("?code= and ?me= are required")
    ok, extra = await verify_indieauth_com_code(
        request.args["code"], urls.client_id, urls.indie_auth_com_redirect_uri
    )
    if ok:
        response = Response.redirect(datasette.urls.instance())
        response.set_cookie(
            "ds_actor",
            datasette.sign(
                {
                    "a": {
                        "me": extra,
                        "display": display_url(extra),
                    }
                },
                "actor",
            ),
        )
        return response
    else:
        return Response.html(escape(extra), status=403)


class Urls:
    def __init__(self, request, datasette):
        self.request = request
        self.datasette = datasette

    def absolute(self, path):
        return self.datasette.absolute_url(self.request, self.datasette.urls.path(path))

    @property
    def login(self):
        return self.absolute("/-/indieauth")

    @property
    def client_id(self):
        return self.login

    @property
    def redirect_uri(self):
        return self.absolute("/-/indieauth/done")

    @property
    def indie_auth_com_redirect_uri(self):
        return self.absolute("/-/indieauth/indieauth-com-done")


async def verify_indieauth_com_code(code, client_id, redirect_uri):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://indieauth.com/auth",
            data={
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            },
        )
        if response.status_code == 200:
            # me=https%3A%2F%2Fsimonwillison.net%2F&scope
            bits = dict(urllib.parse.parse_qsl(response.text))
            if "me" in bits:
                return True, bits["me"]
            else:
                return False, "Server did not return me="
        else:
            bits = dict(urllib.parse.parse_qsl(response.text))
            return False, bits.get("error_description") or "{} error".format(
                response.status_code
            )


@hookimpl
def register_routes():
    return [
        (r"^/-/indieauth$", indieauth),
        (r"^/-/indieauth/done$", indieauth_done),
        (r"^/-/indieauth/indieauth-com-done$", indieauth_com_done),
    ]


@hookimpl
def menu_links(datasette, actor):
    if not actor:
        return [
            {
                "href": datasette.urls.path("/-/indieauth"),
                "label": "Sign in IndieAuth",
            },
        ]


@hookimpl
def permission_allowed(datasette, actor, action):
    if action != "view-instance":
        return None
    plugin_config = datasette.plugin_config("datasette-indieauth") or {}
    if plugin_config.get("restrict_access") is None:
        return None
    # Only actors in the list are allowed
    if not actor:
        return False
    allowed_actors = plugin_config["restrict_access"]
    if isinstance(allowed_actors, str):
        allowed_actors = allowed_actors.split()
    return actor.get("me") in allowed_actors


@hookimpl
def forbidden(request, datasette):
    async def inner():
        return await indieauth_page(request, datasette, 403)

    return inner
