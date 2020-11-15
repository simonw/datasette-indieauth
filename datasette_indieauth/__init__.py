from datasette import hookimpl
from datasette.utils.asgi import Response
import httpx
import urllib


async def indieauth(request, datasette):
    return await indieauth_page(request, datasette)


async def indieauth_page(request, datasette, initial_status=200):
    client_id = datasette.absolute_url(request, datasette.urls.instance())
    redirect_uri = datasette.absolute_url(request, request.path)

    error = None
    status = initial_status

    if request.args.get("code") and request.args.get("me"):
        ok, extra = await verify_code(request.args["code"], client_id, redirect_uri)
        if ok:
            response = Response.redirect(datasette.urls.instance())
            response.set_cookie(
                "ds_actor",
                datasette.sign(
                    {
                        "a": {
                            "me": extra,
                            "display": extra,
                        }
                    },
                    "actor",
                ),
            )
            return response
        else:
            error = extra
            status = 403

    return Response.html(
        await datasette.render_template(
            "indieauth.html",
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "error": error,
            },
            request=request,
        ),
        status=status,
    )


async def verify_code(code, client_id, redirect_uri):
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
