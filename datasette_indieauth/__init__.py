from datasette import hookimpl
from datasette.utils.asgi import Response
import httpx
import urllib


async def indieauth(request, datasette):
    client_id = datasette.absolute_url(request, datasette.urls.instance())
    redirect_uri = datasette.absolute_url(request, request.path)

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
            return Response.text(extra, status=403)

    return Response.html(
        await datasette.render_template(
            "indieauth.html",
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            },
            request=request,
        )
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
            return False, "{}: {}".format(response.status_code, response.text)


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
