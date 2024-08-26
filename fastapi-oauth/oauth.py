import logging
from typing import Optional
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
import secrets
from urllib import parse
import aiohttp
import base64

from ..models.db import Environ
from ..models.response import TokenResponse
from ..config import Settings

settings=Settings()
router=APIRouter(tags=["oauth"])
logger=logging.getLogger("uvicorn")

authServer = {
	"authorizationEndpoint": settings.OAUTH_AUTH_URL,
	"tokenEndpoint": settings.OAUTH_TOKEN_URL
}

client = {
  "client_id": settings.OAUTH_CLIENT_ID,
  "client_secret": settings.OAUTH_SECRET_ID,
  "redirect_uris": [settings.OAUTH_CALLBACK_URL,],
  "scope": settings.OAUTH_SCOPES
}

@router.get("/", response_class=RedirectResponse, status_code=302)
async def oauth_redirect(request:Request):
    state = secrets.token_urlsafe()
    base_url = authServer["authorizationEndpoint"]
    url_param = parse.urlencode({
        "response_type": "code",
        "scope": client["scope"],
        "client_id": client["client_id"],
        "redirect_uri": client["redirect_uris"][0],
        "state": state
    })
    request.session["state"]=state
    authorize_url = f"{base_url}?{url_param}"
    return RedirectResponse(authorize_url, status_code=302)

@router.get("/callback", response_class=RedirectResponse, status_code=302|400)
async def token_request(request:Request, code: str, state: str, error: str | None = None):

    if error is not None:
        logger.error("OAuth error was reported: %s", error)
        return RedirectResponse(settings.OAUTH_ERROR_URL, status_code=301)
    
    if "state" not in request.session:
        logger.error("cant get state from session token")
        return RedirectResponse(settings.OAUTH_ERROR_URL, status_code=301)
    if state != request.session["state"]:
        logger.error("OAuth state DOES NOT MATCH: %s", request.session["state"])
        return RedirectResponse(settings.OAUTH_ERROR_URL, status_code=301)
    request.session.pop("state")
        
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": client["redirect_uris"][0]
    }
    parsed_tokenurl=parse.urlparse(authServer["tokenEndpoint"])
    headers = {
        "Origin": f'{parsed_tokenurl.scheme}://{parsed_tokenurl.netloc}' if settings.OAUTH_TOKEN_ORIGIN is None else settings.OAUTH_TOKEN_ORIGIN,
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + base64.b64encode(f"{parse.quote(client['client_id'])}:{parse.quote(client['client_secret'])}".encode("utf-8")).decode("utf-8")
    }
    try:
        async with aiohttp.ClientSession(headers=headers, conn_timeout=3, read_timeout=3) as session:
            async with session.post(authServer["tokenEndpoint"], data=body) as token_response:
                if token_response.status != 200:
                    logger.error("OAuth token request error: %s", token_response.status, token_response.status)
                    return RedirectResponse(settings.OAUTH_ERROR_URL, status_code=301)
                res: TokenResponse = await token_response.json()
        environ=await Environ.get_or_none(oauth_uid=res["user_id"])
        if environ is None:
            logger.error("Unknown oauth_uid: %s", res["user_id"])
            return RedirectResponse(settings.OAUTH_ERROR_URL, status_code=301)
        environ.oauth_token=res["access_token"]
        request.session["token"]=res["access_token"]
        await environ.save()
    except:
        logger.exception("OAuth token request exception:")
        return RedirectResponse(settings.OAUTH_ERROR_URL, status_code=301)

    return RedirectResponse(settings.OAUTH_HOME_URL, status_code=302)

@router.get("/session", response_model=Optional[str])
async def session(request:Request):
    if await Environ.exists(oauth_token=request.session.get("token", "")):
        return request.session["token"]
    else:
        return None

@router.post("/logout")
async def logout(request:Request):
    token=request.session.pop("token",None)
    if token is not None:
        environ=await Environ.get_or_none(oauth_token=token)
        if environ is not None:
            environ.oauth_token=None
            await environ.save()
