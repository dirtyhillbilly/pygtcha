"""
Serve simple opinionated captcha, and set auth cookie accordingly.
"""

import asyncio
import base64
import dataclasses
import functools
import importlib.resources
import logging
import os
import random
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import cast
from uuid import uuid4

import aiohttp
import aiohttp.web
import jwt
import yaml  # type: ignore
from jinja2 import Environment, PackageLoader, select_autoescape
from PIL import Image

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

PIGS = ["porcs.yml", "bouffons.yml", "quiches.yml", "poobag.yml"]


class Alignment(Enum):
    GOOD = "good"
    EVIL = "evil"


def _png_to_b64(path: Path) -> str:
    assert path.suffix == ".png"
    with path.open("rb") as imgfile:
        res = base64.b64encode(imgfile.read())
    return res.decode()


def _crop(
    box: tuple[float, float, float, float], size: tuple[float, float]
) -> tuple[float, float, float, float]:
    dx, dy, dX, dY = box
    width, height = size
    dx = min(width, max(0, dx))
    dy = min(height, max(0, dy))
    dX = min(width, max(0, dX))
    dY = min(height, max(0, dY))
    return (dx, dy, dX, dY)


def _load_thumbnail(path: Path, dx: int, dy: int, radius: int) -> str:
    output = BytesIO()
    with Image.open(path) as image:
        box = _crop(
            (dx - radius / 2, dy - radius / 2, dx + radius / 2, dy + radius / 2),
            (image.width, image.height),
        )
        thumb = image.resize(size=(128, 128), box=box)
        thumb.save(output, format="png")
    res = base64.b64encode(output.getvalue())
    return res.decode()


@dataclasses.dataclass
class Pig:
    name: str
    uuid: str
    align: Alignment
    desc: str
    img: Path
    miniature: tuple[int, int, int] | None
    links: list[tuple[str, str]] | None = None
    img_data: str = dataclasses.field(init=False)
    thumbnail: str = dataclasses.field(init=False)

    def __post_init__(self):
        self.img_data = _png_to_b64(self.img)
        if self.miniature is not None:
            self.thumbnail = _load_thumbnail(self.img, *self.miniature)


@dataclasses.dataclass
class PigCollection:
    category: str
    title: str
    img_dir: str
    pigs: dict[str, Pig] = dataclasses.field(default_factory=dict)
    good: list[Pig] = dataclasses.field(default_factory=list)
    evil: list[Pig] = dataclasses.field(default_factory=list)

    def add(self, pig: Pig):
        self.pigs[pig.name] = pig
        if pig.align == Alignment.GOOD:
            self.good.append(pig)
        elif pig.align == Alignment.EVIL:
            self.evil.append(pig)


def jwt_payload(ttl=None):
    if ttl is None:
        expiration = {"days": 365}
    else:
        expiration = {"seconds": ttl}

    now = datetime.now(tz=timezone.utc)
    exp = now + timedelta(**expiration)
    nbf = now - timedelta(seconds=1)
    return {"iat": now, "exp": exp, "nbf": nbf}


def temporize(func):
    @functools.wraps(func)
    async def wrapped(self):
        try:
            res = await func(self)
        except aiohttp.web.HTTPOk:
            logger.debug("Ok")
            raise
        else:
            await asyncio.sleep(0.5)
        return res

    return wrapped


class PygtchaVerify(aiohttp.web.View):

    @temporize
    async def get(self):
        """Main handler"""
        config = self.request.app["config"]
        cookie = self.request.cookies.get(config.cookie_name)
        # logger.debug(self.request.headers)
        if cookie:
            try:
                jwt.decode(cookie, config.secret, algorithms="HS256")
            except jwt.PyJWTError:
                # will redirect
                pass
            else:
                raise aiohttp.web.HTTPOk

        # build redirection to captcha page

        proto = self.request.headers.get("X-Forwarded-Proto")
        domain = self.request.headers.get("X-Forwarded-Host")
        path = self.request.headers.get("X-Forwarded-Uri")
        redirect_url = f"{proto}://{domain}{path}"

        authenticator = self.request.headers.get("pygtcha-url", redirect_url)

        res = aiohttp.web.HTTPFound(authenticator)
        payload = jwt_payload(ttl=600)

        payload["redirect_url"] = redirect_url
        payload["domain"] = domain
        payload["csrf"] = uuid4().hex

        jwt_cookie = jwt.encode(payload, config.secret)
        res.set_cookie(f"{config.cookie_name}-redirect", jwt_cookie, samesite="None")
        return res


class PygtchaAuth(aiohttp.web.View):

    @temporize
    async def get(self):
        """Main handler"""
        logger.debug("Getting pygtcha")
        config = self.request.app["config"]
        j2env = self.request.app["j2env"]
        template = j2env.get_template("pygtcha.html.j2")
        pig_selector = self.request.app["selector"]
        jwt_cookie = self.request.cookies.get(f"{config.cookie_name}-redirect", "")

        try:
            redirect = jwt.decode(jwt_cookie, config.secret, algorithms="HS256")
            if len(redirect.get("csrf", "")) != 32:
                logger.debug("Invalid CSRF")
                raise ValueError
        except (jwt.PyJWTError, ValueError) as exc:
            # invalid redirect cookie : get back to /verify
            logger.error(f"Can't validate token [{jwt_cookie}]: {exc}")
            retry = self.request.app.router["verify"].url_for()
            res = aiohttp.web.HTTPFound(retry)
            res.del_cookie(f"{config.cookie_name}-redirect")
            return res

        redirect_url = redirect.get("redirect_url")
        collection, pigs = pig_selector.select(5)
        res = template.render(
            collection=collection, pigs=pigs, redirect_url=redirect_url
        )
        res = aiohttp.web.Response(text=res, content_type="text/html")
        return res

    @temporize
    async def post(self):
        """Main handler"""
        config = self.request.app["config"]
        post_data = await self.request.post()
        category = post_data.get("category")
        pig = post_data.get("selected")
        redirect_url = urllib.parse.unquote_plus(post_data.get("redirect", ""))
        logger.debug(f"Validating {config.cookie_name}={pig}")
        pig_selector = self.request.app["selector"]
        if pig_selector.is_evil(category, pig):
            logger.debug("Ok, access granted")
            cookie = jwt.encode(jwt_payload(), config.secret)
            res = aiohttp.web.HTTPFound(redirect_url)
            res.set_cookie(config.cookie_name, cookie, samesite="None")
            res.del_cookie(f"{config.cookie_name}-redirect")
        else:
            logger.debug("Ko, access refused")
            retry = self.request.app.router["auth"].url_for()
            res = aiohttp.web.HTTPFound(retry)
            res.del_cookie(config.cookie_name)
        return res


class PigSelector:
    def __init__(self):
        self.collection = defaultdict()
        for yaml_def in PIGS:
            self.load_pigs(yaml_def)

    def select(self, count=6) -> tuple[PigCollection, list[Pig]]:
        collections = list(self.collection)
        category = random.sample(
            collections,
            1,
            counts=[len(self.collection[col].pigs) for col in collections],
        )[0]
        collection = self.collection[category]
        pigs = random.sample(collection.good, count - 1) + [
            random.choice(collection.evil)
        ]
        random.shuffle(pigs)
        return collection, pigs

    def is_evil(self, category, name):
        return (
            category in self.collection
            and name in self.collection[category].pigs
            and self.collection[category].pigs[name].align == Alignment.EVIL
        )

    def load_pigs(self, filename: str):
        ref = importlib.resources.files("pygtcha") / "data" / filename
        header, pigs = yaml.load_all(ref.read_bytes(), yaml.SafeLoader)
        category = header["category"]
        self.collection[category] = PigCollection(
            category, header["title"], header["img_dir"]
        )

        for name, pig in pigs.items():
            if "links" in pig:
                links = [(name, url) for name, url in pig["links"].items()]
            else:
                links = []
            if "miniature" in pig:
                miniature = cast(
                    tuple[int, int, int],
                    tuple(map(int, pig["miniature"].split(","))),
                )
            else:
                miniature = None
            self.collection[category].add(
                Pig(
                    name,
                    uuid4().hex,
                    Alignment(pig["alignment"]),
                    pig["description"],
                    importlib.resources.files("pygtcha")
                    / "static"
                    / header["img_dir"]
                    / pig["img"],
                    miniature,
                    links,
                )
            )


@dataclasses.dataclass
class Config:
    secret: str
    cookie_name: str
    url: str


def load_config(conffile: str = "/etc/pygtcha.yml"):
    with open(conffile, "r") as f:
        config = yaml.safe_load(f)

    return Config(
        secret=config.get("secret", uuid4().hex),
        cookie_name=config.get("cookie_name", "pygtcha"),
        url=config.get("url"),
    )


async def app():
    _app = aiohttp.web.Application()
    _app.add_routes(
        [
            aiohttp.web.view("/verify", PygtchaVerify, name="verify"),
            aiohttp.web.view("/auth", PygtchaAuth, name="auth"),
        ]
    )
    source_path = Path(__file__).resolve().parent
    _app.router.add_static("/static", source_path / "static")
    _app["config"] = load_config(os.environ.get("PYGTCHA_CONFIG"))
    _app["j2env"] = Environment(
        loader=PackageLoader("pygtcha"), autoescape=select_autoescape()
    )
    _app["selector"] = PigSelector()

    return _app
