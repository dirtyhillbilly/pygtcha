"""
Serve simple opinionated captcha, and set auth cookie accordingly.
"""

import base64
import dataclasses
import importlib.resources
import logging
import os
import random
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from io import BytesIO
from pathlib import PosixPath
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
SECRET = "asdcdsfv"
COOKIE_NAME = "pygtcha"


class Alignment(Enum):
    GOOD = "good"
    EVIL = "evil"


def _png_to_b64(path: PosixPath) -> str:
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


def _load_thumbnail(path: PosixPath, dx: int, dy: int, radius: int) -> str:
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
    img: PosixPath
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


class PygtchaVerify(aiohttp.web.View):

    async def get(self):
        """Main handler"""

        cookie = self.request.cookies.get(COOKIE_NAME)
        logger.debug(self.request.headers)
        authenticator = self.request.headers["pygtcha-url"]
        proto = self.request.headers["X-Forwarded-Proto"]
        domain = self.request.headers["X-Forwarded-Host"]
        path = self.request.headers["X-Forwarded-Uri"]
        redirect_url = urllib.parse.quote_plus(f"{proto}://{domain}{path}")
        if cookie:
            try:
                jwt.decode(cookie, SECRET, algorithms="HS256")
            except jwt.PyJWTError:
                # will redirect
                pass
            else:
                raise aiohttp.web.HTTPOk

        # redirect to captcha page
        res = aiohttp.web.HTTPFound(authenticator)
        res.set_cookie(f"{COOKIE_NAME}-redirect", redirect_url, samesite="None")
        return res


class PygtchaAuth(aiohttp.web.View):

    async def get(self):
        """Main handler"""
        logger.debug("Getting pygtcha")
        j2env = self.request.app["j2env"]
        template = j2env.get_template("pygtcha.html.j2")
        pig_selector = self.request.app["selector"]
        redirect_url = self.request.cookies.get(f"{COOKIE_NAME}-redirect")
        # redirect_url = self.request.query.get("redirect_url")
        collection, pigs = pig_selector.select(5)
        res = template.render(
            collection=collection, pigs=pigs, redirect_url=redirect_url
        )
        res = aiohttp.web.Response(text=res, content_type="text/html")
        return res

    @staticmethod
    def jwt_payload():
        now = datetime.now(tz=timezone.utc)
        exp = now + timedelta(days=365)
        nbf = now - timedelta(seconds=20)
        return {"iat": now, "exp": exp, "nbf": nbf}

    async def post(self):
        """Main handler"""
        post_data = await self.request.post()
        category = post_data.get("category")
        pig = post_data.get("selected")
        redirect_url = urllib.parse.unquote_plus(post_data.get("redirect"))
        logger.debug(f"Validating {COOKIE_NAME}={pig}")
        pig_selector = self.request.app["selector"]
        if pig_selector.is_evil(category, pig):
            logger.debug("Ok, access granted")
            cookie = jwt.encode(self.jwt_payload(), SECRET)
            res = aiohttp.web.HTTPFound(redirect_url)
            res.set_cookie(COOKIE_NAME, cookie, samesite="None")
            res.del_cookie(f"{COOKIE_NAME}-redirect")
        else:
            logger.debug("Ko, access refused")
            retry = self.request.app.router["auth"].url_for()
            res = aiohttp.web.HTTPFound(retry)
            res.del_cookie(COOKIE_NAME)
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


async def app():
    _app = aiohttp.web.Application()
    _app.add_routes(
        [
            aiohttp.web.view("/verify", PygtchaVerify, name="verify"),
            aiohttp.web.view("/auth", PygtchaAuth, name="auth"),
        ]
    )
    _app.router.add_static("/static", "pygtcha/static")
    _app["salt"] = os.environ.get("PYGTCHA_SALT")
    _app["j2env"] = Environment(
        loader=PackageLoader("pygtcha"), autoescape=select_autoescape()
    )
    if _app["salt"] is None:
        raise ValueError("Environment variable PYGTCHA_SALT is not defined")
    _app["selector"] = PigSelector()

    return _app
