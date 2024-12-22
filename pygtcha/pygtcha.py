"""
Serve simple opinionated captcha, and set auth cookie accordingly.
"""

import base64
import dataclasses
import hashlib
import importlib.resources
import logging
import os
import random
from collections import defaultdict
from enum import Enum
from io import BytesIO
from pathlib import PosixPath
from typing import cast

import aiohttp
import aiohttp.web
import yaml  # type: ignore
from jinja2 import Environment, PackageLoader, select_autoescape
from PIL import Image

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

PIGS = ["porcs.yml", "bouffons.yml", "quiches.yml", "poobag.yml"]


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


class Pygtcha(aiohttp.web.View):

    async def get(self):
        """Main handler"""
        logger.debug("Getting pygtcha")
        j2env = self.request.app["j2env"]
        template = j2env.get_template("pygtcha.html.j2")
        pig_selector = self.request.app["selector"]
        collection, pigs = pig_selector.select(4)
        res = template.render(collection=collection, pigs=pigs)
        return aiohttp.web.Response(text=res, content_type="text/html")

    async def post(self):
        """Main handler"""
        post_data = await self.request.post()
        pygtcha_cookie_name = post_data.get("pygtcha-cookie-name")
        category = post_data.get("category")
        pig = post_data.get("selected")
        logger.debug(f"Validating {pygtcha_cookie_name}={pig}")
        pig_selector = self.request.app["selector"]
        if pig_selector.is_evil(category, pig):
            logger.debug("Ok, access granted")
            h = hashlib.new("sha1")
            h.update(self.request.app["salt"].encode("utf8"))
            h.update(self.request.remote.encode("utf8"))
            res = aiohttp.web.Response(text=f"Ok {pig}")
            res.set_cookie(pygtcha_cookie_name, h.hexdigest())
        else:
            logger.debug("Ko, access refused")
            res = aiohttp.web.Response(text=f"Ko {pig}")
            res.del_cookie(pygtcha_cookie_name)
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
    _app.add_routes([aiohttp.web.view("/", Pygtcha)])
    _app.router.add_static("/static", "pygtcha/static")
    _app["salt"] = os.environ.get("PYGTCHA_SALT")
    _app["j2env"] = Environment(
        loader=PackageLoader("pygtcha"), autoescape=select_autoescape()
    )
    if _app["salt"] is None:
        raise ValueError("Environment variable PYGTCHA_SALT is not defined")
    _app["selector"] = PigSelector()

    return _app
