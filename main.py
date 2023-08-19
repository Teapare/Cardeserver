import os
from repo import Repository
from aiohttp import web
import asyncio
from settings import METADATA_PATH, TARGETS_PATH, REPOSITORY_PATH


async def scream(request):
    return web.Response(text="AAAAAA")


def ensure_dirs_exist():
    if not os.path.exists(REPOSITORY_PATH):
        os.mkdir(REPOSITORY_PATH)
    if not os.path.exists(TARGETS_PATH):
        os.mkdir(TARGETS_PATH)
    if not os.path.exists(METADATA_PATH):
        os.mkdir(METADATA_PATH)


if __name__ == '__main__':
    ensure_dirs_exist()
    repo = Repository()
    repo.initialize()
    app = web.Application()
    app.add_routes([web.static('/metadata', path=METADATA_PATH),
                    web.static('/targets', path=TARGETS_PATH)])

    repo_controller = web.Application()
    repo_controller.add_routes([web.post('/', repo.load_new_version)])

    loop = asyncio.new_event_loop()
    loop.create_task(web._run_app(repo_controller, host='192.168.0.184', port=6006))
    loop.create_task(repo.run())
    web.run_app(app, loop=loop)
