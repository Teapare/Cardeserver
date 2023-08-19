import asyncio

import aiohttp.web

from settings import METADATA_PATH, KEY_PATH, EXPIRY_MAP, TARGETS_PATH
import os
from datetime import datetime, timedelta
from typing import Dict

from securesystemslib.signer import SSlibKey, SSlibSigner
from securesystemslib.interface import generate_and_write_ed25519_keypair, import_ed25519_privatekey_from_file
from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer, JSONDeserializer


def _in(days: float) -> datetime:
    """Adds 'days' to now and returns datetime object w/o microseconds."""
    return datetime.utcnow().replace(microsecond=0) + timedelta(days=days)


class Repository:
    def __init__(self):
        self.roles: Dict[str: Metadata] = {}
        self.key = None
        self.signer: SSlibSigner | None = None
        self.changed = {'root': False, 'targets': False, 'snapshot': False, 'timestamp': False}
        self.serializer = JSONSerializer()
        self.deserializer = JSONDeserializer()

    async def load_new_version(self, request: aiohttp.web.Request):
        for file in os.listdir(TARGETS_PATH):
            os.remove(TARGETS_PATH / file)
        reader = await request.multipart()
        while True:
            part = await reader.next()
            if part is None:
                break
            with open(TARGETS_PATH / f"{part.name}", 'wb') as file:
                file.write(await part.read())
        self.resign_targets(True)
        return aiohttp.web.Response(text="received...")

    def init_repo(self):
        for metadata in os.listdir(METADATA_PATH):
            os.remove(METADATA_PATH / metadata)
        generate_and_write_ed25519_keypair(password='ga>*{0ZyS}LYT(9V9U', filepath=str(KEY_PATH))
        key = import_ed25519_privatekey_from_file(str(KEY_PATH), password='ga>*{0ZyS}LYT(9V9U')
        signer = SSlibSigner(key)
        roles: Dict[str, Metadata] = {
            'root': Metadata(
                Root(
                    expires=_in(EXPIRY_MAP['root']),
                    consistent_snapshot=False
                )
            ),
            'targets': Metadata(
                Targets(expires=_in(EXPIRY_MAP['targets']))
            ),
            'snapshot': Metadata(
                Snapshot(expires=_in(EXPIRY_MAP['snapshot']))
            ),
            'timestamp': Metadata(
                Timestamp(expires=_in(EXPIRY_MAP['timestamp']))
            )
        }
        for role in roles.keys():
            roles['root'].signed.add_key(SSlibKey.from_securesystemslib_key(key), role)

        for target in os.listdir(TARGETS_PATH):
            roles['targets'].signed.targets[target] = TargetFile.from_file(target, str(TARGETS_PATH / target))
        roles['root'].sign(signer)
        roles['root'].to_file(str(METADATA_PATH / "1.root.json"), self.serializer)
        roles['targets'].sign(signer)
        roles['targets'].to_file(str(METADATA_PATH / 'targets.json'), self.serializer)
        roles['snapshot'].sign(signer)
        roles['snapshot'].to_file(str(METADATA_PATH / "snapshot.json"), self.serializer)
        roles['timestamp'].sign(signer)
        roles['timestamp'].to_file(str(METADATA_PATH / 'timestamp.json'), self.serializer)
        return key, roles

    def load_repo(self):
        roles: Dict[str, Metadata] = {}
        root_path = ''
        for metadata_file in os.listdir(METADATA_PATH):
            if '.root.json' in metadata_file:
                root_path = metadata_file if (
                        not root_path or int(root_path.split('.')[0]) < int(metadata_file.split('.')[0])) else root_path
        roles['root'] = Metadata.from_file(str(METADATA_PATH / root_path), self.deserializer)
        key = import_ed25519_privatekey_from_file(str(KEY_PATH), 'ga>*{0ZyS}LYT(9V9U')
        roles["targets"] = Metadata.from_file((str(METADATA_PATH / 'targets.json')), self.deserializer)
        roles["snapshot"] = Metadata.from_file((str(METADATA_PATH / 'snapshot.json')), self.deserializer)
        roles["timestamp"] = Metadata.from_file((str(METADATA_PATH / 'timestamp.json')), self.deserializer)
        return key, roles

    def initialize(self):

        if not os.path.exists(KEY_PATH):
            self.key, self.roles = self.init_repo()
        else:
            self.key, self.roles = self.load_repo()

        self.signer = SSlibSigner(self.key)

    def resign_timestamp(self):
        self.roles['timestamp'].signatures.clear()
        self.roles['timestamp'].signed.expires = _in(EXPIRY_MAP['timestamp'])
        self.roles['timestamp'].signed.version += 1
        self.roles['timestamp'].signed.snapshot_meta.version = self.roles['snapshot'].signed.version
        self.roles['timestamp'].sign(self.signer)
        self.changed['timestamp'] = True

    def resign_snapshot(self):
        self.roles['snapshot'].signatures.clear()
        self.roles['snapshot'].signed.expires = _in(EXPIRY_MAP['snapshot'])
        self.roles['snapshot'].signed.version += 1
        self.roles['snapshot'].signed.meta["targets.json"].version = self.roles['targets'].signed.version
        self.roles['snapshot'].sign(self.signer)
        self.changed['snapshot'] = True
        self.resign_timestamp()

    def resign_targets(self, new_targets=False):
        if new_targets:
            self.roles['targets'].signed.targets.clear()
            for target in os.listdir(TARGETS_PATH):
                self.roles['targets'].signed.targets[target] = TargetFile.from_file(target, str(TARGETS_PATH / target))
        self.roles['targets'].signatures.clear()
        self.roles['targets'].signed.expires = _in(EXPIRY_MAP['targets'])
        self.roles['targets'].signed.version += 1
        self.roles['targets'].sign(self.signer)
        self.changed['targets'] = True
        self.resign_snapshot()

    def resign_root(self, new_key=None):
        self.roles['root'].signed.expires = _in(EXPIRY_MAP['root'])
        self.roles['root'].signatures.clear()
        self.roles['root'].signed.version += 1
        if new_key:
            self.roles['root'].signed.revoke_key(self.key, 'root')
            self.roles['root'].signed.revoke_key(self.key, 'targets')
            self.roles['root'].signed.revoke_key(self.key, 'snapshot')
            self.roles['root'].signed.revoke_key(self.key, 'timestamp')
            self.roles['root'].signed.add_key(new_key, 'root')
            self.roles['root'].signed.add_key(new_key, 'targets')
            self.roles['root'].signed.add_key(new_key, 'snapshot')
            self.roles['root'].signed.add_key(new_key, 'timestamp')
        self.roles['root'].sign(self.signer)
        self.changed['root'] = True
        if new_key:
            self.key = new_key
            self.signer = SSlibSigner(new_key)
            self.roles['root'].sign(self.signer)
            self.resign_targets()

    async def run(self):
        while True:
            if self.roles['root'].signed.is_expired():
                self.resign_root()
            elif self.roles['targets'].signed.is_expired():
                self.resign_targets()
            elif self.roles['snapshot'].signed.is_expired():
                self.resign_snapshot()
            elif self.roles['timestamp'].signed.is_expired():
                self.resign_timestamp()
            if self.changed['root']:
                self.roles['root'].to_file(str(METADATA_PATH / f"{self.roles['root'].signed.version}.root.json"),
                                           self.serializer)
            for name in ['targets', 'snapshot', 'timestamp']:
                if self.changed[name]:
                    self.roles[name].to_file(str(METADATA_PATH / f"{name}.json"), self.serializer)
            await asyncio.sleep(10)
