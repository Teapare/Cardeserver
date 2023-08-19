import pathlib

REPOSITORY_PATH = pathlib.Path('repo')

METADATA_PATH = REPOSITORY_PATH / 'metadata'
TARGETS_PATH = REPOSITORY_PATH / 'targets'
KEY_PATH = REPOSITORY_PATH / 'key'

DATABASE_PATH = REPOSITORY_PATH / 'database'
IMAGES_PATH = DATABASE_PATH / 'images'

EXPIRY_MAP = {"root": 365, "targets": 30, "snapshot": 30, "timestamp": 1}
