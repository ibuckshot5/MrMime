# Needed for download_remote_config_version request.
import json
import os

import logging

APP_VERSION = 6304

# Needed for get_gym_details request.
API_VERSION = '0.63.1'

DEFAULT_CONFIG_FILE = 'mrmime_config.json'

log = logging.getLogger(__name__)

_mr_mime_cfg = {
    'player_locale': {                  # Default player locale
        'country': 'US',
        'language': 'en',
        'timezone': 'America/Denver'
    },
    'parallel_logins': True,            # Parallel logins increases number of requests.
    'login_retries': 3,                 # Number of login retries
    'login_delay': 6,                   # Delay between login retries
    'full_login_flow': True,            # Whether login flow requests should be performed or not
    'scan_delay': 10                    # Wait at least this long between 2 GMO requests
}

# ---------------------------------------------------------------------------


def init_mr_mime(user_cfg=None, config_file=DEFAULT_CONFIG_FILE):
    if os.path.isfile(config_file):
        with open(config_file, 'r') as f:
            try:
                file_cfg = json.loads(f.read())
                log.info("Loading config from {}.".format(config_file))
                _mr_mime_cfg.update(file_cfg)
            except:
                log.error("Could not load config from {}."
                          " Is it proper JSON?".format(config_file))

    if user_cfg:
        log.info("Applying user configuration.")
        _mr_mime_cfg.update(user_cfg)
