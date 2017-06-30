# Needed for download_remote_config_version request.
import json
import logging
import os

log = logging.getLogger(__name__)

APP_VERSION = 6701

# Needed for get_gym_details request.
API_VERSION = '0.67.1'

DEFAULT_CONFIG_FILE = 'mrmime_config.json'


_mr_mime_cfg = {
    # --- localization
    'player_locale': {                  # Default player locale
        'country': 'US',
        'language': 'en',
        'timezone': 'America/Denver'
    },
    # --- general
    'parallel_logins': True,            # Parallel logins increases number of requests.
    'retry_on_hash_quota_exceeded': True,     # DEPRECATED, use retry_on_hashing_error below!
    'retry_on_hashing_error': True,     # Retry requests on recoverable hash server errors (offline, timeout, quota exceeded)
    # --- account login specific
    'login_retries': 3,                 # Number of login retries
    'login_delay': 6,                   # Delay between login retries
    'full_login_flow': True,            # Whether login flow requests should be performed or not
    'download_assets_and_items': True,  # Whether to perform download_asset_digest and download_item_templates requests at all
    # --- misc requests
    'scan_delay': 10,                   # Wait at least this long between 2 GMO requests
    # --- logging
    'debug_log': False,                 # If MrMime should output debug logging
    'log_file': None                    # If given MrMime also logs into this file
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

    if _mr_mime_cfg['debug_log'] is True:
        logging.getLogger('mrmime').setLevel(logging.DEBUG)

    if _mr_mime_cfg['log_file']:
        file_handler = logging.FileHandler(_mr_mime_cfg['log_file'])
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s [%(levelname)8s] %(message)s'))
        logging.getLogger('mrmime').addHandler(file_handler)
