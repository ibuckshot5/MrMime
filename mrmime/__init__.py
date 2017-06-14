# Needed for download_remote_config_version request.
APP_VERSION = 6304


_mr_mime_cfg = {
    'player_locale': {
        'country': 'US',
        'language': 'en',
        'timezone': 'America/Denver'
    },
    'login_retries': 3,
    'login_delay': 6,
    'scan_delay': 10
}


def init_mr_mime(cfg):
    _mr_mime_cfg.update(cfg)
