import hashlib
import logging
import math
import random
import time

import geopy
from pgoapi import PGoApi
from pgoapi.exceptions import AuthException, PgoapiError, \
    BannedAccountException
from pgoapi.protos.pogoprotos.inventory.item.item_id_pb2 import *

from mrmime import _mr_mime_cfg, APP_VERSION, avatar

log = logging.getLogger(__name__)


class POGOAccount(object):

    def __init__(self, auth_service, username, password, hash_key=None, proxy_url=None):
        self.auth_service = auth_service
        self.username = username
        self.password = password
        self.hash_key = hash_key
        self.proxy_url = proxy_url

        self.cfg = _mr_mime_cfg.copy()

        # Tutorial state and warn/ban flags
        self.player_state = {}

        # Trainer statistics
        self.player_stats = {}

        self.captcha_url = None

        # Inventory information
        self.inventory = None
        self.inventory_balls = 0
        self.inventory_total = 0

        # Last log message (for GUI/console)
        self.last_msg = ""

        # --- private fields

        self._api = PGoApi(device_info=self._generate_device_info())
        self._download_settings_hash = None
        self._asset_time = 0
        self._item_templates_time = 0

        # Timestamp when last API request was made
        self._last_request = None

        # Timestamp for incremental inventory updates
        self._last_timestamp_ms = None

    def set_position(self, lat, lng, alt):
        self._api.set_position(lat, lng, alt)

    def perform_request(self, add_main_request, download_settings=False,
                        buddy_walked=True, action=None):
        request = self._api.create_request()
        add_main_request(request)
        request.check_challenge()
        request.get_hatched_eggs()
        if self._last_timestamp_ms:
            request.get_inventory(last_timestamp_ms=self._last_timestamp_ms)
        else:
            request.get_inventory()
        request.check_awarded_badges()
        # Optional requests
        if download_settings:
            if self._download_settings_hash:
                request.download_settings(hash=self._download_settings_hash)
            else:
                request.download_settings()
        if buddy_walked:
            request.get_buddy_walked()

        return self._call_request(request)

    # Use API to check the login status, and retry the login if possible.
    def check_login(self):
        # Check auth ticket
        if self._api.get_auth_provider() and self._api.get_auth_provider().check_ticket():
            return True

        # Set proxy if given.
        if self.proxy_url:
            self._api.set_proxy({
                'http': self.proxy_url,
                'https': self.proxy_url
            })
            self.log_info("Using proxy: {}".format(self.proxy_url))

        # Try to login. Repeat a few times, but don't get stuck here.
        num_tries = 0
        # One initial try + login_retries.
        while num_tries < self.cfg['login_retries']:
            try:
                num_tries += 1
                self.log_info("Login try {}.".format(num_tries))
                if self.proxy_url:
                    self._api.set_authentication(
                        provider=self.auth_service,
                        username=self.username,
                        password=self.password,
                        proxy_config={
                            'http': self.proxy_url,
                            'https': self.proxy_url
                        })
                else:
                    self._api.set_authentication(
                        provider=self.auth_service,
                        username=self.username,
                        password=self.password)
                self.log_info("Login successful after {} tries.".format(num_tries))
                break
            except AuthException:
                self.log_error(
                    'Failed to login. Trying again in {} seconds.'.format(
                        self.cfg['login_delay']))
                time.sleep(self.cfg['login_delay'])

        if num_tries >= self.cfg['login_retries']:
            self.log_error(
                'Failed to login in {} tries. Giving up.'.format(num_tries))
            return False

        try:
            return self._initial_login_request_flow()
        except BannedAccountException:
            self.log_warning("Account most probably BANNED! :-(((")
            self.player_state['banned'] = True
            return False
        except CaptchaException:
            self.log_warning("Account got CAPTCHA'd! :-|")
            return False
        except Exception as e:
            self.log_error("Login failed: {}".format(repr(e)))
            return False

    # Returns warning/banned flags and tutorial state.
    def update_player_state(self):
        request = self._api.create_request()
        request.get_player(
            player_locale=self.cfg['player_locale'])

        responses = self._call_request(request)

        get_player = responses.get('GET_PLAYER', {})
        self.player_state = {
            'tutorial_state': get_player.get('player_data', {}).get('tutorial_state', []),
            'warn': get_player.get('warn', False),
            'banned': get_player.get('banned', False)
        }
        if self.player_state.get('banned', False):
            self.log_warning("GET_PLAYER has the 'banned' flag set.")
            raise BannedAccountException

    def is_logged_in(self):
        # Logged in? Enough time left? Cool!
        if self._api.get_auth_provider() and self._api.get_auth_provider().has_ticket():
            remaining_time = self._api.get_auth_provider()._ticket_expire / 1000 - time.time()
            return remaining_time > 60
        return False

    def is_warned(self):
        return self.player_state.get('warn')

    def is_banned(self):
        return self.player_state.get('banned')

    def has_captcha(self):
        return None if not self.is_logged_in() else (
            self.captcha_url and len(self.captcha_url) > 1)

    def uses_proxy(self):
        return self.proxy_url is not None and len(self.proxy_url) > 0

    # =======================================================================

    def _generate_device_info(self):
        identifier = self.username + self.password
        md5 = hashlib.md5()
        md5.update(identifier)
        pick_hash = int(md5.hexdigest(), 16)

        iphones = {
            'iPhone5,1': 'N41AP',
            'iPhone5,2': 'N42AP',
            'iPhone5,3': 'N48AP',
            'iPhone5,4': 'N49AP',
            'iPhone6,1': 'N51AP',
            'iPhone6,2': 'N53AP',
            'iPhone7,1': 'N56AP',
            'iPhone7,2': 'N61AP',
            'iPhone8,1': 'N71AP',
            'iPhone8,2': 'N66AP',
            'iPhone8,4': 'N69AP',
            'iPhone9,1': 'D10AP',
            'iPhone9,2': 'D11AP',
            'iPhone9,3': 'D101AP',
            'iPhone9,4': 'D111AP'
        }

        ios8 = ('8.0', '8.0.1', '8.0.2', '8.1', '8.1.1',
                '8.1.2', '8.1.3', '8.2', '8.3', '8.4', '8.4.1')
        ios9 = ('9.0', '9.0.1', '9.0.2', '9.1', '9.2', '9.2.1',
                '9.3', '9.3.1', '9.3.2', '9.3.3', '9.3.4', '9.3.5')
        ios10 = ('10.0', '10.0.1', '10.0.2', '10.0.3', '10.1', '10.1.1')

        device_info = {
            'device_brand': 'Apple',
            'device_model': 'iPhone',
            'hardware_manufacturer': 'Apple',
            'firmware_brand': 'iPhone OS'
        }

        devices = tuple(iphones.keys())
        device = devices[pick_hash % len(devices)]
        device_info['device_model_boot'] = device
        device_info['hardware_model'] = iphones[device]
        device_info['device_id'] = md5.hexdigest()

        if device.startswith('iPhone9'):
            ios_pool = ios10
        elif device.startswith('iPhone8'):
            ios_pool = ios9 + ios10
        else:
            ios_pool = ios8 + ios9 + ios10
        device_info['firmware_type'] = ios_pool[pick_hash % len(ios_pool)]

        self.log_info("Using an {} on iOS {} with device ID {}".format(device,
            device_info['firmware_type'], device_info['device_id']))

        return device_info

    def _call_request(self, request):
        # Set hash key for this request
        self._api.activate_hash_server(self.hash_key)

        response = request.call()
        self._last_request = time.time()

        # status_code 3 means BAD_REQUEST, so probably banned
        if 'status_code' in response and response['status_code'] == 3:
            self.log_warning("Got BAD_REQUEST response.")
            raise BannedAccountException

        if not 'responses' in response:
            return {}

        # Return only the responses
        responses = response['responses']

        self._parse_responses(responses)

        return responses

    def _get_inventory_delta(self, inv_response):
        inventory_items = inv_response.get('inventory_delta', {}).get(
            'inventory_items', [])
        inventory = {}
        no_item_ids = (
            ITEM_UNKNOWN,
            ITEM_TROY_DISK,
            ITEM_X_ATTACK,
            ITEM_X_DEFENSE,
            ITEM_X_MIRACLE,
            ITEM_POKEMON_STORAGE_UPGRADE,
            ITEM_ITEM_STORAGE_UPGRADE
        )
        for item in inventory_items:
            iid = item.get('inventory_item_data', {})
            if 'item' in iid and iid['item']['item_id'] not in no_item_ids:
                item_id = iid['item']['item_id']
                count = iid['item'].get('count', 0)
                inventory[item_id] = count
            elif 'egg_incubators' in iid and 'egg_incubator' in iid['egg_incubators']:
                for incubator in iid['egg_incubators']['egg_incubator']:
                    item_id = incubator['item_id']
                    inventory[item_id] = inventory.get(item_id, 0) + 1
        return inventory

    def _update_inventory_totals(self):
        ball_ids = [
            ITEM_POKE_BALL,
            ITEM_GREAT_BALL,
            ITEM_ULTRA_BALL,
            ITEM_MASTER_BALL
        ]
        balls = 0
        total_items = 0
        for item_id in self.inventory:
            if item_id in ['total', 'balls']:
                continue
            if item_id in ball_ids:
                balls += self.inventory[item_id]
            total_items += self.inventory[item_id]
        self.inventory_balls = balls
        self.inventory_total = total_items

    def _parse_responses(self, responses):
        for response_type in responses.keys():
            response = responses[response_type]
            if response_type == 'GET_INVENTORY':
                api_inventory = response

                # Set an (empty) inventory if necessary
                if self.inventory is None:
                    self.inventory = {}

                # Update inventory (balls, items)
                inventory_delta = self._get_inventory_delta(api_inventory)
                self.inventory.update(inventory_delta)
                self._update_inventory_totals()

                # Update stats (level, xp, encounters, captures, km walked, etc.)
                self._update_player_stats(api_inventory)

                # Update last timestamp for inventory requests
                self._last_timestamp_ms = api_inventory[
                    'inventory_delta'].get('new_timestamp_ms', 0)

                # Cleanup
                del responses[response_type]

            # Get settings hash from response for future calls
            if response_type == 'DOWNLOAD_SETTINGS':
                if 'hash' in response:
                    self._download_settings_hash = response['hash']

            # Check for captcha
            if response_type == 'CHECK_CHALLENGE':
                self.captcha_url = response.get('challenge_url')
                if self.has_captcha():
                    raise CaptchaException


    def _update_player_stats(self, api_inventory):
        inventory_items = api_inventory.get('inventory_delta', {}).get(
            'inventory_items', [])
        for item in inventory_items:
            item_data = item.get('inventory_item_data', {})
            if 'player_stats' in item_data:
                self.player_stats.update(item_data['player_stats'])

    def _initial_login_request_flow(self):
        # Empty request -----------------------------------------------------
        self.log_debug("Login Flow: Empty request")
        request = self._api.create_request()
        self._call_request(request)
        time.sleep(random.uniform(.43, .97))

        # Get player info ---------------------------------------------------
        self.log_debug("Login Flow: Get player state")
        self.update_player_state()
        time.sleep(random.uniform(.53, 1.1))

        # Download remote config --------------------------------------------
        self.log_debug("Login Flow: Downloading remote config")
        asset_time, template_time = self._download_remote_config()
        time.sleep(1)

        # Assets and item templates -----------------------------------------
        if asset_time > self._asset_time:
            self.log_debug("Login Flow: Download asset digest")
            self._get_asset_digest(asset_time)
        if template_time > self._item_templates_time:
            self.log_debug("Login Flow: Download item templates")
            self._download_item_templates(template_time)

        # Checking tutorial -------------------------------------------------
        if (self.player_state['tutorial_state'] is not None and
                not all(x in self.player_state['tutorial_state'] for x in
                        (0, 1, 3, 4, 7))):
            self.log_debug("Login Flow: Completing tutorial")
            self._complete_tutorial()
        else:
            # Get player profile
            self.log_debug("Login Flow: Get player profile")
            self.perform_request(lambda req: req.get_player_profile(),
                                 download_settings=True)
            time.sleep(random.uniform(.2, .3))

        # Level up rewards --------------------------------------------------
        self.log_debug("Login Flow: Get levelup rewards")
        self.perform_request(
            lambda req: req.level_up_rewards(level=self.player_stats['level']),
            download_settings=True)

        # Check store -------------------------------------------------------
        # TODO: There is currently no way to call the GET_STORE_ITEMS platform request.

        self.log_info('After-login procedure completed.')
        time.sleep(random.uniform(.5, 1.3))
        return True

    def _set_avatar(self, tutorial=False):
        player_avatar = avatar.new()
        self.perform_request(lambda req: req.list_avatar_customizations(
            avatar_type=player_avatar['avatar'],
#            slot=tuple(),
            filters=2), buddy_walked=not tutorial, action=5)
        time.sleep(random.uniform(7, 14))

        self.perform_request(
            lambda req: req.set_avatar(player_avatar=player_avatar),
            buddy_walked=not tutorial, action=2)

        if tutorial:
            time.sleep(random.uniform(.5, 4))

            self.perform_request(
                lambda req: req.mark_tutorial_complete(
                    tutorials_completed=1), buddy_walked=False)

            time.sleep(random.uniform(.5, 1))

        self.perform_request(
            lambda req: req.get_player_profile(), action=1)

    def _complete_tutorial(self):
        tutorial_state = self.player_state['tutorial_state']
        if 0 not in tutorial_state:
            # legal screen
            self.log_debug("Tutorial #0: Legal screen")
            self.perform_request(lambda req: req.mark_tutorial_complete(
                tutorials_completed=0), buddy_walked=False)
            time.sleep(random.uniform(.35, .525))

            self.perform_request(
                lambda req: req.get_player(
                    player_locale=self.cfg['player_locale']),
                buddy_walked=False)
            time.sleep(1)

        if 1 not in tutorial_state:
            # avatar selection
            self.log_debug("Tutorial #1: Avatar selection")
            self._set_avatar(tutorial=True)

        starter_id = None
        if 3 not in tutorial_state:
            # encounter tutorial
            self.log_debug("Tutorial #3: Catch starter Pokemon")
            time.sleep(random.uniform(.7, .9))
            self.perform_request(lambda req: req.get_download_urls(asset_id=
                ['1a3c2816-65fa-4b97-90eb-0b301c064b7a/1487275569649000',
                'aa8f7687-a022-4773-b900-3a8c170e9aea/1487275581132582',
                 'e89109b0-9a54-40fe-8431-12f7826c8194/1487275593635524']))

            time.sleep(random.uniform(7, 10.3))
            starter = random.choice((1, 4, 7))
            self.perform_request(lambda req: req.encounter_tutorial_complete(
                pokemon_id=starter), action=1)

            time.sleep(random.uniform(.4, .5))
            responses = self.perform_request(
                lambda req: req.get_player(player_locale=self.cfg['player_locale']))

            try:
                inventory = responses[
                    'GET_INVENTORY'].inventory_delta.inventory_items
                for item in inventory:
                    pokemon = item.inventory_item_data.pokemon_data
                    if pokemon.id:
                        starter_id = pokemon.id
                        break
            except (KeyError, TypeError):
                starter_id = None

        if 4 not in tutorial_state:
            # name selection
            self.log_debug("Tutorial #4: Set trainer name")
            time.sleep(random.uniform(12, 18))
            self.perform_request(
                lambda req: req.claim_codename(codename=self.username),
                action=2)

            time.sleep(.7)
            self.perform_request(
                lambda req: req.get_player(player_locale=self.cfg['player_locale']))
            time.sleep(.13)

            self.perform_request(lambda req: req.mark_tutorial_complete(
                tutorials_completed=4), buddy_walked=False)

        if 7 not in tutorial_state:
            # first time experience
            self.log_debug("Tutorial #7: First time experience")
            time.sleep(random.uniform(3.9, 4.5))
            self.perform_request(lambda req: req.mark_tutorial_complete(
                tutorials_completed=7))

        # set starter as buddy
        if starter_id:
            self.log_debug("Setting buddy Pokemon")
            time.sleep(random.uniform(4, 5))
            self.perform_request(
                lambda req: req.set_buddy_pokemon(pokemon_id=starter_id),
                action=2)
            time.sleep(random.uniform(.8, 1.2))

        time.sleep(.2)
        return True

    def _download_remote_config(self):
        responses = self.perform_request(
            lambda req: req.download_remote_config_version(platform=1,
                                                           app_version=APP_VERSION),
            download_settings=True, buddy_walked=False)
        remote_config = responses['DOWNLOAD_REMOTE_CONFIG_VERSION']
        return remote_config['asset_digest_timestamp_ms'] / 1000000, \
               remote_config['item_templates_timestamp_ms'] / 1000

    def _get_asset_digest(self, asset_time):
        i = random.randint(0, 3)
        result = 2
        page_offset = 0
        page_timestamp = 0
        while result == 2:
            responses = self.perform_request(lambda req: req.get_asset_digest(
                platform=1,
                app_version=APP_VERSION,
                paginate=True,
                page_offset=page_offset,
                page_timestamp=page_timestamp), buddy_walked=False, download_settings=True)
            if i > 2:
                time.sleep(1.45)
                i = 0
            else:
                i += 1
                time.sleep(.2)
            try:
                response = responses['GET_ASSET_DIGEST']
            except KeyError:
                break
            result = response['result']
            page_offset = response.get('page_offset')
            page_timestamp = response['timestamp_ms']
        self._asset_time = asset_time

    def _download_item_templates(self, template_time):
        i = random.randint(0, 3)
        result = 2
        page_offset = 0
        page_timestamp = 0
        while result == 2:
            responses = self.perform_request(lambda req: req.download_item_templates(
                paginate=True,
                page_offset=page_offset,
                page_timestamp=page_timestamp), buddy_walked=False, download_settings=True)
            if i > 2:
                time.sleep(1.5)
                i = 0
            else:
                i += 1
                time.sleep(.25)
            try:
                response = responses['DOWNLOAD_ITEM_TEMPLATES']
            except KeyError:
                break
            result = response['result']
            page_offset = response.get('page_offset')
            page_timestamp = response['timestamp_ms']
        self._item_templates_time = template_time

    def jitter_location(self, lat, lng, maxMeters=10):
        origin = geopy.Point(lat, lng)
        b = random.randint(0, 360)
        d = math.sqrt(random.random()) * (float(maxMeters) / 1000)
        destination = geopy.distance.distance(kilometers=d).destination(origin,
                                                                        b)
        return (destination.latitude, destination.longitude)

    def log_info(self, msg):
        self.last_msg = msg
        log.info("[{}] {}".format(self.username, msg))

    def log_debug(self, msg):
        self.last_msg = msg
        log.debug("[{}] {}".format(self.username, msg))

    def log_warning(self, msg):
        self.last_msg = msg
        log.warning("[{}] {}".format(self.username, msg))

    def log_error(self, msg):
        self.last_msg = msg
        log.error("[{}] {}".format(self.username, msg))


class CaptchaException(PgoapiError):
    """Raised when an account got captcha'd"""
