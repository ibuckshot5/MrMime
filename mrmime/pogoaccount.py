import hashlib
import logging
import random
import time
from threading import Lock

from pgoapi import PGoApi
from pgoapi.exceptions import AuthException, PgoapiError, \
    BannedAccountException, HashingQuotaExceededException
from pgoapi.protos.pogoprotos.inventory.item.item_id_pb2 import *
from pgoapi.utilities import get_cell_ids, f2i

from mrmime import _mr_mime_cfg, APP_VERSION, avatar, API_VERSION
from mrmime.cyclicresourceprovider import CyclicResourceProvider
from mrmime.responses import parse_inventory_delta, parse_player_stats
from mrmime.utils import jitter_location

log = logging.getLogger(__name__)
login_lock = Lock()


class POGOAccount(object):

    def __init__(self, auth_service, username, password, hash_key=None,
                 hash_key_provider=None, proxy_url=None, proxy_provider=None):
        self.auth_service = auth_service
        self.username = username
        self.password = password

        # Initialize hash keys
        self._hash_key = None
        if hash_key_provider and not hash_key_provider.is_empty():
            self._hash_key_provider = hash_key_provider
        elif hash_key:
            self._hash_key_provider = CyclicResourceProvider()
            self._hash_key_provider.add_resource(hash_key)
        else:
            self._hash_key_provider = CyclicResourceProvider()

        # Initialize proxies
        self._proxy_url = None
        if proxy_provider and not proxy_provider.is_empty():
            self._proxy_provider = proxy_provider
        elif proxy_url:
            self._proxy_provider = CyclicResourceProvider()
            self._proxy_provider.add_resource(proxy_url)
        else:
            self._proxy_provider = CyclicResourceProvider()

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

        # Location
        self.latitude = None
        self.longitude = None
        self.altitude = None

        # Last log message (for GUI/console)
        self.last_msg = ""

        # --- private fields

        self._api = PGoApi(device_info=self._generate_device_info())
        self._download_settings_hash = None
        self._asset_time = 0
        self._item_templates_time = 0

        # Timestamp when last API request was made
        self._last_request = 0

        # Timestamp of last get_map_objects request
        self._last_gmo = self._last_request

        # Timestamp for incremental inventory updates
        self._last_timestamp_ms = None

        # Timestamp when previous user action is completed
        self._last_action = 0

    def set_position(self, lat, lng, alt):
        """Sets the location and altitude of the account"""
        self._api.set_position(lat, lng, alt)
        self.latitude = lat
        self.longitude = lng
        self.altitude = alt

    def perform_request(self, add_main_request, download_settings=False,
                        buddy_walked=True, get_inbox=True, action=None, jitter=True):
        request = self._api.create_request()

        # Add main request
        add_main_request(request)

        # Standard requests with every call
        request.check_challenge()
        request.get_hatched_eggs()

        # Check inventory with correct timestamp
        if self._last_timestamp_ms:
            request.get_inventory(last_timestamp_ms=self._last_timestamp_ms)
        else:
            request.get_inventory()

        # Always check awarded badges
        request.check_awarded_badges()

        # Optional: download settings (with correct hash value)
        if download_settings:
            if self._download_settings_hash:
                request.download_settings(hash=self._download_settings_hash)
            else:
                request.download_settings()

        # Optional: request buddy kilometers
        if buddy_walked:
            request.get_buddy_walked()

        if get_inbox:
            request.get_inbox(is_history=True)

        return self._call_request(request, action, jitter)

    # Use API to check the login status, and retry the login if possible.
    def check_login(self):
        # Check auth ticket
        if self._api.get_auth_provider() and self._api.get_auth_provider().check_ticket():
            return True

        try:
            if not self.cfg['parallel_logins']:
                login_lock.acquire()

            # Set proxy if given.
            if self._proxy_provider:
                self._proxy_url = self._proxy_provider.next()
                self.log_debug("Using proxy {}".format(self._proxy_url))
                self._api.set_proxy({
                    'http': self._proxy_url,
                    'https': self._proxy_url
                })

            # Try to login. Repeat a few times, but don't get stuck here.
            num_tries = 0
            # One initial try + login_retries.
            while num_tries < self.cfg['login_retries']:
                try:
                    num_tries += 1
                    self.log_info("Login try {}.".format(num_tries))
                    if self._proxy_url:
                        self._api.set_authentication(
                            provider=self.auth_service,
                            username=self.username,
                            password=self.password,
                            proxy_config={
                                'http': self._proxy_url,
                                'https': self._proxy_url
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

            if self.cfg['full_login_flow'] is True:
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
            return True
        finally:
            if not self.cfg['parallel_logins']:
                login_lock.release()


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
        return self._proxy_url is not None and len(self._proxy_url) > 0

    def req_get_map_objects(self):
        """Scans current account location."""
        # Make sure that we don't hammer with GMO requests
        diff = self._last_gmo + self.cfg['scan_delay'] - time.time()
        if diff > 0:
            time.sleep(diff)

        # We jitter here because we need the jittered location NOW
        lat, lng = jitter_location(self.latitude, self.longitude)
        self._api.set_position(lat, lng, self.altitude)

        cell_ids = get_cell_ids(lat, lng)
        timestamps = [0, ] * len(cell_ids)
        responses = self.perform_request(
            lambda req: req.get_map_objects(latitude=f2i(lat),
                                            longitude=f2i(lng),
                                            since_timestamp_ms=timestamps,
                                            cell_id=cell_ids),
            get_inbox=True,
            jitter=False # we already jittered
        )
        self._last_gmo = self._last_request

        return responses

    def req_encounter(self, encounter_id, spawn_point_id, latitude, longitude):
        return self.perform_request(lambda req: req.encounter(
            encounter_id=encounter_id,
            spawn_point_id=spawn_point_id,
            player_latitude=latitude,
            player_longitude=longitude), get_inbox=True)

    def req_catch_pokemon(self, encounter_id, spawn_point_id, ball,
                          normalized_reticle_size, spin_modifier):
        return self.perform_request(lambda req: req.catch_pokemon(
                encounter_id=encounter_id,
                pokeball=ball,
                normalized_reticle_size=normalized_reticle_size,
                spawn_point_id=spawn_point_id,
                hit_pokemon=1,
                spin_modifier=spin_modifier,
                normalized_hit_position=1.0), get_inbox=True)

    def req_release_pokemon(self, pokemon_id):
        return self.perform_request(
            lambda req: req.release_pokemon(pokemon_id=pokemon_id), get_inbox=True)

    def req_fort_search(self, fort_id, fort_lat, fort_lng, player_lat,
                        player_lng):
        return self.perform_request(lambda req: req.fort_search(
            fort_id=fort_id,
            fort_latitude=fort_lat,
            fort_longitude=fort_lng,
            player_latitude=player_lat,
            player_longitude=player_lng), get_inbox=True)

    def req_get_gym_details(self, gym_id, gym_lat, gym_lng, player_lat, player_lng):
        return self.perform_request(
            lambda req: req.get_gym_details(gym_id=gym_id,
                                            player_latitude=f2i(player_lat),
                                            player_longitude=f2i(player_lng),
                                            gym_latitude=gym_lat,
                                            gym_longitude=gym_lng,
                                            client_version=API_VERSION), get_inbox=True)

    def req_recycle_inventory_item(self, item_id, amount):
        return self.perform_request(lambda req: req.recycle_inventory_item(
            item_id=item_id,
            count=amount), get_inbox=True)

    def req_level_up_rewards(self, level):
        return self.perform_request(
            lambda req: req.level_up_rewards(level=level), get_inbox=True)

    def req_verify_challenge(self, captcha_token):
        req = self._api.create_request()
        req.verify_challenge(token=captcha_token)
        responses = self._call_request(req)
        if 'VERIFY_CHALLENGE' in responses:
            response = responses['VERIFY_CHALLENGE']
            if 'success' in response:
                self.captcha_url = None
                self.log_info("Successfully uncaptcha'd.")
                return True
            else:
                self.log_warning("Failed verifyChallenge")
                return False

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

    def _call_request(self, request, action=None, jitter=True):
        # Wait until a previous user action gets completed
        if action:
            now = time.time()
            # wait for the time required, or at least a half-second
            if self._last_action > now + .5:
                time.sleep(self._last_action - now)
            else:
                time.sleep(0.5)

        if jitter:
            lat, lng = jitter_location(self.latitude, self.longitude)
            self._api.set_position(lat, lng, self.altitude)

        success = False
        while not success:
            try:
                # Set hash key for this request
                old_hash_key = self._hash_key
                self._hash_key = self._hash_key_provider.next()
                if self._hash_key != old_hash_key:
                    self.log_debug("Using hash key {}".format(self._hash_key))
                self._api.activate_hash_server(self._hash_key)

                response = request.call()
                self._last_request = time.time()
                success = True
            except HashingQuotaExceededException:
                if self.cfg['retry_on_hash_quota_exceeded'] == True:
                    self.log_warning("Hashing quota exceeded. Retrying in 5s.")
                    time.sleep(5)
                else:
                    raise

        # status_code 3 means BAD_REQUEST, so probably banned
        if 'status_code' in response and response['status_code'] == 3:
            self.log_warning("Got BAD_REQUEST response.")
            raise BannedAccountException

        if not 'responses' in response:
            self.log_error("Got no responses at all!")
            return {}

        # Set the timer when the user action will be completed
        if action:
            self._last_action = self._last_request + action

        # Return only the responses
        responses = response['responses']

        self._parse_responses(responses)

        return responses

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
                inventory_delta = parse_inventory_delta(api_inventory)
                self.inventory.update(inventory_delta)
                self._update_inventory_totals()

                # Update stats (level, xp, encounters, captures, km walked, etc.)
                self.player_stats.update(parse_player_stats(api_inventory))

                # Update last timestamp for inventory requests
                self._last_timestamp_ms = api_inventory[
                    'inventory_delta'].get('new_timestamp_ms', 0)

                # Cleanup
                del responses[response_type]

            # Get settings hash from response for future calls
            elif response_type == 'DOWNLOAD_SETTINGS':
                if 'hash' in response:
                    self._download_settings_hash = response['hash']
                # TODO: Check forced client version and exit program if different

            elif response_type == 'GET_PLAYER':
                self.player_state = {
                    'tutorial_state': response.get('player_data', {}).get('tutorial_state', []),
                    'warn': response.get('warn', False),
                    'banned': response.get('banned', False)
                }
                if self.player_state.get('banned', False):
                    self.log_warning("GET_PLAYER has the 'banned' flag set.")
                    raise BannedAccountException

            # Check for captcha
            elif response_type == 'CHECK_CHALLENGE':
                self.captcha_url = response.get('challenge_url')
                if self.has_captcha():
                    raise CaptchaException

    def _initial_login_request_flow(self):
        self.log_info("Performing full login flow requests")

        # Empty request -----------------------------------------------------
        self.log_debug("Login Flow: Empty request")
        # ===== empty
        request = self._api.create_request()
        self._call_request(request)
        time.sleep(random.uniform(.43, .97))

        # Get player info ---------------------------------------------------
        self.log_debug("Login Flow: Get player state")
        # ===== GET_PLAYER (unchained)
        request = self._api.create_request()
        request.get_player(
            player_locale=self.cfg['player_locale'])
        self._call_request(request)
        time.sleep(random.uniform(.53, 1.1))

        # Download remote config --------------------------------------------
        self.log_debug("Login Flow: Downloading remote config")
        asset_time, template_time = self._download_remote_config_version()
        time.sleep(1)

        # Assets and item templates -----------------------------------------
        if self.cfg['download_assets_and_items'] and asset_time > self._asset_time:
            self.log_debug("Login Flow: Download asset digest")
            self._get_asset_digest(asset_time)
        else:
            self.log_debug("Login Flow: Skipping asset digest download")

        if self.cfg['download_assets_and_items'] and template_time > self._item_templates_time:
            self.log_debug("Login Flow: Download item templates")
            self._download_item_templates(template_time)
        else:
            self.log_debug("Login Flow: Skipping item template download")

        # TODO: Maybe download translation URLs from assets? Like pogonode?

        # Checking tutorial -------------------------------------------------
        if (self.player_state['tutorial_state'] is not None and
                not all(x in self.player_state['tutorial_state'] for x in
                        (0, 1, 3, 4, 7))):
            self.log_debug("Login Flow: Completing tutorial")
            self._complete_tutorial()
        else:
            # Get player profile
            self.log_debug("Login Flow: Get player profile")
            # ===== GET_PLAYER_PROFILE
            self.perform_request(lambda req: req.get_player_profile(),
                                 download_settings=True)
            time.sleep(random.uniform(.2, .3))

        # Level up rewards --------------------------------------------------
        self.log_debug("Login Flow: Get levelup rewards")
        # ===== LEVEL_UP_REWARDS
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
        # ===== LIST_AVATAR_CUSTOMIZATIONS
        self.perform_request(lambda req: req.list_avatar_customizations(
            avatar_type=player_avatar['avatar'],
#            slot=tuple(),
            filters=2), buddy_walked=not tutorial, action=5, get_inbox=False)
        time.sleep(random.uniform(7, 14))

        # ===== SET_AVATAR
        self.perform_request(
            lambda req: req.set_avatar(player_avatar=player_avatar),
            buddy_walked=not tutorial, action=2, get_inbox=False)

        if tutorial:
            time.sleep(random.uniform(.5, 4))

            # ===== MARK_TUTORIAL_COMPLETE
            self.perform_request(
                lambda req: req.mark_tutorial_complete(
                    tutorials_completed=1), buddy_walked=False, get_inbox=False)

            time.sleep(random.uniform(.5, 1))

        self.perform_request(
            lambda req: req.get_player_profile(), action=1, get_inbox=False)

    def _complete_tutorial(self):
        tutorial_state = self.player_state['tutorial_state']
        if 0 not in tutorial_state:
            # legal screen
            self.log_debug("Tutorial #0: Legal screen")
            # ===== MARK_TUTORIAL_COMPLETE
            self.perform_request(lambda req: req.mark_tutorial_complete(
                tutorials_completed=0), buddy_walked=False, get_inbox=False)
            time.sleep(random.uniform(.35, .525))

            # ===== GET_PLAYER
            self.perform_request(
                lambda req: req.get_player(
                    player_locale=self.cfg['player_locale']),
                buddy_walked=False, get_inbox=False)
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
            # ===== GET_DOWNLOAD_URLS
            self.perform_request(lambda req: req.get_download_urls(asset_id=
                ['1a3c2816-65fa-4b97-90eb-0b301c064b7a/1487275569649000',
                'aa8f7687-a022-4773-b900-3a8c170e9aea/1487275581132582',
                 'e89109b0-9a54-40fe-8431-12f7826c8194/1487275593635524']), get_inbox=False)

            time.sleep(random.uniform(7, 10.3))
            starter = random.choice((1, 4, 7))
            # ===== ENCOUNTER_TUTORIAL_COMPLETE
            self.perform_request(lambda req: req.encounter_tutorial_complete(
                pokemon_id=starter), action=1, get_inbox=False)

            time.sleep(random.uniform(.4, .5))
            # ===== GET_PLAYER
            responses = self.perform_request(
                lambda req: req.get_player(player_locale=self.cfg['player_locale']), get_inbox=False)

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
            # ===== CLAIM_CODENAME
            self.perform_request(
                lambda req: req.claim_codename(codename=self.username),
                action=2, get_inbox=False)

            time.sleep(.7)
            # ===== GET_PLAYER
            self.perform_request(
                lambda req: req.get_player(player_locale=self.cfg['player_locale']), get_inbox=False)
            time.sleep(.13)

            # ===== MARK_TUTORIAL_COMPLETE
            self.perform_request(lambda req: req.mark_tutorial_complete(
                tutorials_completed=4), buddy_walked=False, get_inbox=False)

        if 7 not in tutorial_state:
            # first time experience
            self.log_debug("Tutorial #7: First time experience")
            time.sleep(random.uniform(3.9, 4.5))
            # ===== MARK_TUTORIAL_COMPLETE
            self.perform_request(lambda req: req.mark_tutorial_complete(
                tutorials_completed=7), get_inbox=False)

        # set starter as buddy
        if starter_id:
            self.log_debug("Setting buddy Pokemon")
            time.sleep(random.uniform(4, 5))
            # ===== SET_BUDDY_POKEMON
            self.perform_request(
                lambda req: req.set_buddy_pokemon(pokemon_id=starter_id),
                action=2, get_inbox=False)
            time.sleep(random.uniform(.8, 1.2))

        time.sleep(.2)
        return True

    def _download_remote_config_version(self):
        # ===== DOWNLOAD_REMOTE_CONFIG_VERSION
        responses = self.perform_request(
            lambda req: req.download_remote_config_version(platform=1,
                                                           app_version=APP_VERSION),
            download_settings=True, buddy_walked=False, get_inbox=False)
        if 'DOWNLOAD_REMOTE_CONFIG_VERSION' not in responses:
            raise Exception("Call to download_remote_config_version did not"
                            " return proper response.")
        remote_config = responses['DOWNLOAD_REMOTE_CONFIG_VERSION']
        return remote_config['asset_digest_timestamp_ms'] / 1000000, \
               remote_config['item_templates_timestamp_ms'] / 1000

    def _get_asset_digest(self, asset_time):
        i = random.randint(0, 3)
        result = 2
        page_offset = 0
        page_timestamp = 0
        while result == 2:
            # ===== GET_ASSET_DIGEST
            responses = self.perform_request(lambda req: req.get_asset_digest(
                platform=1,
                app_version=APP_VERSION,
                paginate=True,
                page_offset=page_offset,
                page_timestamp=page_timestamp), download_settings=True, buddy_walked=False, get_inbox=False)
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
            # ===== DOWNLOAD_ITEM_TEMPLATES
            responses = self.perform_request(lambda req: req.download_item_templates(
                paginate=True,
                page_offset=page_offset,
                page_timestamp=page_timestamp), download_settings=True, buddy_walked=False, get_inbox=False)
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

    def __getattr__(self, item):
        # Backwards compatibility
        if item == 'hash_key':
            return self._hash_key
        elif item == 'proxy_url':
            return self._proxy_url
        else:
            return self[item]

    def __setattr__(self, key, value):
        if key == 'hash_key':
            # Workaround to directly set one hash key.
            self._hash_key_provider.set_single_resource(value)
            self._hash_key = value
        elif key == 'proxy_url':
            # Workaround to directly set one proxy.
            self._proxy_provider.set_single_resource(value)
            self._proxy_url = value
        else:
            # Default: just set the property the normal way
            super(POGOAccount, self).__setattr__(key, value)

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
