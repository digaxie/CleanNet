"""
DPI Bypass Service v5 - asyncio Engine + Multi-Strategy
System Tray + Web Dashboard + DoH DNS + Health Check + Logging
Configurable site bypass system via config.json
"""
import asyncio
import socket
import threading
import time
import random
import subprocess
import os
import sys
import json
import ctypes
import winreg
import atexit
import signal
import logging
import ssl
import urllib.request
from logging.handlers import RotatingFileHandler
from collections import deque
from datetime import datetime

# System Tray (optional)
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False

# ==================== LOGGING ====================

_script_dir = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(_script_dir, 'bypass.log')

logger = logging.getLogger('dpi-bypass')
logger.setLevel(logging.DEBUG)

_fh = RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=3, encoding='utf-8')
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
))
logger.addHandler(_fh)


class _DashboardLogHandler(logging.Handler):
    def __init__(self, maxlen=200):
        super().__init__()
        self._entries = deque(maxlen=maxlen)
        self._counter = 0

    def emit(self, record):
        self._counter += 1
        self._entries.append((self._counter, self.format(record)))

    def get_entries_after(self, after_id):
        return [(i, msg) for i, msg in self._entries if i > after_id]


_dashboard_handler = _DashboardLogHandler(maxlen=200)
_dashboard_handler.setLevel(logging.DEBUG)
_dashboard_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'
))
logger.addHandler(_dashboard_handler)

# ==================== CONFIG ====================

CONFIG_FILE = os.path.join(_script_dir, 'config.json')

def _validate_config(config):
    """Validate config structure, fix missing fields, log warnings."""
    errors = []
    if not isinstance(config, dict):
        return None, ["Config is not a JSON object"]
    # Ensure top-level keys
    if 'sites' not in config or not isinstance(config.get('sites'), dict):
        config['sites'] = {}
        errors.append("Missing or invalid 'sites' - reset to empty")
    if 'proxy_port' not in config or not isinstance(config.get('proxy_port'), int):
        config['proxy_port'] = 8080
        errors.append("Missing or invalid 'proxy_port' - reset to 8080")
    if 'dashboard_port' not in config or not isinstance(config.get('dashboard_port'), int):
        config['dashboard_port'] = 8888
        errors.append("Missing or invalid 'dashboard_port' - reset to 8888")
    if 'proxy_bypass' not in config or not isinstance(config.get('proxy_bypass'), list):
        config['proxy_bypass'] = []
        errors.append("Missing or invalid 'proxy_bypass' - reset to empty")
    # Validate each site
    bad_sites = []
    for name, site in list(config['sites'].items()):
        if not isinstance(site, dict):
            bad_sites.append(name)
            continue
        if 'domains' not in site or not isinstance(site.get('domains'), list) or not site['domains']:
            bad_sites.append(name)
            errors.append(f"Site '{name}' missing 'domains' list - removed")
            continue
        # Ensure optional fields
        if 'dns_resolve' not in site or not isinstance(site.get('dns_resolve'), list):
            site['dns_resolve'] = site['domains'][:6]
        if 'ips' not in site or not isinstance(site.get('ips'), list):
            site['ips'] = []
        if 'enabled' not in site:
            site['enabled'] = True
    for name in bad_sites:
        del config['sites'][name]
    return config, errors

def load_config():
    default_config = {
        'sites': {
            'discord': {
                'enabled': True,
                'domains': ['discord.com', 'discordapp.com', 'discord.gg',
                            'discord.media', 'discordapp.net', 'discord.dev',
                            'discord.new', 'discord.gift', 'discordstatus.com', 'dis.gd'],
                'dns_resolve': ['discord.com', 'gateway.discord.gg',
                                'cdn.discordapp.com', 'media.discordapp.net'],
                'ips': ['162.159.128.233', '162.159.129.233', '162.159.130.233',
                        '162.159.136.232', '162.159.137.232'],
            }
        },
        'proxy_port': 8080,
        'dashboard_port': 8888,
        'proxy_bypass': [],
    }
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        config, errors = _validate_config(config)
        if config is None:
            logger.error(f"Config validation failed: {errors}")
            return default_config
        for err in errors:
            logger.warning(f"[CONFIG] {err}")
        logger.info(f"Config loaded: {len(config.get('sites', {}))} sites")
        return config
    except json.JSONDecodeError as e:
        logger.error(f"Config JSON parse error (line {e.lineno}): {e.msg}")
        logger.error("Using default config. Fix config.json and reload.")
        return default_config
    except FileNotFoundError:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        logger.info("Default config.json created")
        return default_config
    except Exception as e:
        logger.error(f"Config read error: {e}")
        return default_config

def _build_lists_from_config(config):
    all_domains = []
    all_ips = []
    domain_to_site = {}
    site_ips = {}
    site_dns = {}
    for site_name, site_data in config.get('sites', {}).items():
        if not site_data.get('enabled', True):
            continue
        domains = site_data.get('domains', [])
        if not domains:
            domains = [f"{site_name}.com", f"www.{site_name}.com"]
            site_data['domains'] = domains
        dns_resolve = site_data.get('dns_resolve', [])
        if not dns_resolve:
            dns_resolve = list(domains)
            site_data['dns_resolve'] = dns_resolve
        all_domains.extend(domains)
        site_dns[site_name] = dns_resolve
        site_ip_list = site_data.get('ips', [])
        all_ips.extend(site_ip_list)
        site_ips[site_name] = list(site_ip_list)
        for d in domains:
            domain_to_site[d.lower()] = site_name
    return list(set(all_domains)), list(set(all_ips)), domain_to_site, site_ips, site_dns

# ==================== SETTINGS ====================

_config = load_config()

LOCAL_HOST = '127.0.0.1'
LOCAL_PORT = _config.get('proxy_port', 8080)
WEB_PORT = _config.get('dashboard_port', 8888)

ALWAYS_BYPASS = [
    "localhost", "127.*", "10.*", "192.168.*", "<local>",
    # Microsoft (Store, Office, Windows Update, Azure CDN)
    "*.microsoft.com", "*.microsoftonline.com", "*.windows.com",
    "*.windows.net", "*.live.com", "*.office.com", "*.office.net",
    "*.msftconnecttest.com", "*.msauth.net", "*.msftauth.net",
    "*.azureedge.net", "*.msecnd.net", "*.s-microsoft.com",
    "*.azure.com", "*.msedge.net", "*.bing.com", "*.bing.net",
    # GitHub
    "*.github.com", "*.github.io", "*.githubusercontent.com", "*.githubassets.com",
    # Google
    "*.google.com", "*.googleapis.com", "*.gstatic.com", "*.google-analytics.com",
    # Apple
    "*.apple.com",
    # Common CDNs (not blocked, no need to proxy)
    "*.akamaized.net", "*.akamai.net", "*.akamaihd.net",
    "*.cloudfront.net", "*.cloudflare.com", "*.fastly.net", "*.amazonaws.com",
]

BYPASS_PRESETS = {
    'gaming': [
        # --- Riot Games (LoL, Valorant, TFT, Wild Rift) ---
        '*.riotgames.com', '*.leagueoflegends.com', '*.pvp.net',
        '*.riotcdn.net', '*.lolesports.com', '*.playvalorant.com',
        # --- Epic Games (EGS, Fortnite, Unreal) ---
        '*.epicgames.com', '*.epicgames.dev', '*.unrealengine.com',
        '*.fortnite.com', '*.easyanticheat.net', '*.ol.epicgames.com',
        # --- Steam / Valve (Steam, CS2, Dota 2) ---
        '*.steampowered.com', '*.steamcommunity.com', '*.steamcontent.com',
        '*.steamstatic.com', '*.valvesoftware.com', '*.steamgames.com',
        '*.steamusercontent.com', '*.steamchina.com',
        # --- EA / EA Play (EA App, FIFA, Battlefield, Apex) ---
        '*.ea.com', '*.origin.com', '*.tnt-ea.com',
        '*.dice.se', '*.bioware.com', '*.respawn.com',
        # --- Ubisoft / Ubisoft Connect (AC, R6, Far Cry) ---
        '*.ubisoft.com', '*.ubi.com', '*.uplay.com',
        '*.ubisoftconnect.com', '*.ubisoft-connect.com',
        '*.ubisoft.org', '*.ubisoft-dns.com',
        '*.cdn-ubisoft.com', '*.static-dm.ubisoft.com',
        '*.upc.ubisoft.com',
        # --- Blizzard / Battle.net (WoW, OW2, Diablo, SC2) ---
        '*.blizzard.com', '*.battle.net', '*.blizzard.cn',
        '*.blz-contentstack.com',
        # --- Xbox / Microsoft Gaming (Game Pass, Halo, MS Store) ---
        '*.xbox.com', '*.xboxlive.com', '*.xboxservices.com',
        '*.playfabapi.com', '*.playfab.com', '*.halowaypoint.com',
        '*.gamepass.com', '*.msgamestudios.com',
        # --- PlayStation (PSN, PS Store, PS Plus) ---
        '*.playstation.com', '*.playstation.net',
        '*.playstationnetwork.com', '*.sonyentertainmentnetwork.com',
        '*.sie.com', '*.scea.com',
        # --- Nintendo (eShop, NSO) ---
        '*.nintendo.com', '*.nintendo.net', '*.nintendo.co.jp',
        '*.nintendoswitch.com',
        # --- GOG / CD Projekt (Cyberpunk, Witcher) ---
        '*.gog.com', '*.cdprojektred.com', '*.cdprojekt.com',
        # --- Rockstar Games (GTA, RDR) ---
        '*.rockstargames.com', '*.rsg.sc', '*.socialclub.rockstargames.com',
        # --- Bethesda / ZeniMax (Elder Scrolls, Fallout, Starfield) ---
        '*.bethesda.net', '*.bethsoft.com', '*.zenimax.com',
        # --- Square Enix (FF, Dragon Quest) ---
        '*.square-enix.com', '*.square-enix-games.com',
        '*.finalfantasyxiv.com', '*.playonline.com',
        # --- Bandai Namco (Elden Ring, Tekken, Naruto) ---
        '*.bandainamcoent.com', '*.bandainamco.net',
        '*.bandainamcoent.eu', '*.bandainamcogames.com',
        # --- SEGA / Atlus ---
        '*.sega.com', '*.atlus.com',
        # --- Wargaming (WoT, WoWs, WoWp) ---
        '*.wargaming.net', '*.worldoftanks.com', '*.worldoftanks.eu',
        '*.worldofwarships.com', '*.worldofwarplanes.com', '*.wg.gg',
        # --- Gaijin (War Thunder, Enlisted, CRSED) ---
        '*.gaijin.net', '*.warthunder.com', '*.enlisted.net',
        # --- Garena (Free Fire, LoL SEA) ---
        '*.garena.com', '*.garena.sg',
        # --- Nexon (MapleStory, KartRider) ---
        '*.nexon.com', '*.nexon.net',
        # --- NCSoft (Lineage, Blade & Soul, Guild Wars) ---
        '*.ncsoft.com', '*.plaync.com', '*.arenanet.com',
        # --- HoYoverse / miHoYo (Genshin, HSR, ZZZ) ---
        '*.hoyoverse.com', '*.mihoyo.com', '*.hoyolab.com',
        '*.genshinimpact.com', '*.honkaiimpact3.com',
        '*.kurogames.com',
        # --- Krafton (PUBG, The Callisto Protocol) ---
        '*.krafton.com', '*.pubg.com', '*.pubgesports.com',
        # --- Supercell (CoC, CR, Brawl Stars) ---
        '*.supercell.com', '*.supercell.net',
        '*.brawlstars.com', '*.clashofclans.com', '*.clashroyale.com',
        # --- Roblox ---
        '*.roblox.com', '*.rbxcdn.com',
        # --- Minecraft / Mojang ---
        '*.minecraft.net', '*.mojang.com', '*.minecraftservices.com',
        # --- Anti-cheat ---
        '*.battleye.com', '*.xigncode.com', '*.nprotect.com',
        '*.vanguard.gg',
        # --- Gaming infra / community ---
        '*.unity3d.com', '*.photonengine.com', '*.faceit.com',
        '*.mod.io', '*.nexusmods.com', '*.curseforge.com',
    ],
    'cdn': [
        '*.akamaihd.net', '*.cloudflare.com', '*.fastly.net', '*.cloudfront.net',
    ],
    'streaming': [
        '*.netflix.com', '*.spotify.com', '*.twitch.tv',
    ],
}

HEALTH_CHECK_INTERVAL = 60
IP_UPDATE_INTERVAL = 300

STRATEGY_ORDER = ['direct', 'host_split', 'fragment_light', 'tls_record_frag',
                   'fragment_burst', 'desync', 'fragment_heavy', 'sni_shuffle',
                   'fake_tls_inject', 'triple_split', 'sni_padding',
                   'reverse_frag', 'slow_drip', 'oob_inline', 'dot_shuffle',
                   'tls_multi_record', 'tls_mixed_delay', 'sni_split_byte',
                   'header_fragment', 'tls_zero_frag', 'tls_frag_overlap',
                   'tls_version_mix', 'tls_random_pad_frag',
                   'tls_interleaved_ccs', 'tcp_window_frag']
STRATEGY_SUCCESS_TIMEOUT = 10.0
STRATEGY_FAILURE_COOLDOWN = 3600
STRATEGY_RETEST_INTERVAL = 7200
STRATEGY_SAVE_INTERVAL = 60
STRATEGY_CACHE_FILE = os.path.join(_script_dir, 'strategy_cache.json')
STATS_FILE = os.path.join(_script_dir, 'stats.json')
AI_STRATEGY_FILE = os.path.join(_script_dir, 'ai_strategy.json')
AI_SAVE_INTERVAL = 120
AI_MIN_SAMPLES = 5          # Minimum samples before AI predictions activate
AI_EXPLORATION_RATE = 0.15  # Legacy: kept for reference, Thompson Sampling replaces this
AI_DECAY_FACTOR = 0.95      # Weight decay for older observations
AI_RING_BUFFER_SIZE = 100   # Recent observations ring buffer (was 50)
AI_DRIFT_CHECK_INTERVAL = 60   # Seconds between drift detection checks
AI_SELF_TRAIN_INTERVAL = 1800  # Seconds between self-training probes (30min) — default for 'light'
AI_TRAIN_PROFILES = {
    'light':    {'interval': 1800, 'probes': 3,  'label': 'Light'},
    'medium':   {'interval': 600,  'probes': 5,  'label': 'Medium'},
    'heavy':    {'interval': 120,  'probes': 8,  'label': 'Heavy'},
    'nonstop':  {'interval': 15,   'probes': 10, 'label': 'Nonstop 24/7'},
}
_ai_train_intensity = 'light'
_self_train_state = {'running': False, 'last_run': 0, 'total_probes': 0, 'last_site': '', 'last_strategy': '', 'last_result': '', 'cycle_count': 0}
AI_NN_HIDDEN_SIZE = 16         # Neural network hidden layer size
AI_NN_INPUT_SIZE = 10          # Neural network input features
AI_NN_LEARNING_RATE = 0.01    # SGD learning rate
AI_THOMPSON_DECAY_INTERVAL = 200  # Decay Thompson params every N observations

STRATEGY_GROUPS = {
    'fragmentation': ['fragment_light', 'fragment_burst', 'fragment_heavy', 'header_fragment'],
    'tls_record': ['tls_record_frag', 'tls_multi_record', 'tls_mixed_delay'],
    'sni_based': ['sni_shuffle', 'sni_padding', 'sni_split_byte', 'dot_shuffle', 'host_split'],
    'injection': ['fake_tls_inject', 'desync', 'oob_inline'],
    'split': ['triple_split', 'reverse_frag', 'slow_drip'],
    'direct': ['direct'],
}
STRATEGY_TO_GROUP = {}
for _grp, _strats in STRATEGY_GROUPS.items():
    for _s in _strats:
        STRATEGY_TO_GROUP[_s] = _grp

BYPASS_DOMAINS, BYPASS_IPS, _domain_to_site, _site_ips, _site_dns = _build_lists_from_config(_config)
_site_names = list(_config.get('sites', {}).keys())

def reload_config_dynamically():
    global _config, BYPASS_DOMAINS, BYPASS_IPS, _domain_to_site, _site_ips, _site_dns, _site_names, _domain_ips
    _config = load_config()
    BYPASS_DOMAINS, BYPASS_IPS, _domain_to_site, _site_ips, _site_dns = _build_lists_from_config(_config)
    _domain_ips.clear()
    _site_names = list(_config.get('sites', {}).keys())
    if _running:
        set_proxy(True, LOCAL_HOST, LOCAL_PORT)
    logger.info(f"Config reloaded: {len(_site_names)} sites, {len(_config.get('proxy_bypass', []))} bypass entries")
    return True

# ==================== GLOBAL STATE ====================

_status = "stopped"
_running = False
_tray_icon = None
_loop = None
_shutdown_event = None
_port_ready = threading.Event()
_start_time = None
_ping_ms = -1
_ping_history = deque(maxlen=120)
_stats = {'connections': 0, 'fragments': 0, 'ip_updates': 0,
          'strategy_tries': 0, 'strategy_fallbacks': 0}
_site_stats = {}  # site_name -> {'connections': 0, 'successes': 0, 'failures': 0, 'total_ms': 0}

def _load_stats():
    global _stats, _site_stats
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'global' in data and isinstance(data['global'], dict):
            for k in _stats:
                if k in data['global']:
                    _stats[k] = data['global'][k]
        if 'sites' in data and isinstance(data['sites'], dict):
            _site_stats.update(data['sites'])
        logger.info(f"Stats loaded: {_stats['connections']} total connections")
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning(f"Stats load error: {e}")

def _save_stats():
    try:
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump({'global': _stats, 'sites': _site_stats}, f, indent=2)
    except Exception as e:
        logger.error(f"Stats save error: {e}")

_load_stats()
_test_results = {}  # site_name -> {'status': 'ok'|'fail'|'testing', 'ms': 0, 'time': ''}
_strategy_history = deque(maxlen=100)  # {'time': str, 'site': str, 'strategy': str, 'ms': float, 'success': bool}
_domain_ips = {}  # domain -> [ip1, ip2, ...]
_blocked_domains = {}  # domain -> timestamp - fully blocked CDN domains (fast-fail)
BLOCKED_DOMAIN_TTL = 300  # 5 minutes: blocked domain retry interval
_site_semaphores = {}  # site_name -> asyncio.Semaphore - limit concurrent bypass per site
SITE_MAX_CONCURRENT = 24  # max concurrent bypass connections per site

# ==================== AI TRAINING STATE ====================
_training_state = {
    'active': False,
    'progress': {},      # site_name -> {current_strat, tested, total, pct}
    'results': {},       # site_name -> {best_strategy, best_ms, all_results: [{strategy, success, ms}]}
    'previous_strategies': {},  # site_name -> old strategy (for revert)
    'completed': False,
}

# ==================== HELPERS ====================

CDN_KEYWORD_MAP = {
    'discordapp': 'discord',
}

def _find_site_for_host(host):
    host_lower = host.lower()
    if host_lower in _domain_to_site:
        return _domain_to_site[host_lower]
    for domain, site_name in _domain_to_site.items():
        if host_lower.endswith('.' + domain):
            return site_name
    for cdn_keyword, parent_site in CDN_KEYWORD_MAP.items():
        if cdn_keyword in host_lower and parent_site in _config.get('sites', {}):
            if _config['sites'][parent_site].get('enabled', True):
                return parent_site
    # Dynamic CDN detection: if site name appears in hostname, associate it
    for site_name in _site_names:
        if len(site_name) >= 3 and site_name.lower() in host_lower:
            if site_name in _config.get('sites', {}) and _config['sites'][site_name].get('enabled', True):
                return site_name
    return None

def _is_main_domain(host, site_name):
    for part in host.lower().split('.'):
        if site_name.lower() in part:
            return True
    return False

def get_bypass_ip(host):
    host_lower = host.lower()
    if host_lower in _domain_ips and _domain_ips[host_lower]:
        return random.choice(_domain_ips[host_lower])
    if _find_site_for_host(host_lower):
        return host_lower
    site = _find_site_for_host(host)
    if site and _site_ips.get(site):
        return random.choice(_site_ips[site])
    return None

def get_domain_ips(host):
    host_lower = host.lower()
    if host_lower in _domain_ips and _domain_ips[host_lower]:
        return _domain_ips[host_lower]
    return []

def get_site_ips(host):
    site = _find_site_for_host(host)
    ips = []
    if site and site in _site_ips:
        ips.extend(_site_ips[site])
    CROSS_CDN_MAP = {}
    if site in CROSS_CDN_MAP:
        sister = CROSS_CDN_MAP[site]
        if sister in _site_ips:
            ips.extend(_site_ips[sister])
    return list(set(ips))

def set_proxy(enable, host="127.0.0.1", port=8080):
    user_bypass = _config.get('proxy_bypass', [])
    bypass_list = ";".join(ALWAYS_BYPASS + user_bypass)
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_ALL_ACCESS
        )
        if enable:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass_list)
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
        return True
    except Exception as e:
        logger.error(f"Proxy settings error: {e}")
        return False

AUTOSTART_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_REG_NAME = "CleanNetDPIBypass"

def get_autostart():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, AUTOSTART_REG_NAME)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            winreg.CloseKey(key)
            return False
    except Exception:
        return False

def set_autostart(enable):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_ALL_ACCESS)
        if enable:
            pythonw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
            if not os.path.exists(pythonw):
                pythonw = sys.executable
            script_path = os.path.join(_script_dir, 'bypass_silent.pyw')
            cmd = f'"{pythonw}" "{script_path}"'
            winreg.SetValueEx(key, AUTOSTART_REG_NAME, 0, winreg.REG_SZ, cmd)
            logger.info("Autostart enabled")
        else:
            try:
                winreg.DeleteValue(key, AUTOSTART_REG_NAME)
                logger.info("Autostart disabled")
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        logger.error(f"Autostart error: {e}")
        return False

def _close_writer(w):
    try:
        if w:
            w.close()
    except:
        pass


def _normalize_tls_failure(exc):
    if isinstance(exc, ssl.SSLCertVerificationError):
        detail = getattr(exc, 'verify_message', '') or str(exc) or exc.__class__.__name__
        detail_l = detail.lower()
        if 'hostname mismatch' in detail_l:
            reason = 'hostname_mismatch'
        else:
            reason = 'invalid_certificate'
    elif isinstance(exc, asyncio.TimeoutError):
        reason, detail = 'timeout', 'TLS handshake timed out'
    elif isinstance(exc, ConnectionError):
        reason, detail = 'connection_failed', str(exc) or 'Connection failed'
    elif isinstance(exc, ssl.SSLError):
        detail = str(exc) or exc.__class__.__name__
        if 'alert' in detail.lower():
            reason = 'tls_alert'
        else:
            reason = 'tls_handshake_failed'
    elif isinstance(exc, OSError):
        reason, detail = 'connection_failed', str(exc) or exc.__class__.__name__
    else:
        reason, detail = 'connection_failed', str(exc) or exc.__class__.__name__
    return reason, detail[:160]


def _drain_memory_bio(bio):
    chunks = []
    while True:
        chunk = bio.read()
        if not chunk:
            break
        chunks.append(chunk)
    return b''.join(chunks)


async def _send_probe_payload(writer, payload, strat_name=None, use_strategy=False):
    if not payload:
        return
    if use_strategy and strat_name:
        await STRATEGY_FUNCS[strat_name](writer, payload)
    else:
        writer.write(payload)
        await writer.drain()


async def _verify_tls_strategy(connect_host, server_name, strat_name='direct', port=443, timeout=8):
    start_t = time.perf_counter()
    reader = writer = None
    first_flight = True
    deadline = time.monotonic() + timeout
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(connect_host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        tls_obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)

        while True:
            try:
                tls_obj.do_handshake()
                pending = _drain_memory_bio(outgoing)
                if pending:
                    await _send_probe_payload(writer, pending, strat_name, use_strategy=first_flight)
                    first_flight = False
                elapsed_ms = round((time.perf_counter() - start_t) * 1000, 1)
                return {'ok': True, 'elapsed_ms': elapsed_ms, 'reason': None, 'detail': None}
            except ssl.SSLWantWriteError:
                pending = _drain_memory_bio(outgoing)
                if pending:
                    await _send_probe_payload(writer, pending, strat_name, use_strategy=first_flight)
                    first_flight = False
            except ssl.SSLWantReadError:
                pending = _drain_memory_bio(outgoing)
                if pending:
                    await _send_probe_payload(writer, pending, strat_name, use_strategy=first_flight)
                    first_flight = False
                time_left = max(0.1, deadline - time.monotonic())
                net_data = await asyncio.wait_for(reader.read(8192), timeout=time_left)
                if not net_data:
                    raise ConnectionError("Connection closed during TLS handshake")
                incoming.write(net_data)
    except Exception as exc:
        reason, detail = _normalize_tls_failure(exc)
        return {'ok': False, 'elapsed_ms': 0, 'reason': reason, 'detail': detail}
    finally:
        _close_writer(writer)



def _atexit_handler():
    _strategy_cache.force_save()
    _ai_engine.force_save()
    _save_stats()
    set_proxy(False)

atexit.register(_atexit_handler)

def _cleanup_handler(signum, frame):
    _strategy_cache.force_save()
    _ai_engine.force_save()
    _save_stats()
    set_proxy(False)
    sys.exit(0)

signal.signal(signal.SIGINT, _cleanup_handler)
signal.signal(signal.SIGTERM, _cleanup_handler)
try:
    signal.signal(signal.SIGBREAK, _cleanup_handler)
except AttributeError:
    pass

def _notify(title, message):
    logger.info(f"[NOTIFY] {title}: {message}")

# ==================== DNS (DoH) ====================

DOH_ENDPOINTS = [
    'https://dns.google/resolve',
    'https://cloudflare-dns.com/dns-query',
]
_ssl_ctx = ssl.create_default_context()

def _resolve_domain_doh(domain, timeout=5):
    for endpoint in DOH_ENDPOINTS:
        try:
            url = f'{endpoint}?name={domain}&type=A'
            req = urllib.request.Request(url, headers={
                'Accept': 'application/dns-json',
                'User-Agent': 'Mozilla/5.0',
            })
            resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx)
            data = json.loads(resp.read())
            ips = [a['data'] for a in data.get('Answer', []) if a.get('type') == 1]
            if ips:
                return ips
        except Exception:
            continue
    return []

async def resolve_bypass_ips():
    global BYPASS_IPS, _site_ips, _domain_ips
    loop = asyncio.get_event_loop()
    all_new_ips = set()
    resolved_domains = 0

    domains_to_resolve = set()
    for dns_list in _site_dns.values():
        domains_to_resolve.update(dns_list)

    domain_list = list(domains_to_resolve)
    for i in range(0, len(domain_list), 5):
        batch = domain_list[i:i+5]
        tasks = [loop.run_in_executor(None, _resolve_domain_doh, d) for d in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for domain, result in zip(batch, results):
            if isinstance(result, list) and result:
                _domain_ips[domain] = result
                all_new_ips.update(result)
                resolved_domains += 1

    for site_name, dns_domains in _site_dns.items():
        site_new_ips = set(_site_ips.get(site_name, []))
        for domain in dns_domains:
            if domain in _domain_ips:
                site_new_ips.update(_domain_ips[domain])
        if site_new_ips:
            _site_ips[site_name] = list(site_new_ips)

    if all_new_ips:
        BYPASS_IPS = list(all_new_ips)
        _stats['ip_updates'] += 1
        logger.info(f"IPs updated (DoH): {len(BYPASS_IPS)} IPs, {resolved_domains} domains")
        return True
    logger.warning("DNS resolution failed")
    return False

# ==================== PING + HEALTH ====================

async def measure_ping():
    global _ping_ms
    try:
        ip = random.choice(BYPASS_IPS) if BYPASS_IPS else '1.1.1.1'
        start = time.perf_counter()
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443), timeout=5)
        elapsed = (time.perf_counter() - start) * 1000
        writer.close()
        _ping_ms = round(elapsed)
        _ping_history.append(_ping_ms)
        return _ping_ms
    except:
        _ping_ms = -1
        return -1

async def check_health():
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(LOCAL_HOST, LOCAL_PORT), timeout=10
        )
        all_dns = [d for domains in _site_dns.values() for d in domains]
        test_domain = all_dns[0] if all_dns else 'discord.com'
        writer.write(f'CONNECT {test_domain}:443 HTTP/1.1\r\nHost: {test_domain}:443\r\n\r\n'.encode())
        await writer.drain()
        reader_data = await asyncio.wait_for(
            asyncio.open_connection(LOCAL_HOST, LOCAL_PORT), timeout=10
        )
        writer.close()
        return True
    except:
        return False

async def test_site_connection(site_name):
    """Test connectivity to a site through the proxy bypass using real TLS handshake."""
    site_cfg = _config.get('sites', {}).get(site_name)
    if not site_cfg:
        _test_results[site_name] = {'status': 'fail', 'ms': 0, 'time': _now_iso(), 'error': 'Site not found'}
        return _test_results[site_name]
    domains = site_cfg.get('dns_resolve', site_cfg.get('domains', []))
    test_domain = domains[0] if domains else f"{site_name}.com"
    _test_results[site_name] = {'status': 'testing', 'ms': 0, 'time': _now_iso()}

    import ssl as _ssl

    def _do_test():
        import socket
        s = socket.create_connection((LOCAL_HOST, LOCAL_PORT), timeout=10)
        try:
            s.sendall(f'CONNECT {test_domain}:443 HTTP/1.1\r\nHost: {test_domain}:443\r\n\r\n'.encode())
            resp = b''
            while b'\r\n\r\n' not in resp:
                chunk = s.recv(4096)
                if not chunk:
                    raise ConnectionError("Proxy closed connection")
                resp += chunk
            if b'200' not in resp.split(b'\r\n')[0]:
                raise ConnectionError("Proxy rejected CONNECT")
            ctx = _ssl.create_default_context()
            ss = ctx.wrap_socket(s, server_hostname=test_domain)
            ss.do_handshake()
            ss.close()
        except Exception:
            s.close()
            raise

    start = time.perf_counter()
    try:
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(loop.run_in_executor(None, _do_test), timeout=20)
        elapsed = round((time.perf_counter() - start) * 1000)
        result = {'status': 'ok', 'ms': elapsed, 'time': _now_iso()}
    except Exception as e:
        elapsed = round((time.perf_counter() - start) * 1000)
        reason, detail = _normalize_tls_failure(e)
        result = {'status': 'fail', 'ms': elapsed, 'time': _now_iso(), 'reason': reason, 'error': detail}
    _test_results[site_name] = result
    if result['status'] == 'ok':
        logger.info(f"[TEST] {site_name}: ok ({result.get('ms', 0)}ms)")
    else:
        logger.info(f"[TEST] {site_name}: fail ({result.get('reason', 'unknown')}: {result.get('error', 'n/a')})")

    async def _clear_test():
        await asyncio.sleep(8)
        _test_results.pop(site_name, None)
    asyncio.create_task(_clear_test())

    return result

async def health_check_loop():
    global _status
    await asyncio.sleep(5)
    await resolve_bypass_ips()
    await measure_ping()
    _notify("DPI Bypass", f"Active - {len(BYPASS_IPS)} IPs, {len(BYPASS_DOMAINS)} domains")

    last_ip_update = time.time()
    was_error = False

    while _running:
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)
        if not _running:
            break
        await measure_ping()
        _strategy_cache._save_if_needed()
        _save_stats()

        if time.time() - last_ip_update > IP_UPDATE_INTERVAL:
            await resolve_bypass_ips()
            last_ip_update = time.time()

async def strategy_retest_loop():
    while _running:
        await asyncio.sleep(STRATEGY_RETEST_INTERVAL)
        if not _running:
            break
        now = time.time()
        for site_name, sd in _strategy_cache._data.get('sites', {}).items():
            if sd.get('best_strategy'):
                continue
            expired = []
            for strat, fail_info in sd.get('failures', {}).items():
                last_fail = _parse_iso(fail_info.get('last_fail', ''))
                if last_fail and (now - last_fail) > STRATEGY_RETEST_INTERVAL:
                    expired.append(strat)
            for strat in expired:
                del sd['failures'][strat]
        _strategy_cache._save_if_needed()

# ==================== TLS STRATEGIES ====================

def _find_sni_offset(data):
    try:
        if len(data) < 43 or data[0] != 0x16:
            return None
        pos = 43
        if pos >= len(data):
            return None
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2 + cs_len
        if pos >= len(data):
            return None
        cm_len = data[pos]
        pos += 1 + cm_len
        if pos + 2 > len(data):
            return None
        pos += 2
        ext_end = min(pos + int.from_bytes(data[pos-2:pos], 'big'), len(data))
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos+2], 'big')
            ext_len = int.from_bytes(data[pos+2:pos+4], 'big')
            if ext_type == 0:
                return pos
            pos += 4 + ext_len
        return None
    except Exception:
        return None

def _sni_split_point(data):
    """Calculate the split point at the middle of the SNI name (within payload)."""
    sni_off = _find_sni_offset(data)
    if not sni_off or sni_off <= 5:
        return None
    payload = data[5:]
    sni_payload_idx = sni_off - 5
    if (sni_payload_idx + 9) > len(payload):
        return None
    try:
        name_len = int.from_bytes(payload[sni_payload_idx+7:sni_payload_idx+9], 'big')
        if 0 < name_len < 500 and (sni_payload_idx + 9 + name_len) <= len(payload):
            return sni_payload_idx + 9 + (name_len // 2)
    except Exception:
        pass
    return None


async def strategy_direct(writer, data):
    writer.write(data)
    await writer.drain()

async def strategy_host_split(writer, data):
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sni_offset = _find_sni_offset(data)
        if sni_offset and sni_offset > 0:
            writer.write(data[:sni_offset])
            await writer.drain()
            await asyncio.sleep(0.005)
            writer.write(data[sni_offset:])
            await writer.drain()
            _stats['fragments'] += 1
            return
    writer.write(data)
    await writer.drain()

async def strategy_fragment_light(writer, data):
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        mid = min(len(data) // 2, 100)
        writer.write(data[:mid])
        await writer.drain()
        await asyncio.sleep(0.02)
        writer.write(data[mid:])
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_record_frag(writer, data):
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))

        frag1 = payload[:split_at]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2

        writer.write(rec1)
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(rec2)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_fragment_burst(writer, data):
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        sni_offset = _find_sni_offset(data)
        if sni_offset and sni_offset > 5:
            writer.write(data[:5])
            writer.write(data[5:sni_offset])
            writer.write(data[sni_offset:])
        else:
            third = max(len(data) // 3, 1)
            writer.write(data[:third])
            writer.write(data[third:third*2])
            writer.write(data[third*2:])
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_desync(writer, data):
    sock = writer.transport.get_extra_info('socket')
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
    await asyncio.sleep(0.2)
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sni_offset = _find_sni_offset(data)
        if sni_offset and sni_offset > 5:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = sni_offset - 5
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            writer.write(rec1)
            writer.write(rec2)
            await writer.drain()
        else:
            writer.write(data)
            await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_fragment_heavy(writer, data):
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        # Split TLS header bytes with small delays
        writer.write(data[:1])
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(data[1:5])
        await writer.drain()
        await asyncio.sleep(0.01)
        # Send remaining in larger chunks (16 bytes) with minimal delays
        remaining = data[5:]
        for i in range(0, len(remaining), 16):
            writer.write(remaining[i:i + 16])
            await writer.drain()
            await asyncio.sleep(0.001)
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_sni_shuffle(writer, data):
    try:
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            record_len = int.from_bytes(data[3:5], 'big')
            payload = data[5:5+record_len]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))

            frag1 = payload[:split_at]
            frag2 = payload[split_at:]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2

            writer.write(rec1)
            await writer.drain()
            await asyncio.sleep(0.02)
            writer.write(rec2)
            await writer.drain()
            _stats['fragments'] += 2
        else:
            writer.write(data)
            await writer.drain()
    except Exception:
        writer.write(data)
        await writer.drain()

async def strategy_fake_tls_inject(writer, data):
    """Send a fake TLS ChangeCipherSpec record before the real ClientHello to confuse DPI."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        tls_version = data[1:3]
        # Fake ChangeCipherSpec record (content type 0x14) with 1-byte payload
        fake_record = b'\x14' + tls_version + b'\x00\x01\x01'
        writer.write(fake_record)
        await writer.drain()
        await asyncio.sleep(0.005)
        writer.write(data)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_triple_split(writer, data):
    """Split TLS record into 3 proper TLS records: header area, SNI area, rest."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        sni_off = _find_sni_offset(data)
        if sni_off and sni_off > 5:
            s1 = sni_off - 5
            sni_sp = _sni_split_point(data)
            s2 = sni_sp if sni_sp and sni_sp > s1 else s1 + max((len(payload) - s1) // 2, 1)
        else:
            third = max(len(payload) // 3, 1)
            s1, s2 = third, third * 2
        s1 = max(1, min(s1, len(payload) - 2))
        s2 = max(s1 + 1, min(s2, len(payload) - 1))
        for frag in (payload[:s1], payload[s1:s2], payload[s2:]):
            rec = bytes([content_type]) + tls_version + len(frag).to_bytes(2, 'big') + frag
            writer.write(rec)
            await writer.drain()
            await asyncio.sleep(0.008)
        _stats['fragments'] += 2
    else:
        writer.write(data)
        await writer.drain()

async def strategy_sni_padding(writer, data):
    """Inject a TLS padding extension into ClientHello to inflate packet size past DPI buffers."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        try:
            # Find extensions area and add padding extension (type 0x0015)
            sni_off = _find_sni_offset(data)
            if sni_off and sni_off > 43:
                record_payload = data[5:]
                # Build padding extension: type=0x0015, length=256, data=256 zero bytes
                pad_ext = b'\x00\x15\x01\x00' + (b'\x00' * 256)
                # Insert padding extension right before SNI extension
                insert_at = sni_off - 5
                new_payload = record_payload[:insert_at] + pad_ext + record_payload[insert_at:]
                # Fix extensions length (2 bytes before first extension)
                # Rebuild as single TLS record
                content_type = data[0]
                tls_version = data[1:3]
                # Fix the handshake length (bytes 6-8 in original = payload[1:4])
                hs_type = new_payload[0]
                old_hs_len = int.from_bytes(new_payload[1:4], 'big')
                new_hs_len = old_hs_len + len(pad_ext)
                new_payload = bytes([hs_type]) + new_hs_len.to_bytes(3, 'big') + new_payload[4:]
                # Fix extensions total length
                new_record = bytes([content_type]) + tls_version + len(new_payload).to_bytes(2, 'big') + new_payload
                writer.write(new_record)
                await writer.drain()
                _stats['fragments'] += 1
                return
        except Exception:
            pass
    writer.write(data)
    await writer.drain()

async def strategy_reverse_frag(writer, data):
    """Send TLS record fragments in reverse order - second half first, then first half."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        frag1 = payload[:split_at]
        frag2 = payload[split_at:]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        # Send second fragment first
        writer.write(rec2)
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(rec1)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_slow_drip(writer, data):
    """Send data byte-by-byte with delays to evade DPI reassembly timeouts."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        # Send first 10 bytes one by one with delays (covers TLS header + start of handshake)
        drip_len = min(10, len(data))
        for i in range(drip_len):
            writer.write(data[i:i+1])
            await writer.drain()
            await asyncio.sleep(0.05)
        # Send rest in one chunk
        if drip_len < len(data):
            writer.write(data[drip_len:])
            await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_oob_inline(writer, data):
    """Use TCP urgent (OOB) data to inject a byte that DPI may process but server ignores."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # Send 1 byte as OOB/urgent data - DPI sees it inline, TLS server ignores it
                sock.send(b'\x00', socket.MSG_OOB)
            except Exception:
                pass
        await asyncio.sleep(0.005)
        # Now send real data fragmented at SNI
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        frag1 = payload[:split_at]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        writer.write(rec1)
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(rec2)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_dot_shuffle(writer, data):
    """Randomize the case of the SNI hostname - some DPI does case-sensitive matching."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        try:
            sni_off = _find_sni_offset(data)
            if sni_off:
                # SNI extension: type(2) + len(2) + list_len(2) + type(1) + name_len(2) + name
                name_start = sni_off + 9
                name_len = int.from_bytes(data[sni_off+7:sni_off+9], 'big')
                if name_start + name_len <= len(data) and 0 < name_len < 500:
                    modified = bytearray(data)
                    for i in range(name_start, name_start + name_len):
                        ch = modified[i]
                        if 0x61 <= ch <= 0x7a:  # lowercase a-z
                            if (i % 2) == 0:
                                modified[i] = ch - 32  # to uppercase
                    # Send as TLS record fragments with modified SNI
                    content_type = modified[0]
                    tls_version = bytes(modified[1:3])
                    payload = bytes(modified[5:])
                    split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
                    split_at = max(1, min(split_at, len(payload) - 1))
                    frag1 = payload[:split_at]
                    rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
                    frag2 = payload[split_at:]
                    rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
                    writer.write(rec1)
                    await writer.drain()
                    await asyncio.sleep(0.01)
                    writer.write(rec2)
                    await writer.drain()
                    _stats['fragments'] += 1
                    return
        except Exception:
            pass
    writer.write(data)
    await writer.drain()

async def strategy_tls_multi_record(writer, data):
    """Split TLS into 5-6 tiny records (1-byte payload each) to overwhelm DPI reassembly."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        # Send first 5 bytes as individual 1-byte TLS records
        send_individual = min(5, len(payload))
        for i in range(send_individual):
            rec = bytes([content_type]) + tls_version + b'\x00\x01' + payload[i:i+1]
            writer.write(rec)
            await writer.drain()
            await asyncio.sleep(0.003)
        # Send remaining as one record
        if send_individual < len(payload):
            rest = payload[send_individual:]
            rec = bytes([content_type]) + tls_version + len(rest).to_bytes(2, 'big') + rest
            writer.write(rec)
            await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_mixed_delay(writer, data):
    """TLS record fragmentation with random delays between fragments to break DPI timing."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        import random
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        frag1 = payload[:split_at]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        writer.write(rec1)
        await writer.drain()
        # Random delay between 5-50ms
        await asyncio.sleep(random.uniform(0.005, 0.05))
        writer.write(rec2)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_sni_split_byte(writer, data):
    """Split into 3 TLS records: pre-SNI, single SNI middle byte, post-SNI."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        sni_mid = _sni_split_point(data)
        if sni_mid and 1 < sni_mid < len(payload) - 1:
            # 3 records: everything before SNI middle, 1 byte at SNI middle, everything after
            parts = [payload[:sni_mid], payload[sni_mid:sni_mid+1], payload[sni_mid+1:]]
            for p in parts:
                rec = bytes([content_type]) + tls_version + len(p).to_bytes(2, 'big') + p
                writer.write(rec)
                await writer.drain()
                await asyncio.sleep(0.008)
            _stats['fragments'] += 2
        else:
            # Fallback to regular 2-way split
            split_at = min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            writer.write(rec1)
            await writer.drain()
            await asyncio.sleep(0.008)
            writer.write(rec2)
            await writer.drain()
            _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_header_fragment(writer, data):
    """Fragment the TLS record header itself across TCP segments - DPI can't even parse the header."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        # Send TLS header in 2 pieces: content_type+version (3 bytes), then length (2 bytes)
        writer.write(data[:3])
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(data[3:5])
        await writer.drain()
        await asyncio.sleep(0.01)
        # Send payload in 2 chunks at SNI split point
        payload_start = 5
        sni_mid = _sni_split_point(data)
        if sni_mid:
            abs_split = payload_start + sni_mid
            writer.write(data[payload_start:abs_split])
            await writer.drain()
            await asyncio.sleep(0.005)
            writer.write(data[abs_split:])
        else:
            writer.write(data[payload_start:])
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_zero_frag(writer, data):
    """Inject zero-length TLS records between real fragments to confuse DPI state machine."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        # Zero-length TLS record (valid per spec, servers silently ignore)
        empty_rec = bytes([content_type]) + tls_version + b'\x00\x00'
        frag1 = payload[:split_at]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        # Pattern: empty, frag1, empty, empty, frag2
        writer.write(empty_rec)
        await writer.drain()
        await asyncio.sleep(0.003)
        writer.write(rec1)
        await writer.drain()
        await asyncio.sleep(0.005)
        writer.write(empty_rec)
        await writer.drain()
        writer.write(empty_rec)
        await writer.drain()
        await asyncio.sleep(0.003)
        writer.write(rec2)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_frag_overlap(writer, data):
    """Send overlapping TLS record fragments - DPI can't resolve which data to use."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        # First record: payload up to split_at + 4 extra overlap bytes
        overlap = min(4, len(payload) - split_at)
        frag1 = payload[:split_at + overlap]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        # Second record: starts from split_at (overlaps by 'overlap' bytes)
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        writer.write(rec1)
        await writer.drain()
        await asyncio.sleep(0.008)
        writer.write(rec2)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_version_mix(writer, data):
    """Send TLS record fragments with different version bytes to confuse DPI session tracking."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        payload = data[5:]
        # Three different TLS versions
        versions = [b'\x03\x01', b'\x03\x03', b'\x03\x02']  # TLS 1.0, 1.2, 1.1
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        # Split into 3 parts
        s1 = max(1, split_at // 2)
        s2 = split_at
        parts = [payload[:s1], payload[s1:s2], payload[s2:]]
        for i, part in enumerate(parts):
            ver = versions[i % len(versions)]
            rec = bytes([content_type]) + ver + len(part).to_bytes(2, 'big') + part
            writer.write(rec)
            await writer.drain()
            await asyncio.sleep(0.005)
        _stats['fragments'] += 2
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_random_pad_frag(writer, data):
    """Split TLS payload into random-sized chunks (3-30 bytes) to defeat DPI pattern matching."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        pos = 0
        while pos < len(payload):
            # Random chunk size between 3 and 30 bytes
            chunk_size = random.randint(3, 30)
            chunk = payload[pos:pos + chunk_size]
            rec = bytes([content_type]) + tls_version + len(chunk).to_bytes(2, 'big') + chunk
            writer.write(rec)
            await writer.drain()
            await asyncio.sleep(random.uniform(0.002, 0.008))
            pos += chunk_size
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tls_interleaved_ccs(writer, data):
    """Interleave fake CCS and Alert records between ClientHello fragments to disrupt DPI state."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        # Fake ChangeCipherSpec record (type 0x14)
        fake_ccs = b'\x14' + tls_version + b'\x00\x01\x01'
        # Fake Alert record (type 0x15) - warning level, close_notify
        fake_alert = b'\x15' + tls_version + b'\x00\x02\x01\x00'
        frag1 = payload[:split_at]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        # Send: CCS -> frag1 -> Alert -> frag2 -> CCS
        writer.write(fake_ccs)
        await writer.drain()
        await asyncio.sleep(0.003)
        writer.write(rec1)
        await writer.drain()
        await asyncio.sleep(0.005)
        writer.write(fake_alert)
        await writer.drain()
        await asyncio.sleep(0.003)
        writer.write(rec2)
        await writer.drain()
        await asyncio.sleep(0.003)
        writer.write(fake_ccs)
        await writer.drain()
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

async def strategy_tcp_window_frag(writer, data):
    """Combine small TCP window with TLS record fragmentation to force tiny TCP segments."""
    if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256)
            except Exception:
                pass
        content_type = data[0]
        tls_version = data[1:3]
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        frag1 = payload[:split_at]
        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
        frag2 = payload[split_at:]
        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
        # Send each record byte-by-byte in small bursts to create tiny TCP segments
        for chunk in [rec1, rec2]:
            for i in range(0, len(chunk), 5):
                writer.write(chunk[i:i+5])
                await writer.drain()
                await asyncio.sleep(0.002)
            await asyncio.sleep(0.005)
        # Restore send buffer
        if sock:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            except Exception:
                pass
        _stats['fragments'] += 1
    else:
        writer.write(data)
        await writer.drain()

STRATEGY_FUNCS = {
    'direct': strategy_direct,
    'host_split': strategy_host_split,
    'fragment_light': strategy_fragment_light,
    'tls_record_frag': strategy_tls_record_frag,
    'fragment_burst': strategy_fragment_burst,
    'desync': strategy_desync,
    'fragment_heavy': strategy_fragment_heavy,
    'sni_shuffle': strategy_sni_shuffle,
    'fake_tls_inject': strategy_fake_tls_inject,
    'triple_split': strategy_triple_split,
    'sni_padding': strategy_sni_padding,
    'reverse_frag': strategy_reverse_frag,
    'slow_drip': strategy_slow_drip,
    'oob_inline': strategy_oob_inline,
    'dot_shuffle': strategy_dot_shuffle,
    'tls_multi_record': strategy_tls_multi_record,
    'tls_mixed_delay': strategy_tls_mixed_delay,
    'sni_split_byte': strategy_sni_split_byte,
    'header_fragment': strategy_header_fragment,
    'tls_zero_frag': strategy_tls_zero_frag,
    'tls_frag_overlap': strategy_tls_frag_overlap,
    'tls_version_mix': strategy_tls_version_mix,
    'tls_random_pad_frag': strategy_tls_random_pad_frag,
    'tls_interleaved_ccs': strategy_tls_interleaved_ccs,
    'tcp_window_frag': strategy_tcp_window_frag,
}

# ==================== STRATEGY CACHE ====================

def _now_iso():
    return datetime.now().isoformat(timespec='seconds')

def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


class StrategyCache:
    def __init__(self):
        self._data = {'version': 1, 'sites': {}}
        self._dirty = False
        self._last_save = 0
        self._load()

    def _load(self):
        try:
            with open(STRATEGY_CACHE_FILE, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
            logger.info(f"Strategy cache loaded: {len(self._data.get('sites', {}))} sites")
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"Strategy cache read error: {e}")

    def _save_if_needed(self):
        if self._dirty and (time.time() - self._last_save) > STRATEGY_SAVE_INTERVAL:
            self._do_save()

    def _do_save(self):
        try:
            with open(STRATEGY_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
            self._dirty = False
            self._last_save = time.time()
        except Exception as e:
            logger.error(f"Strategy cache write error: {e}")

    def force_save(self):
        if self._dirty:
            self._do_save()

    def _get_site_data(self, site_name):
        sites = self._data.setdefault('sites', {})
        if site_name not in sites:
            sites[site_name] = {
                'best_strategy': None, 'best_time_ms': None,
                'last_success': None, 'failures': {}, 'successes': {},
            }
        return sites[site_name]

    def get_strategy_order(self, site_name, is_main=True):
        site_config = _config.get('sites', {}).get(site_name, {})
        forced = site_config.get('strategy')
        if forced and forced != 'auto' and forced in STRATEGY_FUNCS:
            return [forced]

        # --- AI-powered strategy selection ---
        if is_main:
            ai_prediction = _ai_engine.predict(site_name, count_as_prediction=True)
            if ai_prediction:
                # AI has enough data — use its ranking
                ai_order = [p[0] for p in ai_prediction]
                top_conf = ai_prediction[0][2] if ai_prediction else 0

                # Filter out strategies in cooldown (but keep AI ranking)
                sd = self._get_site_data(site_name)
                now = time.time()
                result = []
                cooldown_strats = []
                for strat in ai_order:
                    fail_info = sd['failures'].get(strat)
                    if fail_info:
                        last_fail_time = _parse_iso(fail_info.get('last_fail', ''))
                        if last_fail_time and (now - last_fail_time) < STRATEGY_FAILURE_COOLDOWN:
                            cooldown_strats.append(strat)
                            continue
                    result.append(strat)

                if result:
                    logger.debug(f"[AI] {site_name}: predicted [{result[0]}] "
                                 f"(conf={top_conf}, order={','.join(result[:3])})")
                    return result
                # All in cooldown — fall through to cooldown recovery
                if cooldown_strats:
                    return cooldown_strats[:4]

        # --- Fallback: original logic ---
        sd = self._get_site_data(site_name)
        now = time.time()
        result = []
        cooldown_strats = []

        if sd['best_strategy'] and sd['best_strategy'] in STRATEGY_FUNCS:
            result.append(sd['best_strategy'])

        for strat in STRATEGY_ORDER:
            if strat in result:
                continue

            # If it's a CDN domain, ignore recent failures and try all
            if not is_main:
                result.append(strat)
                continue

            fail_info = sd['failures'].get(strat)
            if fail_info:
                last_fail_time = _parse_iso(fail_info.get('last_fail', ''))
                if last_fail_time and (now - last_fail_time) < STRATEGY_FAILURE_COOLDOWN:
                    cooldown_strats.append(strat)
                    continue
            result.append(strat)

        if not result and cooldown_strats:
            strong = [s for s in ['desync', 'tls_record_frag', 'fragment_burst', 'sni_shuffle']
                       if s in cooldown_strats]
            weak = [s for s in cooldown_strats if s not in strong]
            result = (strong + weak)[:4]

        return result

    def record_success(self, site_name, strategy, elapsed_ms):
        sd = self._get_site_data(site_name)
        now_iso = _now_iso()
        succ = sd['successes'].setdefault(strategy, {'count': 0, 'avg_ms': 0, 'last_ok': ''})
        old_avg, old_count = succ['avg_ms'], succ['count']
        succ['count'] = old_count + 1
        succ['avg_ms'] = round((old_avg * old_count + elapsed_ms) / (old_count + 1), 1)
        succ['last_ok'] = now_iso
        # Reset consecutive failure counter on success
        fail = sd['failures'].get(strategy)
        if fail:
            fail['consecutive'] = 0
        if sd['best_strategy'] is None or elapsed_ms < (sd.get('best_time_ms') or 99999):
            sd['best_strategy'] = strategy
            sd['best_time_ms'] = round(elapsed_ms, 1)
        sd['last_success'] = now_iso
        self._dirty = True
        self._save_if_needed()

    def record_failure(self, site_name, strategy):
        sd = self._get_site_data(site_name)
        fail = sd['failures'].setdefault(strategy, {'count': 0, 'last_fail': '', 'consecutive': 0})
        fail['count'] += 1
        fail['last_fail'] = _now_iso()
        fail['consecutive'] = fail.get('consecutive', 0) + 1
        # Only clear best_strategy after 3+ consecutive failures
        if sd['best_strategy'] == strategy and fail['consecutive'] >= 3:
            sd['best_strategy'] = None
            sd['best_time_ms'] = None
        self._dirty = True
        self._save_if_needed()

    def get_site_strategy_info(self, site_name):
        sd = self._data.get('sites', {}).get(site_name)
        if not sd:
            return {'strategy': 'auto', 'time_ms': None}
        return {
            'strategy': sd.get('best_strategy') or 'auto',
            'time_ms': sd.get('best_time_ms'),
        }

    def reset_all(self):
        self._data = {'version': 1, 'sites': {}}
        self._dirty = True
        self._do_save()
        logger.info("Strategy cache reset")


_strategy_cache = StrategyCache()

# ==================== ADAPTIVE AI STRATEGY ENGINE v3 ====================

import math
import random as _rng

class MiniNN:
    """2-layer feedforward neural network. Pure Python, zero dependencies.
    Used for per-site strategy success prediction."""

    def __init__(self, input_size=AI_NN_INPUT_SIZE, hidden_size=AI_NN_HIDDEN_SIZE, output_size=1):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.lr = AI_NN_LEARNING_RATE
        # Xavier initialization
        s1 = (2.0 / (input_size + hidden_size)) ** 0.5
        s2 = (2.0 / (hidden_size + output_size)) ** 0.5
        self.W1 = [[_rng.gauss(0, s1) for _ in range(hidden_size)] for _ in range(input_size)]
        self.b1 = [0.0] * hidden_size
        self.W2 = [[_rng.gauss(0, s2) for _ in range(output_size)] for _ in range(hidden_size)]
        self.b2 = [0.0] * output_size

    def forward(self, x):
        """Forward pass. Returns (output_list, cache_tuple)."""
        z1 = [sum(x[i] * self.W1[i][j] for i in range(self.input_size)) + self.b1[j]
              for j in range(self.hidden_size)]
        h1 = [max(0.0, z) for z in z1]  # ReLU
        z2 = [sum(h1[i] * self.W2[i][j] for i in range(self.hidden_size)) + self.b2[j]
              for j in range(self.output_size)]
        out = [1.0 / (1.0 + math.exp(-max(-500, min(500, z)))) for z in z2]  # Sigmoid
        return out, (x, z1, h1, z2)

    def backward(self, cache, target):
        """Backpropagation with SGD. Binary cross-entropy gradient."""
        x, z1, h1, z2 = cache
        out = [1.0 / (1.0 + math.exp(-max(-500, min(500, z)))) for z in z2]
        dz2 = [out[j] - target[j] for j in range(self.output_size)]
        # Update W2, b2
        for i in range(self.hidden_size):
            for j in range(self.output_size):
                self.W2[i][j] -= self.lr * h1[i] * dz2[j]
        for j in range(self.output_size):
            self.b2[j] -= self.lr * dz2[j]
        # Backprop to hidden
        dh1 = [sum(dz2[j] * self.W2[i][j] for j in range(self.output_size))
               for i in range(self.hidden_size)]
        dz1 = [dh1[i] * (1.0 if z1[i] > 0 else 0.0) for i in range(self.hidden_size)]
        # Update W1, b1
        for i in range(self.input_size):
            for j in range(self.hidden_size):
                self.W1[i][j] -= self.lr * x[i] * dz1[j]
        for j in range(self.hidden_size):
            self.b1[j] -= self.lr * dz1[j]

    def to_dict(self):
        return {'W1': self.W1, 'b1': self.b1, 'W2': self.W2, 'b2': self.b2,
                'is': self.input_size, 'hs': self.hidden_size, 'os': self.output_size}

    @classmethod
    def from_dict(cls, d):
        nn = cls(d.get('is', AI_NN_INPUT_SIZE), d.get('hs', AI_NN_HIDDEN_SIZE), d.get('os', 1))
        nn.W1, nn.b1, nn.W2, nn.b2 = d['W1'], d['b1'], d['W2'], d['b2']
        return nn


class AdaptiveStrategyEngine:
    """
    AI Strategy Engine v3 — Real machine learning for DPI bypass.
    Features: Neural Network scoring, Thompson Sampling exploration,
    concept drift detection, transfer learning, strategy group learning.
    Zero external dependencies — pure Python.
    """

    def __init__(self):
        self._data = self._default_data()
        self._dirty = False
        self._last_save = 0
        self._nn_cache = {}  # site_name -> MiniNN instance (lazy loaded)
        self._load()

    @staticmethod
    def _default_data():
        return {
            'version': 3,
            'sites': {},
            'global_weights': {
                s: {'w_success': 1.0, 'w_latency': 1.0, 'w_recency': 1.0, 'w_temporal': 1.0}
                for s in STRATEGY_ORDER
            },
            'global_priors': {},  # Transfer learning: global Beta priors per strategy
            'total_predictions': 0,
            'correct_predictions': 0,
        }

    def _load(self):
        try:
            with open(AI_STRATEGY_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                v = loaded.get('version', 1)
                if v in (2, 3):
                    self._data = loaded
                    # Migrate v2 -> v3
                    if v == 2:
                        self._data['version'] = 3
                        self._data.setdefault('global_priors', {})
                        for site_ai in self._data.get('sites', {}).values():
                            site_ai.setdefault('thompson', {})
                            site_ai.setdefault('nn_weights', None)
                        self._dirty = True
                        logger.info("[AI] Migrated model v2 -> v3")
            # Rebuild NN cache from loaded weights
            for sname, sai in self._data.get('sites', {}).items():
                if sai.get('nn_weights'):
                    try:
                        self._nn_cache[sname] = MiniNN.from_dict(sai['nn_weights'])
                    except Exception:
                        pass
            # Restore training intensity setting
            global _ai_train_intensity
            saved_intensity = self._data.get('train_intensity', 'light')
            if saved_intensity in AI_TRAIN_PROFILES:
                _ai_train_intensity = saved_intensity
            logger.info(f"[AI v3] Model loaded: {len(self._data.get('sites', {}))} sites, "
                        f"{self._data.get('total_predictions', 0)} predictions, "
                        f"train_intensity={_ai_train_intensity}")
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"[AI] Model load error: {e}")

    def _save_if_needed(self):
        if self._dirty and (time.time() - self._last_save) > AI_SAVE_INTERVAL:
            self._do_save()

    def _do_save(self):
        try:
            # Save training intensity setting
            self._data['train_intensity'] = _ai_train_intensity
            # Serialize NN weights before saving
            for sname, nn in self._nn_cache.items():
                if sname in self._data.get('sites', {}):
                    self._data['sites'][sname]['nn_weights'] = nn.to_dict()
            with open(AI_STRATEGY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, ensure_ascii=False)
            self._dirty = False
            self._last_save = time.time()
        except Exception as e:
            logger.error(f"[AI] Model save error: {e}")

    def force_save(self):
        if self._dirty:
            self._do_save()

    # ── Site Data ──

    def _get_site_ai(self, site_name):
        sites = self._data.setdefault('sites', {})
        if site_name not in sites:
            # Initialize with global priors (transfer learning)
            gp = self._data.get('global_priors', {})
            thompson_init = {}
            for strat in STRATEGY_ORDER:
                prior = gp.get(strat, {'alpha': 1.0, 'beta': 1.0})
                thompson_init[strat] = {'alpha': prior['alpha'], 'beta': prior['beta']}
            sites[site_name] = {
                'hour_matrix': {},
                'day_matrix': {},
                'recent': [],
                'strategy_scores': {},
                'total_observations': 0,
                'thompson': thompson_init,
                'nn_weights': None,
            }
        return sites[site_name]

    def _get_nn(self, site_name):
        """Get or create per-site neural network."""
        if site_name not in self._nn_cache:
            ai = self._data.get('sites', {}).get(site_name)
            if ai and ai.get('nn_weights'):
                try:
                    self._nn_cache[site_name] = MiniNN.from_dict(ai['nn_weights'])
                except Exception:
                    self._nn_cache[site_name] = MiniNN()
            else:
                self._nn_cache[site_name] = MiniNN()
        return self._nn_cache[site_name]

    # ── Thompson Sampling ──

    @staticmethod
    def _gamma_sample(shape):
        """Sample from Gamma(shape, 1) distribution. Pure Python, Marsaglia-Tsang method."""
        if shape <= 0:
            return 0.001
        if shape < 1.0:
            return AdaptiveStrategyEngine._gamma_sample(shape + 1.0) * (_rng.random() ** (1.0 / shape))
        d = shape - 1.0 / 3.0
        c = 1.0 / math.sqrt(9.0 * d)
        for _ in range(100):  # safety limit
            while True:
                x = _rng.gauss(0, 1)
                v = 1.0 + c * x
                if v > 0:
                    break
            v = v * v * v
            u = _rng.random()
            if u < 1.0 - 0.0331 * (x * x) * (x * x):
                return d * v
            if math.log(max(u, 1e-300)) < 0.5 * x * x + d * (1.0 - v + math.log(max(v, 1e-300))):
                return d * v
        return d  # fallback

    def _thompson_sample(self, ai, strategy):
        """Sample from Beta(alpha, beta) for this strategy using Thompson Sampling."""
        ts = ai.setdefault('thompson', {})
        params = ts.setdefault(strategy, {'alpha': 1.0, 'beta': 1.0})
        x = self._gamma_sample(params['alpha'])
        y = self._gamma_sample(params['beta'])
        return x / (x + y) if (x + y) > 1e-10 else 0.5

    # ── Feature Engineering ──

    def _build_features(self, ai, strategy, hour, day, current_time):
        """Build 10-element normalized feature vector for neural network."""
        pi2 = 2.0 * math.pi
        # Cyclical time encoding
        hour_sin = math.sin(pi2 * hour / 24.0) * 0.5 + 0.5
        hour_cos = math.cos(pi2 * hour / 24.0) * 0.5 + 0.5
        day_sin = math.sin(pi2 * day / 7.0) * 0.5 + 0.5
        day_cos = math.cos(pi2 * day / 7.0) * 0.5 + 0.5

        # EMA scores
        ema = ai['strategy_scores'].get(strategy, {})
        ema_success = ema.get('ema_success', 0.5)
        ema_latency = ema.get('ema_latency', 500.0)
        latency_norm = max(0.0, 1.0 - min(ema_latency / 2000.0, 1.0))

        # Temporal score
        hour_data = ai['hour_matrix'].get(str(hour), {}).get(strategy)
        temporal = 0.5
        if hour_data:
            total = hour_data['ok'] + hour_data['fail']
            if total >= 2:
                temporal = hour_data['ok'] / total

        # Recency
        recency = 0.0
        for obs in reversed(ai.get('recent', [])):
            if obs[0] == strategy and obs[1]:
                age = current_time - obs[5]
                recency = math.exp(-age / 3600.0)
                break

        # Observation density
        strat_obs = sum(1 for obs in ai.get('recent', []) if obs[0] == strategy)
        obs_norm = min(1.0, strat_obs / 10.0)

        # Streak score
        streak = 0.5
        for obs in reversed(ai.get('recent', [])):
            if obs[0] == strategy:
                if obs[1]:
                    streak = min(1.0, streak + 0.1)
                else:
                    streak = max(0.0, streak - 0.15)

        return [hour_sin, hour_cos, day_sin, day_cos,
                ema_success, latency_norm, temporal,
                recency, obs_norm, streak]

    # ── Concept Drift Detection ──

    def _detect_drift(self, ai):
        """Compare recent 20 vs previous 20 observations. Returns drift score 0.0-1.0."""
        recent = ai.get('recent', [])
        if len(recent) < 40:
            return 0.0
        window_new = recent[-20:]
        window_old = recent[-40:-20]
        new_ok = sum(1 for obs in window_new if obs[1])
        old_ok = sum(1 for obs in window_old if obs[1])
        rate_delta = abs(new_ok / 20.0 - old_ok / 20.0)
        # Check if winning strategy changed
        from collections import Counter
        new_wins = Counter(obs[0] for obs in window_new if obs[1])
        old_wins = Counter(obs[0] for obs in window_old if obs[1])
        new_top = new_wins.most_common(1)[0][0] if new_wins else None
        old_top = old_wins.most_common(1)[0][0] if old_wins else None
        strat_changed = 1.0 if (new_top and old_top and new_top != old_top) else 0.0
        return min(1.0, rate_delta * 2.0 + strat_changed * 0.3)

    def _apply_drift_response(self, ai, drift_score):
        """React to detected concept drift by boosting exploration."""
        if drift_score < 0.3:
            return
        logger.info(f"[AI] Concept drift detected (score={drift_score:.2f}), boosting exploration")
        decay = max(0.5, 1.0 - drift_score)
        # Decay temporal matrices
        for hour_strats in ai.get('hour_matrix', {}).values():
            for sd in hour_strats.values():
                sd['ok'] = int(sd['ok'] * decay)
                sd['fail'] = int(sd['fail'] * decay)
        for day_strats in ai.get('day_matrix', {}).values():
            for sd in day_strats.values():
                sd['ok'] = int(sd['ok'] * decay)
                sd['fail'] = int(sd['fail'] * decay)
        # Flatten Thompson priors
        flatten = max(0.3, 1.0 - drift_score)
        for params in ai.get('thompson', {}).values():
            params['alpha'] = max(1.0, params['alpha'] * flatten)
            params['beta'] = max(1.0, params['beta'] * flatten)
        # Pull EMA toward neutral
        for ema in ai.get('strategy_scores', {}).values():
            ema['ema_success'] = ema['ema_success'] * 0.7 + 0.5 * 0.3
        ai['_last_drift_time'] = time.time()
        ai['_drift_score'] = drift_score

    # ── Transfer Learning ──

    def _compute_global_reputation(self):
        """Aggregate success across all sites to build global Beta priors for new sites."""
        global_stats = {}
        for site_ai in self._data.get('sites', {}).values():
            for obs in site_ai.get('recent', []):
                gs = global_stats.setdefault(obs[0], {'ok': 0, 'fail': 0})
                if obs[1]:
                    gs['ok'] += 1
                else:
                    gs['fail'] += 1
        priors = {}
        for strat, gs in global_stats.items():
            priors[strat] = {
                'alpha': 1.0 + gs['ok'] * 0.1,
                'beta': 1.0 + gs['fail'] * 0.1,
            }
        self._data['global_priors'] = priors
        return priors

    # ── Core: Record ──

    def record(self, site_name, strategy, success, elapsed_ms):
        """Record an observation and update all AI models online."""
        now = datetime.now()
        hour = str(now.hour)
        day = str(now.weekday())
        ai = self._get_site_ai(site_name)

        # 1. Update hour matrix
        hm = ai['hour_matrix'].setdefault(hour, {})
        hs = hm.setdefault(strategy, {'ok': 0, 'fail': 0, 'total_ms': 0.0})
        if success:
            hs['ok'] += 1
            hs['total_ms'] += elapsed_ms
        else:
            hs['fail'] += 1

        # 2. Update day matrix
        dm = ai['day_matrix'].setdefault(day, {})
        ds = dm.setdefault(strategy, {'ok': 0, 'fail': 0})
        if success:
            ds['ok'] += 1
        else:
            ds['fail'] += 1

        # 3. Update ring buffer (expanded to 100)
        ai['recent'].append([strategy, success, round(elapsed_ms, 1), int(hour), int(day), time.time()])
        if len(ai['recent']) > AI_RING_BUFFER_SIZE:
            ai['recent'] = ai['recent'][-AI_RING_BUFFER_SIZE:]

        # 4. Update EMA
        ema = ai['strategy_scores'].setdefault(strategy, {'ema_success': 0.5, 'ema_latency': 500.0})
        alpha = 0.2
        ema['ema_success'] = ema['ema_success'] * (1 - alpha) + (1.0 if success else 0.0) * alpha
        ema['ema_latency'] = ema['ema_latency'] * (1 - alpha) + elapsed_ms * alpha

        ai['total_observations'] += 1

        # 5. Thompson Sampling update
        ts = ai.setdefault('thompson', {})
        params = ts.setdefault(strategy, {'alpha': 1.0, 'beta': 1.0})
        if success:
            params['alpha'] += 1.0
        else:
            params['beta'] += 1.0
        # Periodic decay to prevent unbounded growth
        if ai['total_observations'] % AI_THOMPSON_DECAY_INTERVAL == 0:
            for sp in ts.values():
                sp['alpha'] = max(1.0, sp['alpha'] * AI_DECAY_FACTOR)
                sp['beta'] = max(1.0, sp['beta'] * AI_DECAY_FACTOR)

        # 6. Strategy group learning: siblings get 20% signal
        group = STRATEGY_TO_GROUP.get(strategy)
        if group:
            siblings = [s for s in STRATEGY_GROUPS[group] if s != strategy]
            for sib in siblings:
                sib_params = ts.setdefault(sib, {'alpha': 1.0, 'beta': 1.0})
                if success:
                    sib_params['alpha'] += 0.2
                else:
                    sib_params['beta'] += 0.2

        # 7. Update global weights
        gw = self._data['global_weights'].setdefault(strategy, {
            'w_success': 1.0, 'w_latency': 1.0, 'w_recency': 1.0, 'w_temporal': 1.0
        })
        if success:
            gw['w_success'] = min(3.0, gw['w_success'] + 0.01)
            if elapsed_ms < 300:
                gw['w_latency'] = min(3.0, gw['w_latency'] + 0.005)
        else:
            gw['w_success'] = max(0.1, gw['w_success'] - 0.02)

        # 8. Neural network online learning (backprop)
        try:
            nn = self._get_nn(site_name)
            features = self._build_features(ai, strategy, int(hour), int(day), time.time())
            _, cache = nn.forward(features)
            nn.backward(cache, [1.0 if success else 0.0])
        except Exception:
            pass  # NN errors should never block proxy

        self._dirty = True
        self._save_if_needed()

    # ── Core: Predict ──

    def predict(self, site_name, count_as_prediction=False):
        """Return strategies sorted by predicted score (best first).
        Uses Thompson Sampling + Neural Network + linear scoring blend."""
        ai = self._get_site_ai(site_name)
        now = datetime.now()
        hour = now.hour
        day = now.weekday()
        current_time = time.time()

        if ai['total_observations'] < AI_MIN_SAMPLES:
            return None

        # Drift detection (throttled to every 60s)
        last_drift_check = ai.get('_last_drift_check', 0)
        if current_time - last_drift_check > AI_DRIFT_CHECK_INTERVAL:
            ai['_last_drift_check'] = current_time
            drift = self._detect_drift(ai)
            if drift > 0.3:
                self._apply_drift_response(ai, drift)

        scores = []
        nn = self._get_nn(site_name)

        for strat in STRATEGY_ORDER:
            # Linear composite score (legacy, always available)
            linear_score, confidence = self._score_strategy_linear(ai, strat, hour, day, current_time)

            # Neural network score
            nn_score = 0.5
            try:
                features = self._build_features(ai, strat, hour, day, current_time)
                nn_out, _ = nn.forward(features)
                nn_score = nn_out[0]
            except Exception:
                pass

            # Blend: NN weight increases with more observations
            blend = min(1.0, ai['total_observations'] / 100.0)
            base_score = blend * nn_score + (1.0 - blend) * linear_score

            # Thompson Sampling for exploration
            thompson = self._thompson_sample(ai, strat)

            # Combined: 60% model score + 40% Thompson exploration
            combined = 0.6 * base_score + 0.4 * thompson
            scores.append((strat, round(combined, 4), round(confidence, 2)))

        scores.sort(key=lambda x: x[1], reverse=True)

        # Log exploration when Thompson causes non-obvious picks
        if len(scores) > 1 and count_as_prediction:
            # Check if Thompson shuffled the top
            linear_top = max(STRATEGY_ORDER, key=lambda s: self._score_strategy_linear(
                ai, s, hour, day, current_time)[0])
            if scores[0][0] != linear_top:
                logger.debug(f"[AI] Exploring: {scores[0][0]} for {site_name} (Thompson)")

        if count_as_prediction:
            self._data['total_predictions'] = self._data.get('total_predictions', 0) + 1
            self._data.setdefault('_last_predictions', {})[site_name] = scores[0][0]

        return scores

    def _score_strategy_linear(self, ai, strategy, hour, day, current_time):
        """Linear composite scoring (legacy method, used as NN fallback)."""
        gw = self._data['global_weights'].get(strategy, {
            'w_success': 1.0, 'w_latency': 1.0, 'w_recency': 1.0, 'w_temporal': 1.0
        })
        ema = ai['strategy_scores'].get(strategy, {})
        ema_success = ema.get('ema_success', 0.5)
        ema_latency = ema.get('ema_latency', 500.0)

        # Temporal
        temporal_score = 0.5
        hour_data = ai['hour_matrix'].get(str(hour), {}).get(strategy)
        if hour_data:
            total = hour_data['ok'] + hour_data['fail']
            if total >= 2:
                temporal_score = hour_data['ok'] / total
        day_data = ai['day_matrix'].get(str(day), {}).get(strategy)
        day_score = 0.5
        if day_data:
            total = day_data['ok'] + day_data['fail']
            if total >= 2:
                day_score = day_data['ok'] / total
        temporal_combined = temporal_score * 0.7 + day_score * 0.3

        latency_score = max(0.0, 1.0 - (ema_latency / 2000.0))

        recency_score = 0.0
        for obs in reversed(ai.get('recent', [])):
            if obs[0] == strategy and obs[1]:
                age = current_time - obs[5]
                recency_score = math.exp(-age / 3600.0)
                break

        strat_obs = sum(1 for obs in ai.get('recent', []) if obs[0] == strategy)
        confidence = min(1.0, strat_obs / 10.0)

        score = (
            gw['w_success']  * ema_success      * 0.35 +
            gw['w_temporal'] * temporal_combined * 0.30 +
            gw['w_latency']  * latency_score    * 0.20 +
            gw['w_recency']  * recency_score    * 0.15
        )
        score *= (0.8 + 0.2 * confidence)
        return round(score, 4), round(confidence, 2)

    # ── Prediction Tracking ──

    def record_prediction_result(self, site_name, winning_strategy):
        last_preds = self._data.get('_last_predictions', {})
        predicted = last_preds.get(site_name)
        if predicted and predicted == winning_strategy:
            self._data['correct_predictions'] = self._data.get('correct_predictions', 0) + 1

    def get_accuracy(self):
        total = self._data.get('total_predictions', 0)
        correct = self._data.get('correct_predictions', 0)
        if total == 0:
            return 0.0
        return round((correct / total) * 100, 1)

    # ── Dashboard Data ──

    def get_site_insights(self, site_name):
        ai = self._data.get('sites', {}).get(site_name)
        if not ai or ai['total_observations'] < AI_MIN_SAMPLES:
            return None
        predictions = self.predict(site_name)
        if not predictions:
            return None
        top = predictions[0]
        # Thompson params for top strategy
        ts = ai.get('thompson', {}).get(top[0], {'alpha': 1, 'beta': 1})
        insights = {
            'ai_active': True,
            'predicted_strategy': top[0],
            'confidence': top[1],
            'score': top[2],
            'total_observations': ai['total_observations'],
            'top_3': [{'strategy': p[0], 'score': p[1], 'confidence': p[2]} for p in predictions[:3]],
            'thompson_alpha': round(ts['alpha'], 1),
            'thompson_beta': round(ts['beta'], 1),
            'drift_score': round(ai.get('_drift_score', 0.0), 2),
            'nn_active': site_name in self._nn_cache,
        }
        # Hourly heatmap
        hour_best = {}
        for h, strats in ai.get('hour_matrix', {}).items():
            best_strat, best_rate = None, 0
            for s, data in strats.items():
                total = data['ok'] + data['fail']
                if total >= 2:
                    rate = data['ok'] / total
                    if rate > best_rate:
                        best_rate = rate
                        best_strat = s
            if best_strat:
                hour_best[h] = {'strategy': best_strat, 'rate': round(best_rate, 2)}
        insights['hour_best'] = hour_best
        return insights

    def get_global_stats(self):
        total_obs = sum(s.get('total_observations', 0) for s in self._data.get('sites', {}).values())
        total_success = sum(
            sum(1 for obs in s.get('recent', []) if obs[1])
            for s in self._data.get('sites', {}).values()
        )
        nn_sites = len(self._nn_cache)
        drift_active = sum(
            1 for s in self._data.get('sites', {}).values()
            if s.get('_drift_score', 0) > 0.3
        )
        return {
            'total_predictions': self._data.get('total_predictions', 0),
            'correct_predictions': self._data.get('correct_predictions', 0),
            'accuracy': self.get_accuracy(),
            'sites_with_data': sum(
                1 for s in self._data.get('sites', {}).values()
                if s.get('total_observations', 0) >= AI_MIN_SAMPLES
            ),
            'total_observations': total_obs,
            'total_success': total_success,
            'success_rate': round((total_success / total_obs * 100), 1) if total_obs > 0 else 0,
            'global_weights': self._data.get('global_weights', {}),
            'nn_active_sites': nn_sites,
            'drift_active': drift_active,
            'engine_version': 3,
        }

    def reset(self):
        self._data = self._default_data()
        self._nn_cache.clear()
        self._dirty = True
        self._do_save()
        logger.info("[AI v3] Model reset")


_ai_engine = AdaptiveStrategyEngine()

# ==================== AI TRAINING ENGINE ====================

async def _probe_strategy(test_ip, test_domain, strat_name):
    """Single strategy probe: verified TLS handshake with cert and hostname validation."""
    result = await _verify_tls_strategy(test_ip, test_domain, strat_name, timeout=8)
    return result['ok'], result['elapsed_ms'] if result['ok'] else 0

async def _self_training_loop():
    """Background task: periodically probe underexplored strategies for all sites."""
    global _ai_train_intensity
    # Nonstop mode starts faster, others wait 5 minutes
    init_wait = 60 if _ai_train_intensity == 'nonstop' else 300
    await asyncio.sleep(init_wait)
    while _running:
        try:
            profile = AI_TRAIN_PROFILES.get(_ai_train_intensity, AI_TRAIN_PROFILES['light'])
            await asyncio.sleep(profile['interval'])
            if _training_state.get('active'):
                continue
            max_probes = profile['probes']
            # Recompute global reputation for transfer learning
            _ai_engine._compute_global_reputation()
            _self_train_state['running'] = True
            _self_train_state['cycle_count'] += 1
            _self_train_state['last_run'] = time.time()
            logger.info(f"[SELF-TRAIN] Cycle #{_self_train_state['cycle_count']} ({_ai_train_intensity} mode, {max_probes} probes, every {profile['interval']}s)")
            for site_name, site_cfg in _config.get('sites', {}).items():
                if not site_cfg.get('enabled', True) or not _running:
                    continue
                ai = _ai_engine._get_site_ai(site_name)
                # Nonstop/heavy modes train even with fewer observations
                min_obs = AI_MIN_SAMPLES if _ai_train_intensity in ('light', 'medium') else 1
                if ai['total_observations'] < min_obs:
                    continue
                # Find underexplored strategies
                obs_counts = {}
                for obs in ai.get('recent', []):
                    obs_counts[obs[0]] = obs_counts.get(obs[0], 0) + 1
                # Higher intensity = higher threshold for "explored"
                explore_threshold = 3 if _ai_train_intensity == 'light' else (5 if _ai_train_intensity == 'medium' else 10)
                underexplored = [s for s in STRATEGY_ORDER if obs_counts.get(s, 0) < explore_threshold]
                if not underexplored:
                    # In nonstop mode, re-test all strategies even if explored
                    if _ai_train_intensity == 'nonstop':
                        underexplored = list(STRATEGY_ORDER)
                    else:
                        continue
                to_test = _rng.sample(underexplored, min(max_probes, len(underexplored)))
                # Get test IP
                domains = site_cfg.get('dns_resolve', site_cfg.get('domains', []))
                test_domain = domains[0] if domains else f"{site_name}.com"
                test_ip = get_bypass_ip(test_domain)
                if not test_ip or test_ip == test_domain.lower():
                    continue
                _self_train_state['last_site'] = site_name
                logger.info(f"[SELF-TRAIN] {site_name}: probing {[s[:12] for s in to_test]}")
                for strat_name in to_test:
                    if not _running:
                        break
                    _self_train_state['last_strategy'] = strat_name
                    probe = await _verify_tls_strategy(test_ip, test_domain, strat_name, timeout=8)
                    success, elapsed_ms = probe['ok'], probe['elapsed_ms']
                    _ai_engine.record(site_name, strat_name, success, elapsed_ms)
                    _self_train_state['total_probes'] += 1
                    if success:
                        _strategy_cache.record_success(site_name, strat_name, elapsed_ms)
                        _self_train_state['last_result'] = f"{strat_name} OK ({elapsed_ms}ms)"
                        logger.info(f"[SELF-TRAIN] {site_name}: {strat_name} ✓ ({elapsed_ms}ms)")
                    else:
                        _strategy_cache.record_failure(site_name, strat_name)
                        _self_train_state['last_result'] = f"{strat_name} FAIL ({probe['reason']})"
                        logger.info(f"[SELF-TRAIN] {site_name}: {strat_name} failed ({probe['reason']}: {probe['detail']})")
                        logger.info(f"[SELF-TRAIN] {site_name}: {strat_name} ✗")
                    await asyncio.sleep(0.5 if _ai_train_intensity == 'nonstop' else 1.0)
            _self_train_state['running'] = False
        except Exception as e:
            _self_train_state['running'] = False
            logger.info(f"[SELF-TRAIN] Error: {e}")

async def _train_site(site_name):
    """Test all strategies for a single site via real TLS handshake. Does not affect live traffic."""
    site_cfg = _config.get('sites', {}).get(site_name)
    if not site_cfg:
        return
    domains = site_cfg.get('dns_resolve', site_cfg.get('domains', []))
    test_domain = domains[0] if domains else f"{site_name}.com"

    # Get an IP to connect to
    test_ip = get_bypass_ip(test_domain)
    if not test_ip or test_ip == test_domain.lower():
        loop = asyncio.get_event_loop()
        try:
            ips = await loop.run_in_executor(None, _resolve_domain_doh, test_domain)
            if ips:
                test_ip = ips[0]
            else:
                logger.warning(f"[TRAIN] {site_name}: no IPs found for {test_domain}")
                return
        except Exception:
            return

    strat_list = list(STRATEGY_FUNCS.keys())
    total = len(strat_list)
    results = []

    _training_state['progress'][site_name] = {
        'current_strat': '', 'tested': 0, 'total': total, 'pct': 0
    }

    for idx, strat_name in enumerate(strat_list):
        if not _training_state['active']:
            break  # Training was cancelled

        _training_state['progress'][site_name]['current_strat'] = strat_name
        _training_state['progress'][site_name]['tested'] = idx
        _training_state['progress'][site_name]['pct'] = int((idx / total) * 100)

        probe = await _verify_tls_strategy(test_ip, test_domain, strat_name, timeout=8)
        success = probe['ok']
        elapsed_ms = probe['elapsed_ms']

        results.append({
            'strategy': strat_name,
            'success': success,
            'ms': elapsed_ms if success else 0,
            'reason': None if success else probe['reason']
        })

        if success:
            logger.info(f"[TRAIN] {site_name}: {strat_name} ✓ ({elapsed_ms}ms)")
        else:
            logger.debug(f"[TRAIN] {site_name}: {strat_name} ✗")

        # Small delay between tests to not overwhelm server/DPI
        await asyncio.sleep(0.5)

    # Update progress to 100%
    _training_state['progress'][site_name] = {
        'current_strat': 'done', 'tested': total, 'total': total, 'pct': 100
    }

    # Find best strategy
    successful = [r for r in results if r['success']]
    if successful:
        best = min(successful, key=lambda r: r['ms'])
        _training_state['results'][site_name] = {
            'best_strategy': best['strategy'],
            'best_ms': best['ms'],
            'success_count': len(successful),
            'total_tested': total,
            'all_results': results
        }
        logger.info(f"[TRAIN] {site_name}: best = {best['strategy']} ({best['ms']}ms), "
                     f"{len(successful)}/{total} strategies worked")
    else:
        _training_state['results'][site_name] = {
            'best_strategy': None,
            'best_ms': 0,
            'success_count': 0,
            'total_tested': total,
            'all_results': results
        }
        logger.warning(f"[TRAIN] {site_name}: no strategies succeeded")


def _build_client_hello(hostname):
    """Build a minimal TLS 1.2 ClientHello with SNI for training tests."""
    host_bytes = hostname.encode('ascii')
    # SNI extension
    sni_ext = (
        b'\x00\x00'  # Extension type: server_name
        + (len(host_bytes) + 5).to_bytes(2, 'big')  # Extension length
        + (len(host_bytes) + 3).to_bytes(2, 'big')  # Server Name List length
        + b'\x00'  # Host name type
        + len(host_bytes).to_bytes(2, 'big')  # Host name length
        + host_bytes
    )
    # Supported versions extension (TLS 1.2, 1.3)
    sv_ext = b'\x00\x2b\x00\x03\x02\x03\x03'
    extensions = sni_ext + sv_ext
    # Cipher suites (common ones)
    ciphers = (
        b'\x13\x01\x13\x02\x13\x03'  # TLS 1.3
        b'\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f'  # ECDHE
        b'\x00\x9e\x00\x9f\x00\x67\x00\x6b'  # DHE
        b'\x00\xff'  # Renegotiation info
    )
    client_random = random.randbytes(32) if hasattr(random, 'randbytes') else bytes(random.getrandbits(8) for _ in range(32))
    # Handshake body
    body = (
        b'\x03\x03'  # Client version TLS 1.2
        + client_random  # Random
        + b'\x00'  # Session ID length = 0
        + len(ciphers).to_bytes(2, 'big') + ciphers
        + b'\x01\x00'  # Compression methods: null
        + len(extensions).to_bytes(2, 'big') + extensions
    )
    # Handshake message
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    # TLS record
    record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    return record


async def _train_all_sites():
    """Run strategy training for all enabled sites."""
    global _training_state
    _training_state['active'] = True
    _training_state['completed'] = False
    _training_state['progress'] = {}
    _training_state['results'] = {}
    logger.info("[TRAIN] Strategy training started for all sites")

    enabled_sites = [
        name for name, cfg in _config.get('sites', {}).items()
        if cfg.get('enabled', True)
    ]

    for site_name in enabled_sites:
        if not _training_state['active']:
            break
        await _train_site(site_name)

    _training_state['active'] = False
    _training_state['completed'] = True
    logger.info(f"[TRAIN] Training complete. Results for {len(_training_state['results'])} sites.")


def _apply_training(site_name):
    """Feed training results into the AI engine so it naturally learns the best strategy."""
    result = _training_state['results'].get(site_name)
    if not result or not result.get('all_results'):
        return False

    # Save current AI data snapshot for revert
    ai_data = _ai_engine._data.get('sites', {}).get(site_name)
    if ai_data:
        import copy
        _training_state['previous_strategies'][site_name] = copy.deepcopy(ai_data)
    else:
        _training_state['previous_strategies'][site_name] = None

    # Reset AI data for this site so training results have full weight
    if site_name in _ai_engine._data.get('sites', {}):
        del _ai_engine._data['sites'][site_name]

    # Also reset strategy cache for this site
    if site_name in _strategy_cache._data.get('sites', {}):
        del _strategy_cache._data['sites'][site_name]
        _strategy_cache._dirty = True

    # Inject all training results as observations into the AI engine
    for r in result['all_results']:
        if r['success']:
            # Record successful strategies multiple times for stronger signal
            for _ in range(5):
                _ai_engine.record(site_name, r['strategy'], True, r['ms'])
                _strategy_cache.record_success(site_name, r['strategy'], r['ms'])
        else:
            _ai_engine.record(site_name, r['strategy'], False, 0)
            _strategy_cache.record_failure(site_name, r['strategy'])

    _ai_engine._dirty = True
    _ai_engine._do_save()
    _strategy_cache._do_save()

    best = result.get('best_strategy', '?')
    logger.info(f"[TRAIN] Fed {len(result['all_results'])} training results into AI for {site_name}. "
                 f"AI should now prefer '{best}'")
    return True


def _revert_training(site_name):
    """Revert AI data to pre-training state."""
    old_ai_data = _training_state['previous_strategies'].get(site_name)
    if old_ai_data is None and site_name not in _training_state['previous_strategies']:
        return False

    # Restore old AI data
    if old_ai_data is not None:
        _ai_engine._data.setdefault('sites', {})[site_name] = old_ai_data
    else:
        _ai_engine._data.get('sites', {}).pop(site_name, None)

    _ai_engine._dirty = True
    _ai_engine._do_save()

    # Reset strategy cache for fresh start
    if site_name in _strategy_cache._data.get('sites', {}):
        del _strategy_cache._data['sites'][site_name]
        _strategy_cache._dirty = True
        _strategy_cache._do_save()

    del _training_state['previous_strategies'][site_name]
    logger.info(f"[TRAIN] Reverted AI data for {site_name} to pre-training state")
    return True

# ==================== PROXY ====================

async def _tunnel_plain(c_reader, c_writer, s_reader, s_writer):
    async def client_to_server():
        try:
            while True:
                data = await c_reader.read(8192)
                if not data:
                    break
                s_writer.write(data)
                await s_writer.drain()
        except:
            pass

    async def server_to_client():
        try:
            while True:
                data = await s_reader.read(8192)
                if not data:
                    break
                c_writer.write(data)
                await c_writer.drain()
        except:
            pass

    tasks = [asyncio.create_task(client_to_server()), asyncio.create_task(server_to_client())]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()


async def _try_connect(host, port, alt_ips=None, timeout=10):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return r, w
    except Exception as e:
        logger.debug(f"Connection failed {host}:{port} -> {e}")
    if alt_ips:
        for alt_ip in alt_ips:
            if alt_ip == host:
                continue
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(alt_ip, port), timeout=8)
                return r, w
            except Exception:
                continue
    return None, None


async def _handle_http_forward(initial_data, client_reader, client_writer):
    """Forward plain HTTP requests (GET/POST etc.) to the target server."""
    s_writer = None
    try:
        first_line = initial_data.split(b'\r\n')[0].decode('utf-8', errors='replace')
        parts = first_line.split(' ')
        if len(parts) < 3:
            return

        method, url, version = parts[0], parts[1], parts[2]

        # Parse URL: http://host[:port]/path
        if url.startswith('http://'):
            url_body = url[7:]
        else:
            url_body = url

        slash_idx = url_body.find('/')
        if slash_idx == -1:
            host_part = url_body
            path = '/'
        else:
            host_part = url_body[:slash_idx]
            path = url_body[slash_idx:]

        if ':' in host_part:
            target_host, target_port = host_part.rsplit(':', 1)
            target_port = int(target_port)
        else:
            target_host = host_part
            target_port = 80

        logger.info(f"[HTTP-FORWARD] {method} {target_host}:{target_port}{path[:60]}")

        # Connect to target
        s_reader, s_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port), timeout=15
        )

        # Rewrite request: absolute URL -> relative path, fix Host header
        header_end = initial_data.find(b'\r\n\r\n')
        if header_end == -1:
            return
        header_bytes = initial_data[:header_end]
        body_bytes = initial_data[header_end:]  # includes \r\n\r\n + any body

        # Replace first line with relative path
        first_line_end = header_bytes.find(b'\r\n')
        new_first_line = f'{method} {path} {version}'.encode()
        rest_headers = header_bytes[first_line_end:]  # starts with \r\n

        # Ensure Host header exists
        if b'Host:' not in rest_headers and b'host:' not in rest_headers:
            rest_headers = f'\r\nHost: {host_part}'.encode() + rest_headers

        rewritten = new_first_line + rest_headers + body_bytes
        s_writer.write(rewritten)
        await s_writer.drain()

        # Relay response back and forth
        await _tunnel_plain(client_reader, client_writer, s_reader, s_writer)

    except Exception as e:
        logger.debug(f"[HTTP-FORWARD] Error: {e}")
    finally:
        if s_writer:
            try:
                s_writer.close()
            except:
                pass


async def handle_proxy_client(reader, writer):
    s_writer = None
    _sem_acquired = False
    _sem_site = None
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=30)
        if not data:
            return

        first_line = data.split(b'\n')[0]

        # Handle HTTP (non-CONNECT) requests: forward them directly
        if b'CONNECT' not in first_line:
            await _handle_http_forward(data, reader, writer)
            return

        parts = first_line.split(b' ')
        if len(parts) < 2:
            return
        host_port = parts[1].split(b':')
        if len(host_port) != 2:
            return
        target_host = host_port[0].decode('utf-8')
        target_port = int(host_port[1])

        site_name = _find_site_for_host(target_host)
        should_bypass = site_name is not None
        target_lower = target_host.lower()



        # Fast-fail: skip if this domain was recently marked as fully blocked
        if should_bypass and target_lower in _blocked_domains:
            if (time.time() - _blocked_domains[target_lower]) < BLOCKED_DOMAIN_TTL:
                logger.debug(f"[FAST-FAIL] {target_host} blocked (cache)")
                return
            else:
                del _blocked_domains[target_lower]

        bypass_ip = get_bypass_ip(target_host) if should_bypass else None

        # Real-time DoH resolution (if no IPs found yet)
        if should_bypass and bypass_ip == target_lower:
            loop = asyncio.get_event_loop()
            try:
                ips = await loop.run_in_executor(None, _resolve_domain_doh, target_lower)
                if ips:
                    _domain_ips[target_lower] = ips
                    bypass_ip = random.choice(ips)
            except:
                pass

        connect_host = bypass_ip if bypass_ip else target_host
        _stats['connections'] += 1

        # Non-bypass: direct tunnel
        if not should_bypass:
            logger.info(f"[PASSTHROUGH] {target_host}:{target_port}")
            s_reader, s_writer = await _try_connect(connect_host, target_port)
            if not s_writer:
                return
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            await _tunnel_plain(reader, writer, s_reader, s_writer)
            return

        # Bypass: strategy trial
        is_main = _is_main_domain(target_host, site_name)
        if site_name not in _site_stats:
            _site_stats[site_name] = {'connections': 0, 'successes': 0, 'failures': 0, 'total_ms': 0}
        _site_stats[site_name]['connections'] += 1
        logger.info(f"[BYPASS] {target_host} -> {connect_host} ({'MAIN' if is_main else 'CDN'})")

        # Per-site concurrency limiter
        if site_name not in _site_semaphores:
            _site_semaphores[site_name] = asyncio.Semaphore(SITE_MAX_CONCURRENT)
        _sem_site = site_name
        try:
            await asyncio.wait_for(_site_semaphores[site_name].acquire(), timeout=30)
            _sem_acquired = True
        except asyncio.TimeoutError:
            logger.debug(f"[THROTTLE] {target_host} too many concurrent, dropping")
            return

        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()

        try:
            first_chunk = await asyncio.wait_for(reader.read(8192), timeout=10)
        except asyncio.TimeoutError:
            return
        if not first_chunk:
            return

        strategies = _strategy_cache.get_strategy_order(site_name, is_main=is_main)
        sd = _strategy_cache._get_site_data(site_name)
        has_best = sd.get('best_strategy') and sd['best_strategy'] != 'direct'
        if not is_main:
            if has_best:
                # CDN: use site's proven strategy, limit to 3 strategies max
                strategies = [s for s in strategies if s != 'direct'][:3]
            elif 'direct' not in strategies:
                strategies = ['direct'] + strategies

        domain_ips = get_domain_ips(target_host)
        pool_1 = domain_ips if domain_ips else [connect_host]
        ip_pools_to_try = [pool_1]

        site_ips = get_site_ips(target_host)
        if site_ips:
            fallback = [ip for ip in site_ips if ip not in pool_1]
            if fallback:
                ip_pools_to_try.append(fallback)

        # CDN domain retry limit: max 2 IPs to try
        max_ips_per_pool = 2 if not is_main else len(pool_1)

        success = False
        all_conn_failed = True  # All IPs connection failed?

        for ip_pool in ip_pools_to_try:
            random.shuffle(ip_pool)
            ips_tried = 0
            for try_ip in ip_pool:
                if ips_tried >= max_ips_per_pool:
                    break
                ips_tried += 1
                for strat_name in strategies:
                    _stats['strategy_tries'] += 1
                    probe = await _verify_tls_strategy(try_ip, target_host, strat_name, port=target_port, timeout=STRATEGY_SUCCESS_TIMEOUT)
                    if not probe['ok']:
                        logger.info(f"[STRATEGY] {site_name}: {strat_name} failed ({probe['reason']}: {probe['detail']}) IP:{try_ip}")
                        _strategy_cache.record_failure(site_name, strat_name)
                        _ai_engine.record(site_name, strat_name, False, 0)
                        _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': strat_name, 'ms': 0, 'success': False})
                        _stats['strategy_fallbacks'] += 1
                        continue

                    s_reader, s_writer = await _try_connect(try_ip, target_port, timeout=8)
                    if not s_writer:
                        logger.info(f"[STRATEGY] {site_name}: {strat_name} failed (connection_failed: could not open tunnel) IP:{try_ip}")
                        _strategy_cache.record_failure(site_name, strat_name)
                        _ai_engine.record(site_name, strat_name, False, 0)
                        _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': strat_name, 'ms': 0, 'success': False})
                        _stats['strategy_fallbacks'] += 1
                        continue

                    try:
                        await STRATEGY_FUNCS[strat_name](s_writer, first_chunk)
                    except Exception as e:
                        logger.info(f"[STRATEGY] {site_name}: {strat_name} failed ({e}) IP:{try_ip}")
                        _close_writer(s_writer)
                        _strategy_cache.record_failure(site_name, strat_name)
                        _ai_engine.record(site_name, strat_name, False, 0)
                        _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': strat_name, 'ms': 0, 'success': False})
                        _stats['strategy_fallbacks'] += 1
                        continue

                    try:
                        server_reply = await asyncio.wait_for(s_reader.read(8192), timeout=STRATEGY_SUCCESS_TIMEOUT)
                        if not server_reply:
                            raise ConnectionError("Empty response")
                        if len(server_reply) >= 2 and server_reply[0] == 0x15:
                            raise ConnectionError("TLS Alert")
                        if len(server_reply) >= 3 and server_reply[0] != 0x16:
                            raise ConnectionError("Invalid TLS response")
                    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                        logger.info(f"[STRATEGY] {site_name}: {strat_name} failed ({e}) IP:{try_ip}")
                        _close_writer(s_writer)
                        _strategy_cache.record_failure(site_name, strat_name)
                        _ai_engine.record(site_name, strat_name, False, 0)
                        _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': strat_name, 'ms': 0, 'success': False})
                        _stats['strategy_fallbacks'] += 1
                        continue

                    # Success - at least one connection worked
                    all_conn_failed = False
                    elapsed_ms = probe['elapsed_ms']
                    _strategy_cache.record_success(site_name, strat_name, elapsed_ms)
                    _ai_engine.record(site_name, strat_name, True, elapsed_ms)
                    _ai_engine.record_prediction_result(site_name, strat_name)
                    _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': strat_name, 'ms': round(elapsed_ms), 'success': True})
                    if site_name in _site_stats:
                        _site_stats[site_name]['successes'] += 1
                        _site_stats[site_name]['total_ms'] += elapsed_ms
                    logger.info(f"[STRATEGY] {site_name}: {strat_name} success ({elapsed_ms:.0f}ms) IP:{try_ip}")

                    writer.write(server_reply)
                    await writer.drain()
                    await _tunnel_plain(reader, writer, s_reader, s_writer)
                    success = True
                    break

                if success:
                    break
            if success:
                return

        # Last resort: direct hostname connection
        if connect_host != target_host:
            logger.info(f"[FALLBACK] {target_host} trying via hostname...")
            for fallback_strat in ['direct', 'tls_record_frag', 'fragment_burst', 'desync']:
                probe = await _verify_tls_strategy(target_host, target_host, fallback_strat, port=target_port, timeout=8)
                if not probe['ok']:
                    logger.info(f"[FALLBACK] {target_host}: {fallback_strat} failed ({probe['reason']}: {probe['detail']})")
                    continue
                s_reader_h, s_writer_h = await _try_connect(target_host, target_port, timeout=8)
                if not s_writer_h:
                    logger.info(f"[FALLBACK] {target_host}: {fallback_strat} failed (connection_failed: could not open tunnel)")
                    continue
                try:
                    await STRATEGY_FUNCS[fallback_strat](s_writer_h, first_chunk)
                    server_reply = await asyncio.wait_for(s_reader_h.read(8192), timeout=8)
                    if server_reply and len(server_reply) >= 1 and server_reply[0] == 0x16:
                        elapsed_ms = probe['elapsed_ms']
                        _strategy_cache.record_success(site_name, fallback_strat, elapsed_ms)
                        _ai_engine.record(site_name, fallback_strat, True, elapsed_ms)
                        _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': fallback_strat, 'ms': round(elapsed_ms), 'success': True})
                        logger.info(f"[FALLBACK] {target_host}: {fallback_strat} success ({elapsed_ms:.0f}ms)")
                        writer.write(server_reply)
                        await writer.drain()
                        await _tunnel_plain(reader, writer, s_reader_h, s_writer_h)
                        return
                except Exception:
                    pass
                _close_writer(s_writer_h)

        # Record per-site failure
        if site_name in _site_stats:
            _site_stats[site_name]['failures'] += 1
        # If CDN domain is fully blocked, save for fast-fail on next requests
        if all_conn_failed and not is_main:
            _blocked_domains[target_lower] = time.time()
            logger.warning(f"[BLOCKED] {target_host} fully blocked, {BLOCKED_DOMAIN_TTL}s fast-fail active")
        else:
            logger.error(f"All strategies failed: {target_host}")

    except Exception as e:
        logger.debug(f"Proxy error: {e}")
    finally:
        if _sem_acquired and _sem_site and _sem_site in _site_semaphores:
            try:
                _site_semaphores[_sem_site].release()
            except ValueError:
                pass
        for w in (s_writer, writer):
            _close_writer(w)

# ==================== WEB DASHBOARD ====================

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CleanNet Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0b0d14;--surface:#111420;--surface2:#171b2d;--surface3:#1e2235;--border:#252940;--border2:#2d3250;--accent:#818cf8;--accent2:#6366f1;--accent-glow:#818cf825;--green:#34d399;--red:#f87171;--orange:#fbbf24;--cyan:#22d3ee;--purple:#a78bfa;--pink:#ec4899;--text:#d0d5e8;--text2:#8890a8;--text3:#585e78;--mono:'JetBrains Mono',Consolas,monospace;--sans:'Inter','Segoe UI',system-ui,sans-serif}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--text3)}
.hdr{background:var(--surface);padding:0 24px;height:56px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}
.hdr h1{font-size:17px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-.3px}
.hdr .tag{background:var(--accent-glow);color:var(--accent);padding:3px 10px;border-radius:20px;font-size:10px;font-weight:600;letter-spacing:.5px}
.hdr .lang{margin-left:auto;display:flex;gap:2px;background:var(--surface2);border-radius:8px;padding:2px}
.hdr .lang button{background:none;border:none;color:var(--text3);padding:4px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600;transition:all .2s}
.hdr .lang button.active{background:var(--accent);color:#fff}
.hdr .lang button:hover:not(.active){color:var(--text)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;padding:20px 24px;max-width:1600px;margin:0 auto}
.card{background:var(--surface);border-radius:14px;padding:20px;border:1px solid var(--border);transition:border-color .3s,box-shadow .3s}
.card:hover{border-color:var(--border2);box-shadow:0 4px 24px #0004}
.card h2{color:var(--text2);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px;font-weight:600;display:flex;align-items:center;gap:8px}
.card h2::before{content:'';display:inline-block;width:3px;height:12px;background:var(--accent);border-radius:2px}
.row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)}
.row:last-child{border:none}
.row span:first-child{font-size:12px;color:var(--text2)}
.row .v{color:#fff;font-weight:600;font-variant-numeric:tabular-nums;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.3px}
.badge::before{content:'';width:7px;height:7px;border-radius:50%;flex-shrink:0}
.b-running{background:#3dd68c15;color:var(--green)}.b-running::before{background:var(--green);box-shadow:0 0 8px var(--green)}
.b-error{background:#f0585815;color:var(--red)}.b-error::before{background:var(--red);box-shadow:0 0 8px var(--red)}
.b-reconnecting{background:#f0a03015;color:var(--orange)}.b-reconnecting::before{background:var(--orange);box-shadow:0 0 8px var(--orange);animation:pulse 1.5s infinite}
.b-stopped{background:#585e7815;color:var(--text3)}.b-stopped::before{background:var(--text3)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.chart-wrap{position:relative;width:100%;height:130px;background:var(--surface2);border-radius:10px;overflow:hidden}
canvas{width:100%;height:100%}
.log{max-height:300px;overflow-y:auto;font-family:var(--mono);font-size:11px;line-height:1.7;background:var(--surface2);border-radius:10px;padding:12px}
.le{padding:3px 6px;border-radius:4px;margin-bottom:1px}
.le:hover{background:var(--surface3)}
.l-ok{color:var(--green)}.l-warn{color:var(--orange)}.l-err{color:var(--red)}.l-pass{color:var(--text3)}.l-http{color:var(--cyan)}
.ips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;max-height:160px;overflow-y:auto;align-content:flex-start}
.ip{background:var(--surface2);padding:4px 10px;border-radius:6px;font-family:var(--mono);font-size:11px;border:1px solid var(--border);transition:border-color .2s}
.ip:hover{border-color:var(--accent)}
.btn{background:var(--accent);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;transition:all .2s;font-family:var(--sans)}
.btn:hover{background:var(--accent2);transform:translateY(-1px);box-shadow:0 4px 12px #6c8aec30}
.btn:active{transform:translateY(0)}
.btn-sm{padding:5px 12px;font-size:10px;border-radius:6px}
.btn-green{background:var(--green)}.btn-green:hover{background:#50e0a0;box-shadow:0 4px 12px #3dd68c30}
.btn-red{background:var(--red)}.btn-red:hover{background:#f07070;box-shadow:0 4px 12px #f0585830}
.btn-ghost{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}.btn-ghost:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-glow)}
.inp{background:var(--surface2);color:#fff;border:1px solid var(--border);padding:8px 14px;border-radius:8px;font-size:12px;outline:none;font-family:var(--sans);transition:border-color .2s}
.inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.full{grid-column:1/-1}
.site-detail{background:var(--surface2);border-radius:10px;padding:14px;margin-bottom:8px;border:1px solid var(--border);transition:border-color .2s}
.site-detail:hover{border-color:var(--border2)}
.site-detail .name{font-family:var(--mono);font-size:13px;font-weight:600;margin-bottom:8px;display:flex;align-items:center;gap:10px}
.site-detail .meta{display:flex;gap:16px;font-size:11px;color:var(--text2);flex-wrap:wrap}
.site-detail .meta span{display:flex;align-items:center;gap:4px}
.test-ok{color:var(--green)}.test-fail{color:var(--red)}.test-ing{color:var(--orange)}
.log-filters{display:flex;gap:3px;background:var(--surface2);border-radius:6px;padding:2px}
.lfb{background:none;border:none;color:var(--text3);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:9px;font-weight:700;font-family:var(--mono);transition:all .2s}
.lfb.active{color:var(--accent);background:var(--accent-glow)}
.lfb:hover:not(.active){color:var(--text)}
.wizard-panel{background:var(--surface2);border:1px solid var(--accent);border-radius:10px;padding:16px;font-size:12px;box-shadow:0 0 20px var(--accent-glow)}
.wizard-panel .wiz-domain{font-family:var(--mono);font-weight:700;color:#fff;margin-bottom:10px;font-size:14px}
.wizard-panel .wiz-ips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.wizard-panel .wiz-ip{background:var(--bg);padding:4px 10px;border-radius:6px;font-family:var(--mono);font-size:11px;color:var(--green);border:1px solid var(--border)}
.wizard-panel .wiz-var{background:var(--surface3);border-radius:8px;padding:8px 10px;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.wizard-panel .wiz-var label{display:flex;align-items:center;gap:8px;cursor:pointer;font-family:var(--mono);font-size:11px;flex:1}
.wizard-panel .wiz-var .wip{font-size:10px;color:var(--text3)}
.cdn-help{margin-bottom:12px}
.cdn-snippet{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin:10px 0;position:relative;font-family:var(--mono);font-size:10px;color:var(--accent);line-height:1.5;white-space:pre-wrap;word-break:break-all;max-height:60px;overflow:hidden}
.cdn-snippet-copy{position:absolute;top:8px;right:8px;background:var(--accent);color:#fff;border:none;padding:3px 10px;border-radius:6px;cursor:pointer;font-size:9px;font-weight:700;transition:all .2s}
.cdn-snippet-copy:hover{background:var(--accent2)}
.cdn-steps{display:flex;gap:14px;margin-top:10px;flex-wrap:wrap}
.cdn-step{display:flex;align-items:center;gap:8px;font-size:10px;color:var(--text2)}
.cdn-step .sn{background:var(--accent);color:#fff;width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;flex-shrink:0}
.site-domains{display:flex;flex-wrap:wrap;gap:5px}
.site-dom-tag{background:var(--surface3);padding:4px 10px;border-radius:6px;font-family:var(--mono);font-size:10px;display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);transition:border-color .2s}
.site-dom-tag:hover{border-color:var(--border2)}
.site-dom-tag .dom-del{color:var(--red);cursor:pointer;font-weight:bold;font-size:13px;opacity:.6;transition:opacity .2s}
.site-dom-tag .dom-del:hover{opacity:1}
.toggle{position:relative;width:36px;height:20px;display:inline-block;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.toggle .slider{position:absolute;inset:0;background:var(--surface3);border-radius:20px;border:1px solid var(--border);transition:all .3s}
.toggle .slider::before{content:'';position:absolute;width:14px;height:14px;left:2px;top:2px;background:var(--text3);border-radius:50%;transition:all .3s}
.toggle input:checked+.slider{background:var(--accent);border-color:var(--accent)}
.toggle input:checked+.slider::before{transform:translateX(16px);background:#fff}
.sec-title{font-size:11px;color:var(--text3);font-weight:600;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.tab-nav{display:flex;gap:2px;padding:0 24px;background:var(--surface);border-bottom:1px solid var(--border);overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab-nav::-webkit-scrollbar{height:0}
.tab-btn{background:none;border:none;color:var(--text3);padding:12px 18px;font-size:12px;font-weight:600;cursor:pointer;font-family:var(--sans);position:relative;white-space:nowrap;transition:color .2s}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--accent)}
.tab-btn.active::after{content:'';position:absolute;bottom:0;left:8px;right:8px;height:2px;background:var(--accent);border-radius:2px 2px 0 0;box-shadow:0 0 8px var(--accent-glow)}
.tab-content{display:none;animation:tabFade .25s ease}
.tab-content.active{display:block}
@keyframes tabFade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.card{background:linear-gradient(135deg,var(--surface) 0%,rgba(23,27,45,.8) 100%);border-radius:14px;padding:20px;border:1px solid var(--border);transition:border-color .3s,box-shadow .3s;backdrop-filter:blur(8px)}
.info-text{font-size:10px;color:var(--text3);margin-top:-10px;margin-bottom:12px;line-height:1.4;font-style:italic}
</style></head><body>
<div class="hdr">
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" stroke="url(#hg)" stroke-width="2"/><path d="M12 8v4l3.5 2" stroke="url(#hg)" stroke-width="2" stroke-linecap="round"/><defs><linearGradient id="hg" x1="3" y1="2" x2="21" y2="22"><stop stop-color="#818cf8"/><stop offset="1" stop-color="#a78bfa"/></linearGradient></defs></svg>
  <h1>CleanNet</h1><span class="tag">v1.1.0</span>
  <div class="lang">
    <button onclick="setLang('en')" id="lb_en">EN</button>
    <button onclick="setLang('tr')" id="lb_tr">TR</button>
    <button onclick="setLang('de')" id="lb_de">DE</button>
  </div>
</div>
<nav class="tab-nav">
  <button class="tab-btn active" onclick="switchTab('overview')" data-tab="overview" data-i="tab_overview">Overview</button>
  <button class="tab-btn" onclick="switchTab('sites')" data-tab="sites" data-i="tab_sites">Sites</button>
  <button class="tab-btn" onclick="switchTab('ai')" data-tab="ai" data-i="tab_ai">AI Engine</button>
  <button class="tab-btn" onclick="switchTab('settings')" data-tab="settings" data-i="tab_settings">Settings</button>
  <button class="tab-btn" onclick="switchTab('logs')" data-tab="logs" data-i="tab_logs">Logs</button>
</nav>

<!-- TAB 1: OVERVIEW -->
<div class="tab-content active" id="tab-overview">
<div class="grid">
  <div class="card">
    <h2 data-i="status">Status</h2>
    <p class="info-text" data-i="info_status">Current proxy status and connection health</p>
    <div class="row"><span data-i="status">Status</span><span id="st" class="badge b-running">Active</span></div>
    <div class="row"><span>Ping</span><span class="v" id="pg">--</span></div>
    <div class="row"><span>Uptime</span><span class="v" id="up">0s</span></div>
  </div>
  <div class="card">
    <h2 data-i="statistics">Statistics</h2>
    <p class="info-text" data-i="info_stats">Connection and bypass statistics since startup</p>
    <div class="row"><span data-i="connections">Connections</span><span class="v" id="cn">0</span></div>
    <div class="row"><span data-i="tls_fragment">TLS Fragment</span><span class="v" id="fg">0</span></div>
    <div class="row"><span data-i="ip_updates">IP Updates</span><span class="v" id="iu">0</span></div>
    <div class="row"><span data-i="strategy_attempts">Strategy Attempts</span><span class="v" id="st_try">0</span></div>
    <div class="row"><span data-i="fallbacks">Fallbacks</span><span class="v" id="st_fb">0</span></div>
  </div>
  <div class="card">
    <h2 data-i="ping_chart">Ping Chart (last 2min)</h2>
    <div class="chart-wrap"><canvas id="ch"></canvas></div>
  </div>
  <div class="card">
    <h2 data-i="ip_pool">IP Pool</h2>
    <p class="info-text" data-i="info_ip_pool">Resolved IP addresses for bypass targets</p>
    <div id="il" class="ips"></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
      <button class="btn btn-sm btn-ghost" onclick="fetch('/api/refresh-ips',{method:'POST'})" data-i="refresh_ips">Refresh IPs</button>
      <button class="btn btn-sm btn-green" onclick="fetch('/api/reload-config',{method:'POST'})" data-i="reload_config">Reload Config</button>
      <button class="btn btn-sm btn-red" onclick="fetch('/api/reset-strategies',{method:'POST'})" data-i="reset_strategies">Reset Strategies</button>
    </div>
  </div>
  <div class="card full">
    <h2 data-i="strategy_timeline">Strategy Timeline</h2>
    <p class="info-text" data-i="info_timeline">Recent bypass strategy results and timing</p>
    <div class="chart-wrap" style="height:140px;"><canvas id="stch"></canvas></div>
    <div id="stl" style="margin-top:10px;font-family:var(--mono);font-size:11px;max-height:120px;overflow-y:auto;"></div>
  </div>
</div>
</div>

<!-- TAB 2: SITES -->
<div class="tab-content" id="tab-sites">
<div class="grid">
  <div class="card full">
    <h2 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
      <span data-i="sites">Sites</span>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-sm" onclick="testAll()" data-i="test_all">Test All</button>
        <button class="btn btn-sm btn-red" onclick="removeAllSites()" data-i="remove_all_sites">Remove All</button>
      </div>
    </h2>
    <p class="info-text" data-i="info_sites">Managed sites with bypass strategies. Add domains to route through proxy.</p>
    <div id="sl" style="margin-bottom:14px;"></div>
    <div style="display:flex;gap:8px;margin-bottom:8px;">
      <input type="text" id="ns" class="inp" placeholder="example.com" style="flex:1;" onkeydown="if(event.key==='Enter')resolveS()">
      <button class="btn" onclick="resolveS()" id="resolveBtn" data-i="resolve">Resolve</button>
    </div>
    <div id="wiz" class="wizard-panel" style="display:none;"></div>
  </div>
  <div class="card full">
    <h2><span data-i="cdn_finder">CDN Finder</span></h2>
    <p class="info-text" data-i="info_cdn">Find and add CDN subdomains used by your sites for complete bypass coverage.</p>
    <div class="cdn-help">
      <p id="cdnDesc" style="margin-bottom:6px;font-size:11px;line-height:1.5;color:var(--text2)"></p>
      <div class="cdn-snippet" id="cdnSnippet"></div>
      <div class="cdn-steps" id="cdnStepsRow"></div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;margin-top:14px;">
      <textarea id="cdnDomain" class="inp" placeholder="cdn.example.com&#10;static.example.com" rows="2" style="flex:1;min-width:160px;resize:vertical;font-size:11px;line-height:1.4;font-family:var(--mono);" onkeydown="if(event.key==='Enter'&&event.ctrlKey)addCdn()"></textarea>
      <select id="cdnSite" class="inp" style="min-width:120px;"></select>
      <button class="btn btn-sm btn-green" onclick="addCdn()" data-i="add_cdn">Add CDN</button>
    </div>
    <div id="cdnResult" style="display:none;"></div>
    <div id="siteDomains" style="margin-top:10px;"></div>
  </div>
</div>
</div>

<!-- TAB 3: AI ENGINE -->
<div class="tab-content" id="tab-ai">
<div class="grid">
  <div class="card full">
    <h2 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
      <span data-i="ai_engine">AI Strategy Engine</span>
      <div style="display:flex;gap:6px;align-items:center;">
        <span id="ai_status" class="badge b-stopped" style="font-size:9px;">Learning</span>
        <button class="btn btn-sm" onclick="startTraining()" id="trainBtn" style="background:linear-gradient(135deg,var(--purple),var(--accent));" data-i="train_ai">&#129504; Train AI</button>
        <button class="btn btn-sm btn-ghost" onclick="fetch('/api/ai-reset',{method:'POST'})" data-i="ai_reset">Reset AI</button>
      </div>
    </h2>
    <p class="info-text" data-i="info_ai">Machine learning engine that learns optimal bypass strategies per site and time.</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px;">
      <div style="background:var(--surface2);border-radius:10px;padding:14px;text-align:center;">
        <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;" data-i="ai_accuracy">Accuracy</div>
        <div id="ai_acc" style="font-size:28px;font-weight:700;font-family:var(--mono);color:var(--green);">--%</div>
      </div>
      <div style="background:var(--surface2);border-radius:10px;padding:14px;text-align:center;">
        <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;" data-i="ai_predictions">Predictions</div>
        <div id="ai_pred" style="font-size:28px;font-weight:700;font-family:var(--mono);color:var(--accent);">0</div>
      </div>
      <div style="background:var(--surface2);border-radius:10px;padding:14px;text-align:center;">
        <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;" data-i="ai_observations">Observations</div>
        <div id="ai_obs" style="font-size:28px;font-weight:700;font-family:var(--mono);color:var(--cyan);">0</div>
      </div>
      <div style="background:var(--surface2);border-radius:10px;padding:14px;text-align:center;">
        <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;" data-i="ai_active_sites">AI Sites</div>
        <div id="ai_sites" style="font-size:28px;font-weight:700;font-family:var(--mono);color:var(--purple);">0</div>
      </div>
    </div>
    <div id="ai_detail" style="font-family:var(--mono);font-size:11px;max-height:200px;overflow-y:auto;"></div>
    <div style="margin-top:12px;">
      <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;" data-i="ai_hourly">Hourly Pattern Heatmap</div>
      <div class="chart-wrap" style="height:80px;"><canvas id="ai_heatmap"></canvas></div>
    </div>
    <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;">
        <div>
          <div style="font-size:11px;color:var(--text2);font-weight:600;" data-i="training_intensity">Training Intensity</div>
          <div id="intensityDesc" style="font-size:10px;color:var(--text3);margin-top:4px;"></div>
        </div>
        <div id="selfTrainStatus" style="display:flex;align-items:center;gap:6px;font-size:10px;color:var(--text3);">
          <span id="selfTrainDot" style="width:8px;height:8px;border-radius:50%;background:var(--text3);display:inline-block;"></span>
          <span id="selfTrainText">Idle</span>
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">
        <button class="btn btn-sm intensity-btn" data-intensity="light" onclick="setTrainIntensity('light')" style="border:1px solid var(--border);background:transparent;transition:all .2s;">
          <span data-i="intensity_light">Light</span>
        </button>
        <button class="btn btn-sm intensity-btn" data-intensity="medium" onclick="setTrainIntensity('medium')" style="border:1px solid var(--border);background:transparent;transition:all .2s;">
          <span data-i="intensity_medium">Medium</span>
        </button>
        <button class="btn btn-sm intensity-btn" data-intensity="heavy" onclick="setTrainIntensity('heavy')" style="border:1px solid var(--border);background:transparent;transition:all .2s;">
          <span data-i="intensity_heavy">Heavy</span>
        </button>
        <button class="btn btn-sm intensity-btn" data-intensity="nonstop" onclick="setTrainIntensity('nonstop')" style="border:1px solid var(--border);background:transparent;transition:all .2s;">
          <span data-i="intensity_nonstop">Nonstop 24/7</span>
        </button>
      </div>
      <div id="selfTrainInfo" style="display:none;background:var(--surface2);border-radius:8px;padding:10px 12px;margin-top:8px;font-family:var(--mono);font-size:10px;">
        <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;">
          <span><span style="color:var(--text3);">Probes:</span> <span id="stProbes" style="color:var(--cyan);">0</span></span>
          <span><span style="color:var(--text3);">Cycles:</span> <span id="stCycles" style="color:var(--accent);">0</span></span>
          <span><span style="color:var(--text3);">Last:</span> <span id="stLast" style="color:var(--green);">-</span></span>
        </div>
      </div>
      <div id="intensityWarning" style="display:none;font-size:10px;color:var(--orange);background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.2);border-radius:6px;padding:8px 10px;margin-top:6px;" data-i="intensity_warning">
        Nonstop mode makes continuous background connections to test strategies. This may increase network activity significantly.
      </div>
    </div>
    <div id="trainPanel" style="display:none;margin-top:16px;border-top:1px solid var(--border);padding-top:14px;">
      <div style="font-size:11px;color:var(--text2);font-weight:600;margin-bottom:10px;" data-i="training_results">Training Results</div>
      <div id="trainProgress" style="margin-bottom:10px;"></div>
      <div id="trainResults"></div>
    </div>
  </div>
</div>
</div>

<!-- TAB 4: SETTINGS -->
<div class="tab-content" id="tab-settings">
<div class="grid">
  <div class="card">
    <h2 data-i="general_settings">General</h2>
    <p class="info-text" data-i="info_general">Core proxy settings and startup behavior</p>
    <div class="row"><span data-i="autostart">Auto-start</span><span class="v"><label class="toggle"><input type="checkbox" id="as" onchange="toggleAS()"><span class="slider"></span></label></span></div>
  </div>
  <div class="card">
    <h2 data-i="config_mgmt">Config Management</h2>
    <p class="info-text" data-i="info_config">Export, import configuration and fix UWP apps</p>
    <div style="display:flex;flex-direction:column;gap:10px;">
      <button class="btn btn-ghost" onclick="exportCfg()" data-i="export_config">Export Config</button>
      <label class="btn btn-ghost" style="text-align:center;cursor:pointer;" data-i="import_config">Import Config
        <input type="file" accept=".json" onchange="importCfg(event)" style="display:none;">
      </label>
      <div style="border-top:1px solid var(--border);padding-top:10px;margin-top:4px;">
        <div style="font-size:10px;color:var(--text3);margin-bottom:6px;" data-i="uwp_desc">Microsoft Store / UWP apps not working?</div>
        <button class="btn btn-ghost" onclick="fixUwp()" id="uwpBtn" data-i="fix_uwp">Fix UWP Loopback</button>
      </div>
    </div>
  </div>
  <div class="card full">
    <h2 data-i="proxy_bypass">Proxy Bypass (Exclude)</h2>
    <p class="info-text" data-i="info_bypass">Domains that bypass the proxy and connect directly</p>
    <div id="bl" class="ips" style="margin-bottom:14px;"></div>
    <div style="display:flex;gap:8px;margin-bottom:8px;">
      <input type="text" id="nb" class="inp" placeholder="*.example.com" style="flex:1;">
      <button class="btn btn-sm" onclick="addB()" data-i="add">Add</button>
    </div>
    <div style="display:flex;gap:8px;">
      <select id="preset" class="inp" style="flex:1;">
        <option value="" data-i="load_preset">Load Preset...</option>
        <option value="gaming">Gaming</option>
        <option value="cdn">CDN</option>
        <option value="streaming">Streaming</option>
      </select>
      <button class="btn btn-sm btn-green" onclick="loadPreset()" data-i="load">Load</button>
      <button class="btn btn-sm btn-red" onclick="clearBypass()" data-i="clear_all">Clear All</button>
    </div>
  </div>
</div>
</div>

<!-- TAB 5: LOGS -->
<div class="tab-content" id="tab-logs">
<div class="grid">
  <div class="card full">
    <h2 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">
      <span>Log</span>
      <div style="display:flex;gap:6px;align-items:center;">
        <div class="log-filters" id="lf">
          <button class="lfb active" data-f="all" onclick="toggleLF(this)">ALL</button>
          <button class="lfb" data-f="bypass" onclick="toggleLF(this)">BYPASS</button>
          <button class="lfb" data-f="pass" onclick="toggleLF(this)">PASS</button>
          <button class="lfb" data-f="http" onclick="toggleLF(this)">HTTP</button>
          <button class="lfb" data-f="error" onclick="toggleLF(this)">ERROR</button>
        </div>
        <button class="btn btn-sm btn-ghost" onclick="copyLogs()" data-i="copy">Copy</button>
      </div>
    </h2>
    <div id="lg" class="log" style="max-height:500px;"></div>
  </div>
</div>
</div>
<script>
const I={
  en:{status:'Status',statistics:'Statistics',connections:'Connections',tls_fragment:'TLS Fragment',ip_updates:'IP Updates',strategy_attempts:'Strategy Attempts',fallbacks:'Fallbacks',ping_chart:'Ping Chart (last 2min)',ip_pool:'IP Pool',sites:'Sites',proxy_bypass:'Proxy Bypass (Exclude)',config_mgmt:'Config Management',autostart:'Auto-start',refresh_ips:'Refresh IPs',reload_config:'Reload Config',reset_strategies:'Reset Strategies',add_site:'Add Site',add:'Add',load:'Load',clear_all:'Clear All',load_preset:'Load Preset...',test_all:'Test All',test:'Test',export_config:'Export Config',import_config:'Import Config',copy:'Copy',copied:'Copied!',on:'On',off:'Off',active:'Active',error:'Error',reconnecting:'Reconnecting',stopped:'Stopped',conn:'Conn',success:'OK',fail:'Fail',avg:'Avg',testing:'Testing...',test_ok:'OK',test_fail:'Fail',import_ok:'Config imported!',import_fail:'Import failed',resolve:'Resolve',resolving:'Resolving...',confirm_add:'Confirm & Add',cancel:'Cancel',no_ips_found:'No IPs found for',subdomains_found:'Subdomains found',strategy_timeline:'Strategy Timeline',cdn_finder:'CDN Finder',cdn_help_desc:'Copy the script below, open the target site, press F12, paste it into Console and press Enter.',cdn_step1:'Copy script',cdn_step2:'Open target site + F12',cdn_step3:'Paste in Console + Enter',cdn_step4:'Add domains below',add_cdn:'Add CDN',cdn_added:'CDN domain added!',cdn_select_site:'Select site...',cdn_domain_exists:'Domain already exists',cdn_no_domain:'Enter a CDN domain',remove_domain:'Domain removed',site_domains:'Site Domains',remove_site:'Remove site',remove_all_sites:'Remove All',confirm_remove_site:'Remove site',confirm_remove_all_sites:'Remove all sites? This cannot be undone.',fix_uwp:'Fix UWP Loopback',uwp_desc:'Microsoft Store / UWP apps not working?',uwp_done:'UWP fix applied! (admin prompt sent)',ai_engine:'AI Strategy Engine',ai_accuracy:'Accuracy',ai_predictions:'Predictions',ai_observations:'Observations',ai_active_sites:'AI Sites',ai_hourly:'Hourly Pattern Heatmap',ai_reset:'Reset AI',ai_learning:'Learning',ai_active_label:'Active',ai_site_prediction:'AI Prediction',default_bypass:'Default (built-in)',custom_bypass:'Custom',train_ai:'\ud83e\udde0 Train AI',training_results:'Training Results',training_progress:'Training in progress...',training_complete:'Training complete!',apply_strategy:'Apply',revert_strategy:'Revert',best_found:'Best strategy found',no_improvement:'No improvement found',training_active:'Training...',tab_overview:'Overview',tab_sites:'Sites',tab_ai:'AI Engine',tab_settings:'Settings',tab_logs:'Logs',general_settings:'General',info_status:'Current proxy status and connection health',info_stats:'Connection and bypass statistics since startup',info_ip_pool:'Resolved IP addresses for bypass targets',info_timeline:'Recent bypass strategy results and timing',info_sites:'Managed sites with bypass strategies. Add domains to route through proxy.',info_cdn:'Find and add CDN subdomains used by your sites for complete bypass coverage.',info_ai:'Machine learning engine that learns optimal bypass strategies per site and time.',info_general:'Core proxy settings and startup behavior',info_config:'Export, import configuration and fix UWP apps',info_bypass:'Domains that bypass the proxy and connect directly',training_intensity:'Training Intensity',intensity_light:'Light',intensity_medium:'Medium',intensity_heavy:'Heavy',intensity_nonstop:'Nonstop 24/7',intensity_warning:'Nonstop/Heavy mode makes continuous background connections to test strategies. This may increase network activity significantly.'},
  tr:{status:'Durum',statistics:'Istatistikler',connections:'Baglantilar',tls_fragment:'TLS Fragment',ip_updates:'IP Guncelleme',strategy_attempts:'Strateji Denemeleri',fallbacks:'Geri Donusler',ping_chart:'Ping Grafigi (son 2dk)',ip_pool:'IP Havuzu',sites:'Siteler',proxy_bypass:'Proxy Haric Tutma',config_mgmt:'Config Yonetimi',autostart:'Otomatik Baslat',refresh_ips:'IP Guncelle',reload_config:'Config Yukle',reset_strategies:'Strateji Sifirla',add_site:'Site Ekle',add:'Ekle',load:'Yukle',clear_all:'Tumunu Sil',load_preset:'Preset Sec...',test_all:'Hepsini Test Et',test:'Test',export_config:'Config Disa Aktar',import_config:'Config Iceye Aktar',copy:'Kopyala',copied:'Kopyalandi!',on:'Acik',off:'Kapali',active:'Aktif',error:'Hata',reconnecting:'Yeniden Baglaniyor',stopped:'Durdu',conn:'Bag',success:'OK',fail:'Hata',avg:'Ort',testing:'Test ediliyor...',test_ok:'Basarili',test_fail:'Basarisiz',import_ok:'Config aktarildi!',import_fail:'Aktarim basarisiz',resolve:'Cozumle',resolving:'Cozumleniyor...',confirm_add:'Onayla ve Ekle',cancel:'Iptal',no_ips_found:'IP bulunamadi',subdomains_found:'Bulunan alt domainler',strategy_timeline:'Strateji Zaman Cizgisi',cdn_finder:'CDN Bulucu',cdn_help_desc:'Asagidaki scripti kopyala, hedef siteyi ac, F12 bas, Console sekmesine yapistir ve Enter bas.',cdn_step1:'Scripti kopyala',cdn_step2:'Hedef site + F12',cdn_step3:'Console yapistir + Enter',cdn_step4:'Domainleri asagiya ekle',add_cdn:'CDN Ekle',cdn_added:'CDN domaini eklendi!',cdn_select_site:'Site sec...',cdn_domain_exists:'Domain zaten mevcut',cdn_no_domain:'CDN domaini girin',remove_domain:'Domain kaldirildi',site_domains:'Site Domainleri',remove_site:'Siteyi sil',remove_all_sites:'Tumunu Sil',confirm_remove_site:'Siteyi sil',confirm_remove_all_sites:'Tum siteler silinsin mi? Bu islem geri alinamaz.',fix_uwp:'UWP Loopback Duzelt',uwp_desc:'Microsoft Store / UWP uygulamalar calismiyor mu?',uwp_done:'UWP duzeltmesi uygulandi! (admin izni istendi)',ai_engine:'AI Strateji Motoru',ai_accuracy:'Isabetlilik',ai_predictions:'Tahminler',ai_observations:'Gozlemler',ai_active_sites:'AI Siteler',ai_hourly:'Saatlik Patern Haritasi',ai_reset:'AI Sifirla',ai_learning:'Ogreniyor',ai_active_label:'Aktif',ai_site_prediction:'AI Tahmini',default_bypass:'Varsayilan (dahili)',custom_bypass:'Ozel',train_ai:'\ud83e\udde0 AI Egit',training_results:'Egitim Sonuclari',training_progress:'Egitim devam ediyor...',training_complete:'Egitim tamamlandi!',apply_strategy:'Uygula',revert_strategy:'Geri Al',best_found:'En iyi strateji bulundu',no_improvement:'Iyilestirme bulunamadi',training_active:'Egitiyor...',tab_overview:'Genel Bakis',tab_sites:'Siteler',tab_ai:'AI Motoru',tab_settings:'Ayarlar',tab_logs:'Loglar',general_settings:'Genel',info_status:'Proxy durumu ve baglanti sagligi',info_stats:'Baslangictan bu yana baglanti ve bypass istatistikleri',info_ip_pool:'Bypass hedefleri icin cozumlenmis IP adresleri',info_timeline:'Son bypass strateji sonuclari ve zamanlama',info_sites:'Bypass stratejileriyle yonetilen siteler. Proxy uzerinden yonlendirmek icin domain ekleyin.',info_cdn:'Tam bypass kapsamasi icin sitelerinizin kullandigi CDN alt domainlerini bulun.',info_ai:'Site ve zamana gore en uygun bypass stratejisini ogrenen makine ogrenimi motoru.',info_general:'Temel proxy ayarlari ve baslatma davranisi',info_config:'Yapilandirmayi disa/iceye aktarin ve UWP uygulamalarini duzelt',info_bypass:'Proxy\'yi atlayip dogrudan baglanan domainler',training_intensity:'Egitim Yogunlugu',intensity_light:'Hafif',intensity_medium:'Orta',intensity_heavy:'Yogun',intensity_nonstop:'Nonstop 7/24',intensity_warning:'Nonstop/Yogun mod, stratejileri test etmek icin surekli arka plan baglantilari yapar. Ag aktivitesini onemli olcude artirabilir.'},
  de:{status:'Status',statistics:'Statistiken',connections:'Verbindungen',tls_fragment:'TLS Fragment',ip_updates:'IP Updates',strategy_attempts:'Strategieversuche',fallbacks:'Rueckfaelle',ping_chart:'Ping-Diagramm (letzte 2min)',ip_pool:'IP-Pool',sites:'Websites',proxy_bypass:'Proxy-Bypass (Ausschluss)',config_mgmt:'Config-Verwaltung',autostart:'Autostart',refresh_ips:'IPs aktualisieren',reload_config:'Config laden',reset_strategies:'Strategien zuruecksetzen',add_site:'Website hinzufuegen',add:'Hinzufuegen',load:'Laden',clear_all:'Alle loeschen',load_preset:'Preset laden...',test_all:'Alle testen',test:'Test',export_config:'Config exportieren',import_config:'Config importieren',copy:'Kopieren',copied:'Kopiert!',on:'An',off:'Aus',active:'Aktiv',error:'Fehler',reconnecting:'Verbinde...',stopped:'Gestoppt',conn:'Verb',success:'OK',fail:'Fehler',avg:'Avg',testing:'Teste...',test_ok:'OK',test_fail:'Fehlgeschlagen',import_ok:'Config importiert!',import_fail:'Import fehlgeschlagen',resolve:'Aufloesen',resolving:'Aufloesen...',confirm_add:'Bestaetigen',cancel:'Abbrechen',no_ips_found:'Keine IPs gefunden fuer',subdomains_found:'Gefundene Subdomains',strategy_timeline:'Strategie-Zeitachse',cdn_finder:'CDN Finder',cdn_help_desc:'Kopieren Sie das Script, oeffnen Sie die Zielseite, druecken Sie F12, fuegen Sie es in die Console ein und druecken Sie Enter.',cdn_step1:'Script kopieren',cdn_step2:'Zielseite + F12',cdn_step3:'In Console einfuegen + Enter',cdn_step4:'Domains unten hinzufuegen',add_cdn:'CDN hinzufuegen',cdn_added:'CDN-Domain hinzugefuegt!',cdn_select_site:'Seite waehlen...',cdn_domain_exists:'Domain existiert bereits',cdn_no_domain:'CDN-Domain eingeben',remove_domain:'Domain entfernt',site_domains:'Seiten-Domains',remove_site:'Seite entfernen',remove_all_sites:'Alle entfernen',confirm_remove_site:'Seite entfernen',confirm_remove_all_sites:'Alle Seiten entfernen? Dies kann nicht rueckgaengig gemacht werden.',fix_uwp:'UWP Loopback beheben',uwp_desc:'Microsoft Store / UWP-Apps funktionieren nicht?',uwp_done:'UWP-Fix angewendet! (Admin-Eingabeaufforderung gesendet)',ai_engine:'AI Strategie-Engine',ai_accuracy:'Genauigkeit',ai_predictions:'Vorhersagen',ai_observations:'Beobachtungen',ai_active_sites:'AI Seiten',ai_hourly:'Stuendliches Muster-Heatmap',ai_reset:'AI zuruecksetzen',ai_learning:'Lernt',ai_active_label:'Aktiv',ai_site_prediction:'AI Vorhersage',default_bypass:'Standard (eingebaut)',custom_bypass:'Benutzerdefiniert',train_ai:'\ud83e\udde0 AI Trainieren',training_results:'Trainingsergebnisse',training_progress:'Training laeuft...',training_complete:'Training abgeschlossen!',apply_strategy:'Anwenden',revert_strategy:'Zuruecksetzen',best_found:'Beste Strategie gefunden',no_improvement:'Keine Verbesserung',training_active:'Trainiert...',tab_overview:'Uebersicht',tab_sites:'Websites',tab_ai:'AI Engine',tab_settings:'Einstellungen',tab_logs:'Logs',general_settings:'Allgemein',info_status:'Aktueller Proxy-Status und Verbindungszustand',info_stats:'Verbindungs- und Bypass-Statistiken seit dem Start',info_ip_pool:'Aufgeloeste IP-Adressen fuer Bypass-Ziele',info_timeline:'Aktuelle Bypass-Strategie-Ergebnisse und Timing',info_sites:'Verwaltete Websites mit Bypass-Strategien. Domains hinzufuegen um ueber Proxy zu routen.',info_cdn:'CDN-Subdomains Ihrer Websites fuer vollstaendige Bypass-Abdeckung finden.',info_ai:'Machine-Learning-Engine die optimale Bypass-Strategien pro Website und Uhrzeit lernt.',info_general:'Grundlegende Proxy-Einstellungen und Startverhalten',info_config:'Konfiguration exportieren/importieren und UWP-Apps beheben',info_bypass:'Domains die den Proxy umgehen und direkt verbinden',training_intensity:'Trainingsintensitaet',intensity_light:'Leicht',intensity_medium:'Mittel',intensity_heavy:'Intensiv',intensity_nonstop:'Nonstop 24/7',intensity_warning:'Nonstop/Intensiv-Modus stellt kontinuierliche Hintergrundverbindungen her um Strategien zu testen. Dies kann die Netzwerkaktivitaet erheblich erhoehen.'}
};
let L=localStorage.getItem('cleannet_lang')||navigator.language.slice(0,2);
if(!I[L])L='en';
function setLang(l){L=l;localStorage.setItem('cleannet_lang',l);applyLang()}
function t(k){return I[L][k]||I.en[k]||k}
function switchTab(tab){
  document.querySelectorAll('.tab-content').forEach(el=>el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el=>el.classList.remove('active'));
  const tc=document.getElementById('tab-'+tab);if(tc)tc.classList.add('active');
  const tb=document.querySelector('.tab-btn[data-tab="'+tab+'"]');if(tb)tb.classList.add('active');
  localStorage.setItem('cleannet_tab',tab);
  if(tab==='overview'){setTimeout(()=>{dC();},50)}
}
(function(){const saved=localStorage.getItem('cleannet_tab');if(saved&&document.getElementById('tab-'+saved)){switchTab(saved)}})();
function applyLang(){
  document.querySelectorAll('[data-i]').forEach(el=>{
    const k=el.getAttribute('data-i');
    if(el.tagName==='OPTION')el.textContent=t(k);
    else if(el.tagName==='LABEL')el.childNodes[0].textContent=t(k)+' ';
    else el.textContent=t(k);
  });
  document.querySelectorAll('.hdr .lang button').forEach(b=>{b.classList.remove('active')});
  const ab=document.getElementById('lb_'+L);if(ab)ab.classList.add('active');
  const cdnD=document.getElementById('cdnDesc');if(cdnD)cdnD.textContent=t('cdn_help_desc');
  const cdnSR=document.getElementById('cdnStepsRow');if(cdnSR)cdnSR.innerHTML=[1,2,3,4].map(n=>'<div class="cdn-step"><span class="sn">'+n+'</span>'+t('cdn_step'+n)+'</div>').join('');
}
const es=new EventSource('/api/events');
const pH=[];const mP=120;
es.onmessage=e=>{const d=JSON.parse(e.data);U(d)};
function U(d){try{
  const s=document.getElementById('st');
  const sm={'running':[t('active'),'b-running'],'error':[t('error'),'b-error'],'reconnecting':[t('reconnecting'),'b-reconnecting'],'stopped':[t('stopped'),'b-stopped']};
  const si=sm[d.status]||['?','b-stopped'];
  s.textContent=si[0];s.className='badge '+si[1];
  document.getElementById('pg').textContent=d.ping>0?d.ping+'ms':'--';
  document.getElementById('up').textContent=fU(d.uptime);
  document.getElementById('cn').textContent=d.connections;
  document.getElementById('fg').textContent=d.fragments;
  document.getElementById('iu').textContent=d.ip_updates;
  document.getElementById('st_try').textContent=d.strategy_tries||0;
  document.getElementById('st_fb').textContent=d.strategy_fallbacks||0;
  document.getElementById('il').innerHTML=(d.ips||[]).map(i=>'<span class="ip">'+i+'</span>').join('');
  if(d.sites){
    const sC={'direct':'#34d399','host_split':'#818cf8','fragment_light':'#fbbf24','tls_record_frag':'#22d3ee','fragment_burst':'#ff9800','desync':'#a78bfa','fragment_heavy':'#f87171','sni_shuffle':'#ec4899','fake_tls_inject':'#fb923c','triple_split':'#4ade80','sni_padding':'#f472b6','reverse_frag':'#facc15','slow_drip':'#94a3b8','oob_inline':'#2dd4bf','dot_shuffle':'#c084fc','tls_multi_record':'#38bdf8','tls_mixed_delay':'#a3e635','sni_split_byte':'#e879f9','header_fragment':'#fb7185','auto':'#585e78'};
    document.getElementById('sl').innerHTML=Object.keys(d.sites).map(s=>{
      const si=d.sites[s];
      const isEn=si.enabled!==false;
      const bg=isEn?'var(--green)':'var(--text3)';
      const strat=si.current_strategy||'auto';
      const stCol=sC[strat]||'#585e78';
      const cc=si.conn_count||0,sc=si.success_count||0,fc=si.fail_count||0,am=si.avg_ms||0;
      const rate=cc>0?Math.round(sc/(sc+fc)*100):0;
      const tt=si.test;
      let testHtml='<button class="btn btn-sm btn-ghost" onclick="testSite(\''+s+'\')" style="padding:3px 10px;font-size:9px;">'+t('test')+'</button>';
      if(tt){
        if(tt.status==='testing')testHtml='<span class="test-ing" style="font-size:10px;">'+t('testing')+'</span>';
        else if(tt.status==='ok')testHtml='<span class="test-ok" style="font-size:10px;">'+t('test_ok')+' '+tt.ms+'ms</span>';
        else testHtml='<span class="test-fail" style="font-size:10px;" title="'+esc(tt.error||tt.reason||'')+'">'+t('test_fail')+'</span>';
      }
      return '<div class="site-detail">'
        +'<div class="name">'
        +'<div style="width:8px;height:8px;border-radius:50%;background:'+bg+';cursor:pointer;flex-shrink:0;" onclick="ts(\''+s+'\')"></div>'
        +'<span style="cursor:pointer;color:#fff;" onclick="ts(\''+s+'\')">'+s+'</span>'
        +'<span style="font-size:9px;color:'+stCol+';font-weight:700;background:'+stCol+'15;padding:2px 8px;border-radius:10px;">['+strat+']</span>'
        +(si.strategy_time_ms?'<span style="font-size:9px;color:var(--text3)">'+si.strategy_time_ms+'ms</span>':'')
        +(si.ai&&si.ai.ai_active?'<span style="font-size:8px;color:var(--purple);background:var(--purple)15;padding:1px 6px;border-radius:8px;" title="AI confidence: '+Math.round(si.ai.confidence*100)+'%">AI '+Math.round(si.ai.confidence*100)+'%</span>':'')
        +'<span style="margin-left:auto;display:flex;gap:4px;align-items:center;">'+testHtml
        +'<span onclick="removeSite(\''+s+'\')" title="'+t('remove_site')+'" style="cursor:pointer;color:var(--red);opacity:.35;transition:opacity .2s;display:flex;padding:2px;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.35"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/></svg></span>'
        +'</span>'
        +'</div>'
        +'<div class="meta">'
        +'<span>'+t('conn')+': <b style="color:#fff">'+cc+'</b></span>'
        +'<span>'+t('success')+': <b style="color:var(--green)">'+sc+'</b></span>'
        +'<span>'+t('fail')+': <b style="color:var(--red)">'+fc+'</b></span>'
        +(am?'<span>'+t('avg')+': <b style="color:var(--accent)">'+am+'ms</b></span>':'')
        +(cc>0?'<span style="font-weight:700;color:'+(rate>70?'var(--green)':rate>30?'var(--orange)':'var(--red)')+'">'+rate+'%</span>':'')
        +'</div></div>';
    }).join('');
    updateCdnSiteList(d.sites);
  }
  if(d.proxy_bypass!==undefined){renderBypass(d.proxy_bypass,d.always_bypass)}
  if(d.autostart!==undefined){document.getElementById('as').checked=d.autostart}
  if(d.ping>0){pH.push(d.ping);if(pH.length>mP)pH.shift();dC()}
  if(d.strategy_history){renderST(d.strategy_history)}
  if(d.ai_stats){renderAI(d.ai_stats,d.sites)}
  if(d.self_train){updateSelfTrainUI(d.self_train)}
  if(d.new_logs&&d.new_logs.length){
    const l=document.getElementById('lg');
    d.new_logs.forEach(e=>{
      const div=document.createElement('div');div.className='le';
      const lt=e.includes('[BYPASS]')?'bypass':e.includes('[PASSTHROUGH]')?'pass':e.includes('[HTTP-FORWARD]')?'http':(e.includes('ERROR')||e.includes('WARNING'))?'error':'other';
      div.setAttribute('data-lt',lt);
      const c=lt==='error'?'l-err':lt==='bypass'?'l-ok':lt==='pass'?'l-pass':lt==='http'?'l-http':'';
      div.innerHTML='<span class="'+(c||'')+'">'+esc(e)+'</span>';
      if(!_lfMatch(lt))div.style.display='none';
      l.appendChild(div)});
    l.scrollTop=l.scrollHeight;
    while(l.children.length>150)l.removeChild(l.firstChild)}
}catch(e){console.error('U() error:',e)}}
function dC(){
  const cv=document.getElementById('ch');const x=cv.getContext('2d');
  const r=window.devicePixelRatio||1;
  cv.width=cv.offsetWidth*r;cv.height=cv.offsetHeight*r;
  x.scale(r,r);const w=cv.offsetWidth,h=cv.offsetHeight;
  x.clearRect(0,0,w,h);
  if(pH.length<2)return;
  const mx=Math.max(...pH)*1.3||1;
  x.strokeStyle='#252940';x.lineWidth=0.5;
  for(let i=0;i<4;i++){const y=h*(i/3);x.beginPath();x.moveTo(0,y);x.lineTo(w,y);x.stroke()}
  x.strokeStyle='#6c8aec';x.lineWidth=2;x.lineJoin='round';x.lineCap='round';x.beginPath();
  pH.forEach((p,i)=>{const px=(i/(mP-1))*w,py=h-(p/mx)*h;i===0?x.moveTo(px,py):x.lineTo(px,py)});
  x.stroke();
  const g=x.createLinearGradient(0,0,0,h);g.addColorStop(0,'#6c8aec20');g.addColorStop(1,'#6c8aec00');
  x.lineTo((pH.length-1)/(mP-1)*w,h);x.lineTo(0,h);x.fillStyle=g;x.fill()
}
async function ts(s){await fetch('/api/toggle-site',{method:'POST',body:JSON.stringify({site:s})})}
let _wizData=null;
async function resolveS(){
  const i=document.getElementById('ns'),v=i.value.trim().toLowerCase(),b=document.getElementById('resolveBtn'),w=document.getElementById('wiz');
  if(!v)return;
  b.textContent=t('resolving');b.disabled=true;
  try{
    const r=await fetch('/api/resolve-domain',{method:'POST',body:JSON.stringify({domain:v})});
    _wizData=await r.json();
    if(!_wizData.ips||!_wizData.ips.length){w.innerHTML='<div style="color:#f04747">'+t('no_ips_found')+': '+esc(v)+'</div>';w.style.display='block';return}
    let h='<div class="wiz-domain">'+esc(_wizData.domain)+'</div>';
    h+='<div style="margin-bottom:6px;color:#747885;font-size:10px">IPs:</div><div class="wiz-ips">';
    _wizData.ips.forEach(ip=>{h+='<span class="wiz-ip">'+esc(ip)+'</span>'});
    h+='</div>';
    if(_wizData.variants&&_wizData.variants.length){
      h+='<div style="margin:8px 0 6px;color:#747885;font-size:10px">'+t('subdomains_found')+':</div>';
      _wizData.variants.forEach((vr,idx)=>{
        h+='<div class="wiz-var"><label><input type="checkbox" checked data-wv="'+idx+'"> '+esc(vr.domain)+'</label><span class="wip">'+vr.ips.join(', ')+'</span></div>';
      });
    }
    h+='<div style="display:flex;gap:8px;margin-top:10px;"><button class="btn btn-sm" onclick="confirmWiz()" style="background:#43b581">'+t('confirm_add')+'</button><button class="btn btn-sm" onclick="cancelWiz()" style="background:#747885">'+t('cancel')+'</button></div>';
    w.innerHTML=h;w.style.display='block';
  }catch(e){w.innerHTML='<div style="color:#f04747">Error: '+esc(e.message)+'</div>';w.style.display='block'}
  finally{b.textContent=t('resolve');b.disabled=false}
}
async function confirmWiz(){
  if(!_wizData)return;
  const domains=[_wizData.domain];const ips=[..._wizData.ips];const dns_resolve=[_wizData.domain];
  document.querySelectorAll('[data-wv]').forEach(cb=>{
    if(cb.checked){
      const vr=_wizData.variants[parseInt(cb.getAttribute('data-wv'))];
      domains.push(vr.domain);dns_resolve.push(vr.domain);vr.ips.forEach(ip=>{if(!ips.includes(ip))ips.push(ip)});
    }
  });
  await fetch('/api/add-site',{method:'POST',body:JSON.stringify({domain:_wizData.domain,domains,ips,dns_resolve})});
  document.getElementById('ns').value='';document.getElementById('wiz').style.display='none';_wizData=null;
}
function cancelWiz(){document.getElementById('wiz').style.display='none';_wizData=null;}
let _lastSites={};
function updateCdnSiteList(sites){
  _lastSites=sites;
  const sel=document.getElementById('cdnSite');
  const cur=sel.value;
  sel.innerHTML='<option value="">'+t('cdn_select_site')+'</option>';
  Object.keys(sites).forEach(s=>{
    const o=document.createElement('option');o.value=s;o.textContent=s;sel.appendChild(o);
  });
  if(cur&&sites[cur])sel.value=cur;
  renderSiteDomains(sites);
}
function renderSiteDomains(sites){
  const c=document.getElementById('siteDomains');
  let h='';
  Object.keys(sites).forEach(s=>{
    const doms=sites[s].domains||[];
    if(!doms.length)return;
    h+='<div style="margin-bottom:8px;"><div style="font-family:monospace;font-size:11px;font-weight:700;color:#7289da;margin-bottom:4px;">'+esc(s)+'</div><div class="site-domains">';
    doms.forEach(d=>{
      const se=esc(d).replace(/'/g,"\\'");
      h+='<span class="site-dom-tag"><span style="color:#b0b8d1">'+esc(d)+'</span><span class="dom-del" onclick="removeDom(\''+esc(s).replace(/'/g,"\\'")+'\',\''+se+'\')">&times;</span></span>';
    });
    h+='</div></div>';
  });
  c.innerHTML=h;
}
async function addCdn(){
  const inp=document.getElementById('cdnDomain'),raw=inp.value.trim().toLowerCase(),site=document.getElementById('cdnSite').value;
  const res=document.getElementById('cdnResult');
  if(!raw){res.innerHTML='<span style="color:#faa61a">'+t('cdn_no_domain')+'</span>';res.style.display='block';return}
  if(!site){res.innerHTML='<span style="color:#faa61a">'+t('cdn_select_site')+'</span>';res.style.display='block';return}
  const doms=raw.split(/[\n\r,;\s]+/).map(d=>d.trim()).filter(d=>d&&d.includes('.'));
  if(!doms.length){res.innerHTML='<span style="color:#faa61a">'+t('cdn_no_domain')+'</span>';res.style.display='block';return}
  const existing=(_lastSites[site]&&_lastSites[site].domains)||[];
  const skipped=[],added=[];
  for(const dom of doms){
    if(existing.includes(dom)){skipped.push(dom);continue}
    await fetch('/api/add-cdn',{method:'POST',body:JSON.stringify({site:site,domain:dom})});
    existing.push(dom);added.push(dom);
  }
  inp.value='';
  let msg='';
  if(added.length)msg+='<span style="color:#43b581">'+t('cdn_added')+' '+added.map(d=>esc(d)).join(', ')+' &rarr; '+esc(site)+'</span>';
  if(skipped.length)msg+=(msg?'<br>':'')+'<span style="color:#faa61a">'+t('cdn_domain_exists')+': '+skipped.map(d=>esc(d)).join(', ')+'</span>';
  res.innerHTML=msg;res.style.display='block';
  setTimeout(()=>{res.style.display='none'},5000);
}
async function removeDom(site,dom){
  await fetch('/api/remove-domain',{method:'POST',body:JSON.stringify({site:site,domain:dom})});
}
async function removeSite(s){if(confirm(t('confirm_remove_site')+' "'+s+'"?'))await fetch('/api/remove-site',{method:'POST',body:JSON.stringify({site:s})})}
async function removeAllSites(){if(confirm(t('confirm_remove_all_sites')))await fetch('/api/remove-all-sites',{method:'POST'})}
async function testSite(s){await fetch('/api/test-site',{method:'POST',body:JSON.stringify({site:s})})}
async function testAll(){await fetch('/api/test-all',{method:'POST'})}
const _stC={'direct':'#34d399','host_split':'#818cf8','fragment_light':'#fbbf24','tls_record_frag':'#22d3ee','fragment_burst':'#ff9800','desync':'#a78bfa','fragment_heavy':'#f87171','sni_shuffle':'#ec4899','fake_tls_inject':'#fb923c','triple_split':'#4ade80','sni_padding':'#f472b6','reverse_frag':'#facc15','slow_drip':'#94a3b8','oob_inline':'#2dd4bf','dot_shuffle':'#c084fc','tls_multi_record':'#38bdf8','tls_mixed_delay':'#a3e635','sni_split_byte':'#e879f9','header_fragment':'#fb7185'};
function renderST(hist){
  if(!hist||!hist.length)return;
  // Canvas chart
  const cv=document.getElementById('stch');if(!cv)return;
  const x=cv.getContext('2d');const r=window.devicePixelRatio||1;
  cv.width=cv.offsetWidth*r;cv.height=cv.offsetHeight*r;
  x.scale(r,r);const w=cv.offsetWidth,h=cv.offsetHeight;
  x.clearRect(0,0,w,h);
  // Grid
  x.strokeStyle='#252940';x.lineWidth=0.5;
  for(let i=0;i<4;i++){const y=h*(i/3);x.beginPath();x.moveTo(0,y);x.lineTo(w,y);x.stroke()}
  const succ=hist.filter(e=>e.success&&e.ms>0);
  if(succ.length>0){
    const mx=Math.max(...succ.map(e=>e.ms))*1.3||1;
    // Draw lines connecting points
    x.strokeStyle='#252940';x.lineWidth=1;x.beginPath();
    hist.forEach((e,i)=>{
      if(!e.success)return;
      const px=(i/(hist.length-1||1))*w,py=h-(e.ms/mx)*h;
      if(i===0||!hist[i-1].success)x.moveTo(px,py);else x.lineTo(px,py);
    });
    x.stroke();
    // Draw dots
    hist.forEach((e,i)=>{
      const px=(i/(hist.length-1||1))*w;
      const col=_stC[e.strategy]||'#747885';
      if(e.success){
        const py=h-(e.ms/mx)*h;
        x.beginPath();x.arc(px,py,4,0,Math.PI*2);x.fillStyle=col;x.fill();
        // Site label
        x.fillStyle='#8890a8';x.font='8px monospace';x.textAlign='center';
        x.fillText(e.site.slice(0,4),px,py-8);
      }else{
        // X mark for failures at top
        const py=8;
        x.strokeStyle=col;x.lineWidth=2;
        x.beginPath();x.moveTo(px-3,py-3);x.lineTo(px+3,py+3);x.stroke();
        x.beginPath();x.moveTo(px+3,py-3);x.lineTo(px-3,py+3);x.stroke();
      }
    });
  }
  // Text list (last 10)
  const sl=document.getElementById('stl');
  const last=hist.slice(-10).reverse();
  sl.innerHTML=last.map(e=>{
    const col=_stC[e.strategy]||'#747885';
    const icon=e.success?'<span style="color:var(--green)">&#10003;</span>':'<span style="color:var(--red)">&#10007;</span>';
    return '<div style="padding:3px 6px;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:center;border-radius:4px;">'
      +'<span style="color:var(--text3);min-width:55px">'+esc(e.time)+'</span>'
      +'<span style="color:#fff;min-width:60px;font-weight:600">'+esc(e.site)+'</span>'
      +'<span style="color:'+col+';min-width:100px">'+esc(e.strategy)+'</span>'
      +(e.ms?'<span style="color:var(--accent);min-width:45px">'+e.ms+'ms</span>':'<span style="min-width:45px;color:var(--text3)">--</span>')
      +icon+'</div>';
  }).join('');
}
function renderBypass(list,defaults){
  let h='';
  if(defaults&&defaults.length){
    h+='<div style="margin-bottom:10px;"><div class="sec-title" style="margin-bottom:6px;" data-i="default_bypass">Default (built-in)</div><div style="display:flex;flex-wrap:wrap;gap:4px;">';
    defaults.forEach(e=>{
      h+='<span style="display:inline-flex;align-items:center;background:var(--surface3);padding:3px 8px;border-radius:5px;font-size:10px;font-family:var(--mono);color:var(--text3);border:1px solid var(--border);">'+esc(e)+'</span>';
    });
    h+='</div></div>';
  }
  if(list&&list.length){
    h+='<div style="margin-bottom:6px;"><div class="sec-title" style="margin-bottom:6px;" data-i="custom_bypass">Custom</div><div style="display:flex;flex-wrap:wrap;gap:5px;">';
    list.forEach(e=>{
      const se=esc(e).replace(/'/g,"\\'");
      h+='<div style="display:inline-flex;align-items:center;background:var(--surface2);padding:4px 10px;border-radius:6px;gap:6px;border:1px solid var(--border);">'
        +'<span style="font-size:11px;font-family:var(--mono)">'+esc(e)+'</span>'
        +'<span style="cursor:pointer;color:var(--red);font-weight:bold;font-size:13px;opacity:.6;transition:opacity .2s;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.6" onclick="removeB(\''+se+'\')">&times;</span>'
        +'</div>';
    });
    h+='</div></div>';
  }
  document.getElementById('bl').innerHTML=h;
}
async function addB(){const i=document.getElementById('nb');const v=i.value.trim();if(!v)return;i.value='';await fetch('/api/add-bypass',{method:'POST',body:JSON.stringify({entry:v})})}
async function removeB(e){await fetch('/api/remove-bypass',{method:'POST',body:JSON.stringify({entry:e})})}
async function clearBypass(){if(confirm(t('Are you sure you want to clear the entire bypass list?'))){await fetch('/api/clear-bypass',{method:'POST'})}}
async function loadPreset(){const sel=document.getElementById('preset');const v=sel.value;if(!v)return;sel.value='';await fetch('/api/load-preset',{method:'POST',body:JSON.stringify({preset:v})})}
async function toggleAS(){await fetch('/api/toggle-autostart',{method:'POST'})}
async function fixUwp(){const b=document.getElementById('uwpBtn');b.disabled=true;b.textContent='...';try{await fetch('/api/fix-uwp',{method:'POST'});b.textContent=t('uwp_done');setTimeout(()=>{b.textContent=t('fix_uwp');b.disabled=false},3000)}catch(e){b.textContent='Error';b.disabled=false}}
function exportCfg(){window.open('/api/export-config','_blank')}
async function importCfg(ev){
  const f=ev.target.files[0];if(!f)return;
  try{const txt=await f.text();const r=await fetch('/api/import-config',{method:'POST',body:txt});
  if(r.ok)alert(t('import_ok'));else alert(t('import_fail'));}catch(e){alert(t('import_fail'))}
  ev.target.value='';
}
function copyLogs(){
  const l=document.getElementById('lg');
  const lines=Array.from(l.children).map(e=>e.textContent).join('\n');
  navigator.clipboard.writeText(lines).then(()=>{
    const b=document.querySelector('.card.full .btn');
    const orig=b.textContent;b.textContent=t('copied');setTimeout(()=>b.textContent=t('copy'),1500);
  });
}
function fU(s){const h=Math.floor(s/3600),m=Math.floor(s%3600/60),sc=s%60;return h>0?h+'h '+m+'m':m>0?m+'m '+sc+'s':sc+'s'}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML}
let _lf={all:true,bypass:false,pass:false,http:false,error:false};
function _lfMatch(lt){if(_lf.all)return true;if(_lf[lt])return true;if(!_lf.bypass&&!_lf.pass&&!_lf.http&&!_lf.error)return true;return false}
function toggleLF(btn){
  const f=btn.getAttribute('data-f');
  if(f==='all'){_lf={all:true,bypass:false,pass:false,http:false,error:false}}
  else{_lf.all=false;_lf[f]=!_lf[f];if(!_lf.bypass&&!_lf.pass&&!_lf.http&&!_lf.error)_lf.all=true}
  document.querySelectorAll('.lfb').forEach(b=>{b.classList.toggle('active',_lf[b.getAttribute('data-f')])});
  document.querySelectorAll('#lg .le').forEach(el=>{el.style.display=_lfMatch(el.getAttribute('data-lt')||'other')?'':'none'});
}
window.addEventListener('resize',dC);
const _cdnParts=['(function(){var h=location.hostname,ds={};performance.getEntriesByType("resource").forEach(function(e){try{var u=new URL(e.name),d=u.hostname;if(d&&d!==h&&d.indexOf("google")===-1&&d.indexOf("facebook")===-1&&d.indexOf("doubleclick")===-1&&d.indexOf("googleapis")===-1&&d.indexOf("gstatic")===-1&&d.indexOf("googletagmanager")===-1)ds[d]=1}catch(x){}});var doms=Object.keys(ds).sort();','if(!doms.length){console.log("No external domains found.");return}','var o=document.getElementById("_cnp");if(o)o.remove();var p=document.createElement("div");p.id="_cnp";','var s=p.style;s.cssText="position:fixed;top:10px;right:10px;z-index:999999;background:#1a1d2e;color:#b0b8d1;border:2px solid #7289da;border-radius:10px;padding:16px;font-family:Consolas,monospace;font-size:12px;max-height:80vh;overflow-y:auto;min-width:320px;box-shadow:0 4px 24px rgba(0,0,0,.5)";','var t=document.createElement("div");t.style.cssText="color:#7289da;font-weight:700;margin-bottom:8px;font-size:14px";t.textContent="CDN Domains ("+doms.length+")";p.appendChild(t);','doms.forEach(function(d){var r=document.createElement("div");r.style.cssText="padding:4px 0;border-bottom:1px solid #2a2e3f";r.textContent=d;p.appendChild(r)});','var bw=document.createElement("div");bw.style.cssText="margin-top:10px;display:flex;gap:8px";','var cb=document.createElement("button");cb.textContent="Copy All";cb.style.cssText="background:#43b581;color:#fff;border:none;padding:6px 16px;border-radius:6px;cursor:pointer;font-weight:700";','cb.onclick=function(){navigator.clipboard.writeText(doms.join("\\n"));cb.textContent="Copied!";setTimeout(function(){p.remove()},800)};bw.appendChild(cb);','var xb=document.createElement("button");xb.textContent="Close";xb.style.cssText="background:#f04747;color:#fff;border:none;padding:6px 16px;border-radius:6px;cursor:pointer;font-weight:700";','xb.onclick=function(){p.remove()};bw.appendChild(xb);p.appendChild(bw);document.body.appendChild(p)})()'];
const _cdnScript=_cdnParts.join('');
function copyCdnScript(){navigator.clipboard.writeText(_cdnScript).then(()=>{const b=document.getElementById('cdnCopyBtn');b.textContent=t('copied');setTimeout(()=>b.textContent=t('copy'),1500)})}
(function(){const el=document.getElementById('cdnSnippet');if(el){el.textContent=_cdnScript;const btn=document.createElement('button');btn.className='cdn-snippet-copy';btn.id='cdnCopyBtn';btn.textContent='Copy';btn.onclick=copyCdnScript;el.appendChild(btn)}})();
function renderAI(ai,sites){
  const acc=document.getElementById('ai_acc');
  const pred=document.getElementById('ai_pred');
  const obs=document.getElementById('ai_obs');
  const aiSites=document.getElementById('ai_sites');
  const status=document.getElementById('ai_status');
  if(!ai)return;
  acc.textContent=ai.accuracy+'%';
  acc.style.color=ai.accuracy>70?'var(--green)':ai.accuracy>40?'var(--orange)':'var(--red)';
  pred.textContent=ai.total_predictions;
  obs.textContent=ai.total_observations;
  aiSites.textContent=ai.sites_with_data;
  if(ai.sites_with_data>0){
    status.textContent=t('ai_active_label');status.className='badge b-running';
  }else{
    status.textContent=t('ai_learning');status.className='badge b-reconnecting';
  }
  // Update training intensity UI from server state
  if(ai.train_intensity&&ai.train_intensity!==_currentIntensity){
    updateIntensityUI(ai.train_intensity);
  }else if(!document.querySelector('.intensity-btn[style*="linear-gradient"]')){
    updateIntensityUI(ai.train_intensity||'light');
  }
  // AI site details
  const det=document.getElementById('ai_detail');
  if(sites){
    let h='';
    const sC={'direct':'#34d399','host_split':'#818cf8','fragment_light':'#fbbf24','tls_record_frag':'#22d3ee','fragment_burst':'#ff9800','desync':'#a78bfa','fragment_heavy':'#f87171','sni_shuffle':'#ec4899','fake_tls_inject':'#fb923c','triple_split':'#4ade80','sni_padding':'#f472b6','reverse_frag':'#facc15','slow_drip':'#94a3b8','oob_inline':'#2dd4bf','dot_shuffle':'#c084fc','tls_multi_record':'#38bdf8','tls_mixed_delay':'#a3e635','sni_split_byte':'#e879f9','header_fragment':'#fb7185'};
    Object.keys(sites).forEach(s=>{
      const si=sites[s];
      if(!si.ai||!si.ai.ai_active)return;
      const a=si.ai;
      const col=sC[a.predicted_strategy]||'#585e78';
      const confPct=Math.round(a.confidence*100);
      const confCol=confPct>70?'var(--green)':confPct>40?'var(--orange)':'var(--red)';
      h+='<div style="display:flex;align-items:center;gap:10px;padding:6px 8px;border-bottom:1px solid var(--border);border-radius:4px;">';
      h+='<span style="color:#fff;font-weight:600;min-width:70px;">'+esc(s)+'</span>';
      h+='<span style="color:'+col+';background:'+col+'15;padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;">'+esc(a.predicted_strategy)+'</span>';
      h+='<span style="color:'+confCol+';font-size:10px;">'+confPct+'% conf</span>';
      h+='<span style="color:var(--text3);font-size:10px;">'+a.total_observations+' obs</span>';
      if(a.top_3&&a.top_3.length>1){
        h+='<span style="color:var(--text3);font-size:9px;margin-left:auto;">';
        a.top_3.slice(1).forEach(p=>{
          h+='<span style="color:'+(sC[p.strategy]||'#585e78')+';margin-left:4px;">'+p.strategy.slice(0,6)+':'+Math.round(p.score*100)+'</span>';
        });
        h+='</span>';
      }
      h+='</div>';
    });
    det.innerHTML=h||'<div style="color:var(--text3);padding:8px;">'+t('ai_learning')+'...</div>';
  }
  // Heatmap
  renderAIHeatmap(sites);
}
function renderAIHeatmap(sites){
  const cv=document.getElementById('ai_heatmap');if(!cv)return;
  const x=cv.getContext('2d');const r=window.devicePixelRatio||1;
  cv.width=cv.offsetWidth*r;cv.height=cv.offsetHeight*r;
  x.scale(r,r);const w=cv.offsetWidth,h=cv.offsetHeight;
  x.clearRect(0,0,w,h);
  // Collect hour_best from all sites
  const hourData={};
  const sC={'direct':'#34d399','host_split':'#818cf8','fragment_light':'#fbbf24','tls_record_frag':'#22d3ee','fragment_burst':'#ff9800','desync':'#a78bfa','fragment_heavy':'#f87171','sni_shuffle':'#ec4899','fake_tls_inject':'#fb923c','triple_split':'#4ade80','sni_padding':'#f472b6','reverse_frag':'#facc15','slow_drip':'#94a3b8','oob_inline':'#2dd4bf','dot_shuffle':'#c084fc','tls_multi_record':'#38bdf8','tls_mixed_delay':'#a3e635','sni_split_byte':'#e879f9','header_fragment':'#fb7185'};
  if(!sites)return;
  const siteNames=Object.keys(sites).filter(s=>sites[s].ai&&sites[s].ai.hour_best);
  if(!siteNames.length)return;
  const cellW=w/24;const cellH=Math.min(20,h/(siteNames.length+1));
  // Header row - hours
  x.fillStyle='#585e78';x.font='8px monospace';x.textAlign='center';
  for(let hr=0;hr<24;hr++){
    x.fillText(hr.toString().padStart(2,'0'),hr*cellW+cellW/2,10);
  }
  // Rows per site
  siteNames.forEach((s,si)=>{
    const ai=sites[s].ai;
    const yOff=14+si*cellH;
    // Site label
    x.fillStyle='#8890a8';x.font='8px monospace';x.textAlign='left';
    for(let hr=0;hr<24;hr++){
      const hb=ai.hour_best[hr.toString()];
      const xPos=hr*cellW;
      if(hb){
        const col=sC[hb.strategy]||'#585e78';
        const alpha=Math.max(0.2,hb.rate);
        x.globalAlpha=alpha;
        x.fillStyle=col;
        x.fillRect(xPos+1,yOff,cellW-2,cellH-2);
        x.globalAlpha=1;
      }else{
        x.fillStyle='#181b27';
        x.fillRect(xPos+1,yOff,cellW-2,cellH-2);
      }
    }
    // Site name on right
    x.fillStyle='#8890a8';x.font='8px monospace';x.textAlign='left';
  });
}
// ==================== TRAINING ====================
let _trainPoll=null;
let _currentIntensity='light';
const _intensityInfo={
  light:{en:'Every 30min, 3 probes per site',tr:'30 dakikada bir, site basina 3 test',de:'Alle 30min, 3 Tests pro Seite'},
  medium:{en:'Every 10min, 5 probes per site',tr:'10 dakikada bir, site basina 5 test',de:'Alle 10min, 5 Tests pro Seite'},
  heavy:{en:'Every 2min, 8 probes per site',tr:'2 dakikada bir, site basina 8 test',de:'Alle 2min, 8 Tests pro Seite'},
  nonstop:{en:'Every 15s, 10 probes per site (24/7)',tr:'15 saniyede bir, site basina 10 test (7/24)',de:'Alle 15s, 10 Tests pro Seite (24/7)'}
};
function updateIntensityUI(intensity){
  _currentIntensity=intensity;
  document.querySelectorAll('.intensity-btn').forEach(b=>{
    const isActive=b.dataset.intensity===intensity;
    b.style.background=isActive?'linear-gradient(135deg,var(--accent),var(--purple))':'transparent';
    b.style.borderColor=isActive?'var(--accent)':'var(--border)';
    b.style.color=isActive?'#fff':'var(--text2)';
  });
  const desc=document.getElementById('intensityDesc');
  if(desc&&_intensityInfo[intensity]){desc.textContent=_intensityInfo[intensity][L]||_intensityInfo[intensity].en;}
  const warn=document.getElementById('intensityWarning');
  if(warn){warn.style.display=(intensity==='nonstop'||intensity==='heavy')?'block':'none';}
}
function updateSelfTrainUI(st){
  const dot=document.getElementById('selfTrainDot');
  const txt=document.getElementById('selfTrainText');
  const info=document.getElementById('selfTrainInfo');
  if(!dot||!txt)return;
  if(st.running){
    dot.style.background='var(--green)';
    dot.style.animation='pulse 1s infinite';
    txt.style.color='var(--green)';
    txt.textContent=st.last_site?('Training '+st.last_site+'...'):'Training...';
  }else if(st.total_probes>0){
    dot.style.background='var(--accent)';
    dot.style.animation='none';
    txt.style.color='var(--text2)';
    const ago=st.last_run>=0?(st.last_run<60?st.last_run+'s ago':Math.floor(st.last_run/60)+'m ago'):'';
    txt.textContent='Idle'+(ago?' · '+ago:'');
  }else{
    dot.style.background='var(--text3)';
    dot.style.animation='none';
    txt.style.color='var(--text3)';
    txt.textContent=L==='tr'?'Bekleniyor...':'Waiting...';
  }
  if(st.total_probes>0&&info){
    info.style.display='block';
    const pr=document.getElementById('stProbes');if(pr)pr.textContent=st.total_probes;
    const cy=document.getElementById('stCycles');if(cy)cy.textContent=st.cycle_count;
    const la=document.getElementById('stLast');if(la)la.textContent=st.last_result||'-';
    if(st.last_result&&st.last_result.includes('OK')){la.style.color='var(--green)';}
    else if(st.last_result&&st.last_result.includes('FAIL')){la.style.color='var(--red)';}
  }
}
async function setTrainIntensity(intensity){
  updateIntensityUI(intensity);
  try{
    await fetch('/api/ai-train-intensity',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({intensity:intensity})});
  }catch(e){console.error('Set intensity error:',e);}
}
async function startTraining(){
  const b=document.getElementById('trainBtn');b.disabled=true;b.textContent=t('training_active');
  document.getElementById('trainPanel').style.display='block';
  document.getElementById('trainProgress').innerHTML='<div style="color:var(--accent);font-size:11px;">'+t('training_progress')+'</div>';
  document.getElementById('trainResults').innerHTML='';
  await fetch('/api/train-start',{method:'POST'});
  _trainPoll=setInterval(pollTraining,2000);
}
async function pollTraining(){
  try{
    const r=await fetch('/api/train-status');const d=await r.json();
    let ph='';
    if(d.progress){Object.keys(d.progress).forEach(s=>{
      const p=d.progress[s];
      ph+='<div style="margin-bottom:6px;"><span style="color:#fff;font-size:11px;font-weight:600;">'+s+'</span> ';
      ph+='<span style="color:var(--text3);font-size:10px;">'+p.current_strat+' ('+p.tested+'/'+p.total+')</span>';
      ph+='<div style="background:var(--surface3);border-radius:4px;height:4px;margin-top:3px;"><div style="background:linear-gradient(90deg,var(--accent),var(--purple));height:100%;border-radius:4px;width:'+p.pct+'%;transition:width .3s;"></div></div></div>';
    })}
    document.getElementById('trainProgress').innerHTML=ph||'<div style="color:var(--accent);font-size:11px;">'+t('training_progress')+'</div>';
    if(d.completed&&!d.active){
      clearInterval(_trainPoll);_trainPoll=null;
      const b=document.getElementById('trainBtn');b.disabled=false;b.textContent=t('train_ai');
      document.getElementById('trainProgress').innerHTML='<div style="color:var(--green);font-size:11px;font-weight:600;">'+t('training_complete')+'</div>';
      let rh='';
      if(d.results){Object.keys(d.results).forEach(s=>{
        const rs=d.results[s];
        const canRevert=d.previous_strategies&&d.previous_strategies[s]!==undefined;
        rh+='<div style="background:var(--surface2);border-radius:8px;padding:10px;margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;gap:8px;">';
        rh+='<div><span style="color:#fff;font-weight:600;font-size:11px;">'+s+'</span><br>';
        if(rs.best_strategy){rh+='<span style="color:var(--green);font-size:10px;font-weight:700;">'+rs.best_strategy+'</span> <span style="color:var(--text3);font-size:9px;">'+rs.best_ms+'ms ('+rs.success_count+'/'+rs.total_tested+')</span>';}
        else{rh+='<span style="color:var(--red);font-size:10px;">'+t('no_improvement')+'</span>';}
        rh+='</div><div style="display:flex;gap:4px;">';
        if(rs.best_strategy){rh+='<button class="btn btn-sm btn-green" onclick="applyTraining(\''+s+'\')">'+t('apply_strategy')+'</button>';}
        if(canRevert){rh+='<button class="btn btn-sm btn-red" onclick="revertTraining(\''+s+'\')">'+t('revert_strategy')+'</button>';}
        rh+='</div></div>';
      })}
      document.getElementById('trainResults').innerHTML=rh;
    }
  }catch(e){console.error('pollTraining error:',e)}
}
async function applyTraining(s){await fetch('/api/train-apply',{method:'POST',body:JSON.stringify({site:s})});if(_trainPoll)clearInterval(_trainPoll);pollTraining()}
async function revertTraining(s){await fetch('/api/train-revert',{method:'POST',body:JSON.stringify({site:s})});pollTraining()}
applyLang();
// Initialize training intensity from server
fetch('/api/ai-train-intensity').then(r=>r.json()).then(d=>{if(d.intensity)updateIntensityUI(d.intensity)}).catch(()=>{updateIntensityUI('light')});
</script></body></html>"""

async def handle_http(reader, writer):
    global _ai_train_intensity
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        if not request_line:
            return

        parts = request_line.decode(errors='ignore').strip().split(' ')
        method = parts[0] if parts else 'GET'
        path = parts[1] if len(parts) > 1 else '/'

        while True:
            line = await reader.readline()
            if line == b'\r\n' or not line:
                break

        if path == '/':
            body = DASHBOARD_HTML.encode('utf-8')
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n'
                b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
            )
            writer.write(body)

        elif path == '/api/stats':
            data = json.dumps(_get_stats_data()).encode()
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                b'Content-Length: ' + str(len(data)).encode() + b'\r\n\r\n'
            )
            writer.write(data)

        elif path == '/api/events':
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n'
                b'Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n'
            )
            await writer.drain()
            last_log_id = 0
            while _running:
                data, last_log_id = _get_sse_data(last_log_id)
                try:
                    writer.write(f'data: {json.dumps(data)}\n\n'.encode())
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                    break
                await asyncio.sleep(1)
            return

        elif path == '/api/refresh-ips' and method == 'POST':
            asyncio.create_task(resolve_bypass_ips())
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/reload-config' and method == 'POST':
            reload_config_dynamically()
            asyncio.create_task(resolve_bypass_ips())
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/toggle-site' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site')
                if site_name and site_name in _config.get('sites', {}):
                    cur = _config['sites'][site_name].get('enabled', True)
                    _config['sites'][site_name]['enabled'] = not cur
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    asyncio.create_task(resolve_bypass_ips())
            except Exception as e:
                logger.error(f"Toggle error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/remove-site' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site')
                if site_name and site_name in _config.get('sites', {}):
                    del _config['sites'][site_name]
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    logger.info(f"Site removed: {site_name}")
            except Exception as e:
                logger.error(f"Remove site error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/remove-all-sites' and method == 'POST':
            try:
                _config['sites'] = {}
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(_config, f, indent=4)
                reload_config_dynamically()
                logger.info("All sites removed")
            except Exception as e:
                logger.error(f"Remove all sites error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/resolve-domain' and method == 'POST':
            result = {'domain': '', 'ips': [], 'variants': []}
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                domain = req_data.get('domain', '').strip().lower()
                if domain:
                    result['domain'] = domain
                    loop = asyncio.get_event_loop()
                    ips = await loop.run_in_executor(None, _resolve_domain_doh, domain)
                    result['ips'] = ips
                    variants = []
                    for prefix in ['www', 'cdn', 'api', 'static', 'media', 'app']:
                        sub = f"{prefix}.{domain}"
                        sub_ips = await loop.run_in_executor(None, _resolve_domain_doh, sub)
                        if sub_ips:
                            variants.append({'domain': sub, 'ips': sub_ips})
                    result['variants'] = variants
            except Exception as e:
                logger.error(f"Resolve domain error: {e}")
            data = json.dumps(result).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n')
            writer.write(data)

        elif path == '/api/add-site' and method == 'POST':
            try:
                body_bytes = await reader.read(4096)
                req_data = json.loads(body_bytes.decode())
                domain = req_data.get('domain', '').strip().lower()
                if domain:
                    base_name = domain.replace('www.', '').split('.')[0]
                    domains = req_data.get('domains', [domain, f"www.{domain}"])
                    ips = req_data.get('ips', [])
                    dns_resolve = req_data.get('dns_resolve', list(domains))
                    if 'sites' not in _config:
                        _config['sites'] = {}
                    _config['sites'][base_name] = {
                        "enabled": True,
                        "domains": domains,
                        "dns_resolve": dns_resolve,
                        "ips": ips
                    }
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    asyncio.create_task(resolve_bypass_ips())
            except Exception as e:
                logger.error(f"Add site error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/add-cdn' and method == 'POST':
            try:
                body_bytes = await reader.read(2048)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site', '').strip()
                cdn_domain = req_data.get('domain', '').strip().lower()
                if site_name and cdn_domain and site_name in _config.get('sites', {}):
                    site_cfg = _config['sites'][site_name]
                    domains = site_cfg.get('domains', [])
                    dns_resolve = site_cfg.get('dns_resolve', [])
                    if cdn_domain not in domains:
                        domains.append(cdn_domain)
                        site_cfg['domains'] = domains
                    if cdn_domain not in dns_resolve:
                        dns_resolve.append(cdn_domain)
                        site_cfg['dns_resolve'] = dns_resolve
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    asyncio.create_task(resolve_bypass_ips())
                    logger.info(f"CDN domain added: {cdn_domain} -> {site_name}")
            except Exception as e:
                logger.error(f"Add CDN error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/remove-domain' and method == 'POST':
            try:
                body_bytes = await reader.read(2048)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site', '').strip()
                domain = req_data.get('domain', '').strip().lower()
                if site_name and domain and site_name in _config.get('sites', {}):
                    site_cfg = _config['sites'][site_name]
                    domains = site_cfg.get('domains', [])
                    dns_resolve = site_cfg.get('dns_resolve', [])
                    if domain in domains:
                        domains.remove(domain)
                        site_cfg['domains'] = domains
                    if domain in dns_resolve:
                        dns_resolve.remove(domain)
                        site_cfg['dns_resolve'] = dns_resolve
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    asyncio.create_task(resolve_bypass_ips())
                    logger.info(f"Domain removed: {domain} from {site_name}")
            except Exception as e:
                logger.error(f"Remove domain error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/reset-strategies' and method == 'POST':
            _strategy_cache.reset_all()
            _ai_engine.reset()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/ai-stats':
            stats = _ai_engine.get_global_stats()
            stats['train_intensity'] = _ai_train_intensity
            stats['train_profile'] = AI_TRAIN_PROFILES.get(_ai_train_intensity, AI_TRAIN_PROFILES['light'])
            ai_data = json.dumps(stats).encode()
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                b'Content-Length: ' + str(len(ai_data)).encode() + b'\r\n\r\n'
            )
            writer.write(ai_data)

        elif path == '/api/ai-train-intensity' and method == 'GET':
            resp = json.dumps({'intensity': _ai_train_intensity, 'profiles': AI_TRAIN_PROFILES}).encode()
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                b'Content-Length: ' + str(len(resp)).encode() + b'\r\n\r\n'
            )
            writer.write(resp)

        elif path == '/api/ai-train-intensity' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                body_data = json.loads(body_bytes.decode()) if body_bytes else {}
                new_intensity = body_data.get('intensity', 'light')
                if new_intensity in AI_TRAIN_PROFILES:
                    _ai_train_intensity = new_intensity
                    _ai_engine._dirty = True
                    _ai_engine._do_save()
                    logger.info(f"[AI] Training intensity changed to: {new_intensity}")
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')
                else:
                    writer.write(b'HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{"error":"invalid intensity"}')
            except Exception as e:
                logger.error(f"[AI] Set intensity error: {e}")
                writer.write(b'HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{"error":"server error"}')

        elif path == '/api/ai-reset' and method == 'POST':
            _ai_engine.reset()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/train-start' and method == 'POST':
            if not _training_state['active']:
                asyncio.create_task(_train_all_sites())
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/train-status':
            train_data = json.dumps({
                'active': _training_state['active'],
                'completed': _training_state['completed'],
                'progress': _training_state['progress'],
                'results': {s: {k: v for k, v in r.items() if k != 'all_results'} for s, r in _training_state['results'].items()},
                'previous_strategies': _training_state['previous_strategies'],
            }).encode()
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                b'Content-Length: ' + str(len(train_data)).encode() + b'\r\n\r\n'
            )
            writer.write(train_data)

        elif path == '/api/train-apply' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site', '')
                if site_name:
                    _apply_training(site_name)
            except Exception as e:
                logger.error(f"Train apply error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/train-revert' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site', '')
                if site_name:
                    _revert_training(site_name)
            except Exception as e:
                logger.error(f"Train revert error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/add-bypass' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                entry = req_data.get('entry', '').strip()
                if entry and entry not in ALWAYS_BYPASS:
                    if 'proxy_bypass' not in _config:
                        _config['proxy_bypass'] = []
                    if entry not in _config['proxy_bypass']:
                        _config['proxy_bypass'].append(entry)
                        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                            json.dump(_config, f, indent=4)
                        reload_config_dynamically()
            except Exception as e:
                logger.error(f"Add bypass error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/remove-bypass' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                entry = req_data.get('entry', '').strip()
                if entry and 'proxy_bypass' in _config:
                    _config['proxy_bypass'] = [e for e in _config['proxy_bypass'] if e != entry]
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
            except Exception as e:
                logger.error(f"Remove bypass error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/clear-bypass' and method == 'POST':
            try:
                if 'proxy_bypass' in _config:
                    _config['proxy_bypass'] = []
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    logger.info("Cleared all proxy bypass entries")
            except Exception as e:
                logger.error(f"Clear bypass error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/load-preset' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                preset_name = req_data.get('preset', '')
                if preset_name in BYPASS_PRESETS:
                    if 'proxy_bypass' not in _config:
                        _config['proxy_bypass'] = []
                    existing = set(_config['proxy_bypass'])
                    for entry in BYPASS_PRESETS[preset_name]:
                        if entry not in existing:
                            _config['proxy_bypass'].append(entry)
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    logger.info(f"Loaded preset: {preset_name}")
            except Exception as e:
                logger.error(f"Load preset error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/get-autostart':
            data = json.dumps({'autostart': get_autostart()}).encode()
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                b'Content-Length: ' + str(len(data)).encode() + b'\r\n\r\n'
            )
            writer.write(data)

        elif path == '/api/toggle-autostart' and method == 'POST':
            current = get_autostart()
            set_autostart(not current)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/test-site' and method == 'POST':
            try:
                body_bytes = await reader.read(1024)
                req_data = json.loads(body_bytes.decode())
                site_name = req_data.get('site', '')
                if site_name and site_name in _config.get('sites', {}):
                    asyncio.create_task(test_site_connection(site_name))
            except Exception as e:
                logger.error(f"Test site error: {e}")
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/test-all' and method == 'POST':
            for sn in _config.get('sites', {}):
                if _config['sites'][sn].get('enabled', True):
                    asyncio.create_task(test_site_connection(sn))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')

        elif path == '/api/export-config':
            data = json.dumps(_config, indent=2, ensure_ascii=False).encode('utf-8')
            writer.write(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                b'Content-Disposition: attachment; filename="cleannet_config.json"\r\n'
                b'Content-Length: ' + str(len(data)).encode() + b'\r\n\r\n'
            )
            writer.write(data)

        elif path == '/api/import-config' and method == 'POST':
            try:
                body_bytes = await reader.read(65536)
                new_config = json.loads(body_bytes.decode())
                if 'sites' in new_config:
                    _config.update(new_config)
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(_config, f, indent=4)
                    reload_config_dynamically()
                    asyncio.create_task(resolve_bypass_ips())
                    logger.info("Config imported successfully")
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')
                else:
                    writer.write(b'HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{"error":"Invalid config: missing sites"}')
            except json.JSONDecodeError:
                writer.write(b'HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{"error":"Invalid JSON"}')
            except Exception as e:
                logger.error(f"Import config error: {e}")
                writer.write(b'HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{"error":"Import failed"}')

        elif path == '/api/fix-uwp' and method == 'POST':
            try:
                import tempfile
                bat_path = os.path.join(tempfile.gettempdir(), 'cleannet_uwp_fix.bat')
                with open(bat_path, 'w', encoding='utf-8') as f:
                    f.write('@echo off\r\nCheckNetIsolation LoopbackExempt -a -p=S-1-15-2-1 >nul 2>&1\r\n')
                ctypes.windll.shell32.ShellExecuteW(None, 'runas', bat_path, None, None, 1)
                logger.info("[UWP] Loopback exemption requested (admin prompt)")
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')
            except Exception as e:
                logger.error(f"UWP fix error: {e}")
                writer.write(b'HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{"error":"UWP fix failed"}')

        else:
            writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')

        await writer.drain()
    except:
        pass
    finally:
        _close_writer(writer)

def _get_stats_data():
    site_data = {}
    for site_name, site_info in _config.get('sites', {}).items():
        strat_info = _strategy_cache.get_site_strategy_info(site_name)
        ss = _site_stats.get(site_name, {'connections': 0, 'successes': 0, 'failures': 0, 'total_ms': 0})
        avg_ms = round(ss['total_ms'] / ss['successes']) if ss['successes'] > 0 else 0
        ai_insights = _ai_engine.get_site_insights(site_name)
        site_data[site_name] = {
            'enabled': site_info.get('enabled', True),
            'current_strategy': strat_info['strategy'],
            'strategy_time_ms': strat_info['time_ms'],
            'domains': site_info.get('domains', []),
            'domain_count': len(site_info.get('domains', [])),
            'conn_count': ss['connections'],
            'success_count': ss['successes'],
            'fail_count': ss['failures'],
            'avg_ms': avg_ms,
            'test': _test_results.get(site_name),
            'ai': ai_insights,
        }
    return {
        'status': _status,
        'ping': _ping_ms,
        'uptime': int(time.time() - _start_time) if _start_time else 0,
        'connections': _stats['connections'],
        'fragments': _stats['fragments'],
        'ip_updates': _stats['ip_updates'],
        'strategy_tries': _stats['strategy_tries'],
        'strategy_fallbacks': _stats['strategy_fallbacks'],
        'ips': list(BYPASS_IPS),
        'sites': site_data,
        'proxy_bypass': _config.get('proxy_bypass', []),
        'always_bypass': ALWAYS_BYPASS,
        'autostart': get_autostart(),
        'strategy_history': list(_strategy_history)[-50:],
        'ai_stats': _ai_engine.get_global_stats(),
        'training': {'active': _training_state['active'], 'completed': _training_state['completed']},
        'self_train': {
            'running': _self_train_state['running'],
            'total_probes': _self_train_state['total_probes'],
            'cycle_count': _self_train_state['cycle_count'],
            'last_site': _self_train_state['last_site'],
            'last_result': _self_train_state['last_result'],
            'last_run': int(time.time() - _self_train_state['last_run']) if _self_train_state['last_run'] > 0 else -1,
        },
    }

def _get_sse_data(last_log_id):
    entries = _dashboard_handler.get_entries_after(last_log_id)
    new_id = entries[-1][0] if entries else last_log_id
    data = _get_stats_data()
    data['new_logs'] = [msg for _, msg in entries]
    return data, new_id

# ==================== SYSTEM TRAY ====================

_STATUS_COLORS = {
    "running": (67, 181, 129), "stopped": (150, 150, 150),
    "error": (240, 71, 71), "reconnecting": (250, 166, 26),
}
_STATUS_TEXT = {
    "running": "Active", "stopped": "Stopped",
    "error": "Connection Error", "reconnecting": "Reconnecting",
}

def _create_icon(color):
    import math
    sz = 64
    img = Image.new('RGBA', (sz, sz), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy, r = sz // 2, sz // 2, 26
    # Hexagon
    pts = [(cx + r * math.cos(math.radians(a - 90)), cy + r * math.sin(math.radians(a - 90))) for a in range(0, 360, 60)]
    draw.polygon(pts, outline=color, fill=None)
    draw.polygon(pts, outline=color)  # thicker border
    inner = [(cx + (r-2) * math.cos(math.radians(a - 90)), cy + (r-2) * math.sin(math.radians(a - 90))) for a in range(0, 360, 60)]
    draw.polygon(inner, outline=color)
    # Clock hands inside
    draw.line([(cx, cy), (cx, cy - 14)], fill=color, width=3)  # minute hand (up)
    draw.line([(cx, cy), (cx + 10, cy + 6)], fill=color, width=3)  # hour hand
    # Center dot
    draw.ellipse([cx - 3, cy - 3, cx + 3, cy + 3], fill=color)
    return img

def _update_tray():
    if _tray_icon:
        try:
            color = _STATUS_COLORS.get(_status, (150, 150, 150))
            _tray_icon.icon = _create_icon(color)
            ping_str = f" | {_ping_ms}ms" if _ping_ms > 0 else ""
            _tray_icon.title = f"CleanNet - {_STATUS_TEXT.get(_status, _status)}{ping_str}"
        except:
            pass

def _on_open_dashboard(icon, item):
    import webbrowser
    webbrowser.open(f'http://{LOCAL_HOST}:{WEB_PORT}')

def _on_refresh_ips(icon, item):
    if _loop:
        asyncio.run_coroutine_threadsafe(resolve_bypass_ips(), _loop)

def _on_open_log(icon, item):
    if os.path.exists(LOG_FILE):
        os.startfile(LOG_FILE)

def _on_exit(icon, item):
    global _running
    logger.info("User exit")
    _running = False
    _strategy_cache.force_save()
    _ai_engine.force_save()
    set_proxy(False)
    if _loop and _shutdown_event:
        _loop.call_soon_threadsafe(_shutdown_event.set)
    icon.stop()

def _get_user_language():
    """Detect Windows display language: tr, de, or en (fallback)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\International")
        locale_name = winreg.QueryValueEx(key, "LocaleName")[0]
        winreg.CloseKey(key)
        lang = locale_name.split('-')[0].lower()
        if lang in ('tr', 'de'):
            return lang
    except Exception:
        pass
    return 'en'

def _do_full_shutdown(icon):
    """Runs in a separate thread so MessageBox doesn't block pystray."""
    global _running
    import ctypes as _ct
    MB_YESNO = 0x04
    MB_ICONWARNING = 0x30
    MB_TOPMOST = 0x40000
    IDYES = 6

    lang = _get_user_language()

    if lang == 'tr':
        title = "CleanNet - Tam Kapatma"
        msg = (
            "Bu islem asagidakileri yapacaktir:\n\n"
            "1. DPI Bypass proxy'si durdurulacak\n"
            "2. Windows proxy ayarlari sifirlanacak\n"
            "3. DNS onbellegi temizlenecek (ipconfig /flushdns)\n\n"
            "Diger uygulamalariniz etkilenmeyecektir.\n\n"
            "Devam etmek istiyor musunuz?"
        )
    elif lang == 'de':
        title = "CleanNet - Vollstaendiges Herunterfahren"
        msg = (
            "Folgende Aktionen werden ausgefuehrt:\n\n"
            "1. DPI-Bypass-Proxy wird gestoppt\n"
            "2. Windows-Proxy-Einstellungen werden zurueckgesetzt\n"
            "3. DNS-Cache wird geleert (ipconfig /flushdns)\n\n"
            "Andere Anwendungen werden nicht beeintraechtigt.\n\n"
            "Moechten Sie fortfahren?"
        )
    else:
        title = "CleanNet - Full Shutdown"
        msg = (
            "The following actions will be performed:\n\n"
            "1. DPI Bypass proxy will be stopped\n"
            "2. Windows proxy settings will be cleared\n"
            "3. DNS cache will be flushed (ipconfig /flushdns)\n\n"
            "Other applications will not be affected.\n\n"
            "Do you want to continue?"
        )

    result = _ct.windll.user32.MessageBoxW(
        0, msg, title,
        MB_YESNO | MB_ICONWARNING | MB_TOPMOST
    )
    if result != IDYES:
        return

    logger.info("Full shutdown initiated")
    _running = False
    _strategy_cache.force_save()
    _ai_engine.force_save()
    set_proxy(False)
    if _loop and _shutdown_event:
        _loop.call_soon_threadsafe(_shutdown_event.set)

    import tempfile
    bat_content = (
        '@echo off\r\n'
        'ipconfig /flushdns >nul 2>&1\r\n'
        'echo [OK] DNS cache flushed.\r\n'
        'timeout /t 2 /nobreak >nul\r\n'
    )
    bat_path = os.path.join(tempfile.gettempdir(), 'dpi_bypass_shutdown.bat')
    try:
        with open(bat_path, 'w', encoding='utf-8') as f:
            f.write(bat_content)
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', bat_path, None, None, 1)
    except Exception as e:
        logger.error(f"Full shutdown error: {e}")
    icon.stop()

def _on_full_shutdown(icon, item):
    threading.Thread(target=_do_full_shutdown, args=(icon,), daemon=True).start()

def _on_restart(icon, item):
    global _running
    _running = False
    if _loop and _shutdown_event:
        _loop.call_soon_threadsafe(_shutdown_event.set)
    icon.stop()
    subprocess.Popen([sys.executable, __file__])

def _setup_tray():
    global _tray_icon
    menu = pystray.Menu(
        pystray.MenuItem('CleanNet v1.1.0', None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(lambda t: f"Status: {_STATUS_TEXT.get(_status, _status)}", None, enabled=False),
        pystray.MenuItem(lambda t: f"Ping: {_ping_ms}ms" if _ping_ms > 0 else "Ping: --", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Dashboard", _on_open_dashboard),
        pystray.MenuItem("Refresh IPs", _on_refresh_ips),
        pystray.MenuItem("Log File", _on_open_log),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Restart", _on_restart),
        pystray.MenuItem("Exit", _on_exit),
        pystray.MenuItem("Full Shutdown (Reset Network)", _on_full_shutdown),
    )
    _tray_icon = pystray.Icon('cleannet', _create_icon(_STATUS_COLORS["running"]),
                               'CleanNet - Active', menu)
    return _tray_icon

# ==================== MAIN ====================

async def _async_main():
    global _shutdown_event, _running, _status
    _shutdown_event = asyncio.Event()

    try:
        proxy = await asyncio.start_server(handle_proxy_client, LOCAL_HOST, LOCAL_PORT)
    except OSError:
        logger.warning(f"Port {LOCAL_PORT} already in use")
        _port_ready.set()
        return

    _port_ready.set()
    _running = True
    _status = "running"
    logger.info(f"Proxy listening: {LOCAL_HOST}:{LOCAL_PORT}")

    web = None
    try:
        web = await asyncio.start_server(handle_http, LOCAL_HOST, WEB_PORT)
        logger.info(f"Dashboard: http://{LOCAL_HOST}:{WEB_PORT}")
    except OSError:
        logger.warning(f"Dashboard port {WEB_PORT} busy")

    asyncio.create_task(health_check_loop())
    asyncio.create_task(strategy_retest_loop())
    asyncio.create_task(_self_training_loop())
    await _shutdown_event.wait()

    proxy.close()
    await proxy.wait_closed()
    if web:
        web.close()
        await web.wait_closed()

def _run_async_loop(loop):
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_async_main())
    except:
        pass

def start_proxy():
    global _loop, _start_time, _running

    logger.info("=" * 50)
    logger.info("CleanNet v1.1.0 starting...")
    logger.info(f"Bypass sites: {', '.join(_site_names)}")

    set_proxy(False)

    _loop = asyncio.new_event_loop()
    async_thread = threading.Thread(target=_run_async_loop, args=(_loop,), daemon=True)
    async_thread.start()

    if not _port_ready.wait(timeout=5):
        logger.error("Proxy failed to start")
        sys.exit(0)

    if not _running:
        sys.exit(0)

    set_proxy(True)
    _start_time = time.time()
    logger.info("System proxy enabled")

    if TRAY_AVAILABLE:
        try:
            icon = _setup_tray()
            icon.run()
        except Exception as e:
            logger.error(f"Tray error: {e}")
            try:
                while _running:
                    time.sleep(1)
            except:
                pass
    else:
        try:
            while _running:
                time.sleep(1)
        except:
            pass

    _running = False
    set_proxy(False)
    logger.info("DPI Bypass shut down")

if __name__ == '__main__':
    start_proxy()
