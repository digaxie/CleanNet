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
                   'fragment_burst', 'desync', 'fragment_heavy', 'sni_shuffle']
STRATEGY_SUCCESS_TIMEOUT = 10.0
STRATEGY_FAILURE_COOLDOWN = 3600
STRATEGY_RETEST_INTERVAL = 7200
STRATEGY_SAVE_INTERVAL = 60
STRATEGY_CACHE_FILE = os.path.join(_script_dir, 'strategy_cache.json')
STATS_FILE = os.path.join(_script_dir, 'stats.json')

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



def _atexit_handler():
    _strategy_cache.force_save()
    _save_stats()
    set_proxy(False)

atexit.register(_atexit_handler)

def _cleanup_handler(signum, frame):
    _strategy_cache.force_save()
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
        result = {'status': 'fail', 'ms': elapsed, 'time': _now_iso(), 'error': str(e)[:50]}
    _test_results[site_name] = result
    logger.info(f"[TEST] {site_name}: {result['status']} ({result.get('ms', 0)}ms)")

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
        writer.write(data[:1])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(data[1:3])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(data[3:5])
        await writer.drain()
        await asyncio.sleep(0.05)
        remaining = data[5:]
        for i in range(0, len(remaining), 4):
            writer.write(remaining[i:i + 4])
            await writer.drain()
            await asyncio.sleep(0.005)
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

STRATEGY_FUNCS = {
    'direct': strategy_direct,
    'host_split': strategy_host_split,
    'fragment_light': strategy_fragment_light,
    'tls_record_frag': strategy_tls_record_frag,
    'fragment_burst': strategy_fragment_burst,
    'desync': strategy_desync,
    'fragment_heavy': strategy_fragment_heavy,
    'sni_shuffle': strategy_sni_shuffle,
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
        if sd['best_strategy'] is None or elapsed_ms < (sd.get('best_time_ms') or 99999):
            sd['best_strategy'] = strategy
            sd['best_time_ms'] = round(elapsed_ms, 1)
        sd['last_success'] = now_iso
        self._dirty = True
        self._save_if_needed()

    def record_failure(self, site_name, strategy):
        sd = self._get_site_data(site_name)
        fail = sd['failures'].setdefault(strategy, {'count': 0, 'last_fail': ''})
        fail['count'] += 1
        fail['last_fail'] = _now_iso()
        if sd['best_strategy'] == strategy:
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
                remaining_ips = [ip for ip in ip_pool if ip != try_ip]
                for strat_name in strategies:
                    _stats['strategy_tries'] += 1
                    s_reader, s_writer = await _try_connect(try_ip, target_port, remaining_ips)
                    if not s_writer:
                        break

                    start_t = time.perf_counter()
                    try:
                        await STRATEGY_FUNCS[strat_name](s_writer, first_chunk)
                    except Exception as e:
                        logger.info(f"[STRATEGY] {site_name}: {strat_name} failed ({e}) IP:{try_ip}")
                        _close_writer(s_writer)
                        _strategy_cache.record_failure(site_name, strat_name)
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
                        _strategy_history.append({'time': datetime.now().strftime('%H:%M:%S'), 'site': site_name, 'strategy': strat_name, 'ms': 0, 'success': False})
                        _stats['strategy_fallbacks'] += 1
                        continue

                    # Success - at least one connection worked
                    all_conn_failed = False
                    elapsed_ms = (time.perf_counter() - start_t) * 1000
                    _strategy_cache.record_success(site_name, strat_name, elapsed_ms)
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
                s_reader_h, s_writer_h = await _try_connect(target_host, target_port, timeout=8)
                if not s_writer_h:
                    break
                start_t = time.perf_counter()
                try:
                    await STRATEGY_FUNCS[fallback_strat](s_writer_h, first_chunk)
                    server_reply = await asyncio.wait_for(s_reader_h.read(8192), timeout=8)
                    if server_reply and len(server_reply) >= 1 and server_reply[0] == 0x16:
                        elapsed_ms = (time.perf_counter() - start_t) * 1000
                        _strategy_cache.record_success(site_name, fallback_strat, elapsed_ms)
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
:root{--bg:#0a0b10;--surface:#12141d;--surface2:#181b27;--surface3:#1e2235;--border:#252940;--border2:#2d3250;--accent:#6c8aec;--accent2:#8ba3f5;--accent-glow:#6c8aec25;--green:#3dd68c;--red:#f05858;--orange:#f0a030;--cyan:#38c8d8;--purple:#a855f7;--pink:#ec4899;--text:#d0d5e8;--text2:#8890a8;--text3:#585e78;--mono:'JetBrains Mono',Consolas,monospace;--sans:'Inter','Segoe UI',system-ui,sans-serif}
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
</style></head><body>
<div class="hdr">
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" stroke="url(#hg)" stroke-width="2"/><path d="M12 8v4l3.5 2" stroke="url(#hg)" stroke-width="2" stroke-linecap="round"/><defs><linearGradient id="hg" x1="3" y1="2" x2="21" y2="22"><stop stop-color="#6c8aec"/><stop offset="1" stop-color="#a855f7"/></linearGradient></defs></svg>
  <h1>CleanNet</h1><span class="tag">v1.0</span>
  <div class="lang">
    <button onclick="setLang('en')" id="lb_en">EN</button>
    <button onclick="setLang('tr')" id="lb_tr">TR</button>
    <button onclick="setLang('de')" id="lb_de">DE</button>
  </div>
</div>
<div class="grid">
  <div class="card">
    <h2 data-i="status">Status</h2>
    <div class="row"><span data-i="status">Status</span><span id="st" class="badge b-running">Active</span></div>
    <div class="row"><span>Ping</span><span class="v" id="pg">--</span></div>
    <div class="row"><span>Uptime</span><span class="v" id="up">0s</span></div>
    <div class="row"><span data-i="autostart">Auto-start</span><span class="v"><label class="toggle"><input type="checkbox" id="as" onchange="toggleAS()"><span class="slider"></span></label></span></div>
  </div>
  <div class="card">
    <h2 data-i="statistics">Statistics</h2>
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
    <div id="il" class="ips"></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-sm btn-ghost" onclick="fetch('/api/refresh-ips',{method:'POST'})" data-i="refresh_ips">Refresh IPs</button>
      <button class="btn btn-sm btn-green" onclick="fetch('/api/reload-config',{method:'POST'})" data-i="reload_config">Reload Config</button>
      <button class="btn btn-sm btn-red" onclick="fetch('/api/reset-strategies',{method:'POST'})" data-i="reset_strategies">Reset Strategies</button>
    </div>
  </div>
  <div class="card full">
    <h2 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
      <span data-i="sites">Sites</span>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-sm" onclick="testAll()" data-i="test_all">Test All</button>
        <button class="btn btn-sm btn-red" onclick="removeAllSites()" data-i="remove_all_sites">Remove All</button>
      </div>
    </h2>
    <div id="sl" style="margin-bottom:14px;"></div>
    <div style="display:flex;gap:8px;margin-bottom:8px;">
      <input type="text" id="ns" class="inp" placeholder="example.com" style="flex:1;" onkeydown="if(event.key==='Enter')resolveS()">
      <button class="btn" onclick="resolveS()" id="resolveBtn" data-i="resolve">Resolve</button>
    </div>
    <div id="wiz" class="wizard-panel" style="display:none;"></div>
  </div>
  <div class="card full">
    <h2><span data-i="cdn_finder">CDN Finder</span></h2>
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
  <div class="card">
    <h2 data-i="proxy_bypass">Proxy Bypass (Exclude)</h2>
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
  <div class="card">
    <h2 data-i="config_mgmt">Config Management</h2>
    <div style="display:flex;flex-direction:column;gap:10px;">
      <button class="btn btn-ghost" onclick="exportCfg()" data-i="export_config">Export Config</button>
      <label class="btn btn-ghost" style="text-align:center;cursor:pointer;" data-i="import_config">Import Config
        <input type="file" accept=".json" onchange="importCfg(event)" style="display:none;">
      </label>
    </div>
  </div>
  <div class="card full">
    <h2 data-i="strategy_timeline">Strategy Timeline</h2>
    <div class="chart-wrap" style="height:140px;"><canvas id="stch"></canvas></div>
    <div id="stl" style="margin-top:10px;font-family:var(--mono);font-size:11px;max-height:120px;overflow-y:auto;"></div>
  </div>
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
    <div id="lg" class="log"></div>
  </div>
</div>
<script>
const I={
  en:{status:'Status',statistics:'Statistics',connections:'Connections',tls_fragment:'TLS Fragment',ip_updates:'IP Updates',strategy_attempts:'Strategy Attempts',fallbacks:'Fallbacks',ping_chart:'Ping Chart (last 2min)',ip_pool:'IP Pool',sites:'Sites',proxy_bypass:'Proxy Bypass (Exclude)',config_mgmt:'Config Management',autostart:'Auto-start',refresh_ips:'Refresh IPs',reload_config:'Reload Config',reset_strategies:'Reset Strategies',add_site:'Add Site',add:'Add',load:'Load',clear_all:'Clear All',load_preset:'Load Preset...',test_all:'Test All',test:'Test',export_config:'Export Config',import_config:'Import Config',copy:'Copy',copied:'Copied!',on:'On',off:'Off',active:'Active',error:'Error',reconnecting:'Reconnecting',stopped:'Stopped',conn:'Conn',success:'OK',fail:'Fail',avg:'Avg',testing:'Testing...',test_ok:'OK',test_fail:'Fail',import_ok:'Config imported!',import_fail:'Import failed',resolve:'Resolve',resolving:'Resolving...',confirm_add:'Confirm & Add',cancel:'Cancel',no_ips_found:'No IPs found for',subdomains_found:'Subdomains found',strategy_timeline:'Strategy Timeline',cdn_finder:'CDN Finder',cdn_help_desc:'Copy the script below, open the target site, press F12, paste it into Console and press Enter.',cdn_step1:'Copy script',cdn_step2:'Open target site + F12',cdn_step3:'Paste in Console + Enter',cdn_step4:'Add domains below',add_cdn:'Add CDN',cdn_added:'CDN domain added!',cdn_select_site:'Select site...',cdn_domain_exists:'Domain already exists',cdn_no_domain:'Enter a CDN domain',remove_domain:'Domain removed',site_domains:'Site Domains',remove_site:'Remove site',remove_all_sites:'Remove All',confirm_remove_site:'Remove site',confirm_remove_all_sites:'Remove all sites? This cannot be undone.'},
  tr:{status:'Durum',statistics:'Istatistikler',connections:'Baglantilar',tls_fragment:'TLS Fragment',ip_updates:'IP Guncelleme',strategy_attempts:'Strateji Denemeleri',fallbacks:'Geri Donusler',ping_chart:'Ping Grafigi (son 2dk)',ip_pool:'IP Havuzu',sites:'Siteler',proxy_bypass:'Proxy Haric Tutma',config_mgmt:'Config Yonetimi',autostart:'Otomatik Baslat',refresh_ips:'IP Guncelle',reload_config:'Config Yukle',reset_strategies:'Strateji Sifirla',add_site:'Site Ekle',add:'Ekle',load:'Yukle',clear_all:'Tumunu Sil',load_preset:'Preset Sec...',test_all:'Hepsini Test Et',test:'Test',export_config:'Config Disa Aktar',import_config:'Config Iceye Aktar',copy:'Kopyala',copied:'Kopyalandi!',on:'Acik',off:'Kapali',active:'Aktif',error:'Hata',reconnecting:'Yeniden Baglaniyor',stopped:'Durdu',conn:'Bag',success:'OK',fail:'Hata',avg:'Ort',testing:'Test ediliyor...',test_ok:'Basarili',test_fail:'Basarisiz',import_ok:'Config aktarildi!',import_fail:'Aktarim basarisiz',resolve:'Cozumle',resolving:'Cozumleniyor...',confirm_add:'Onayla ve Ekle',cancel:'Iptal',no_ips_found:'IP bulunamadi',subdomains_found:'Bulunan alt domainler',strategy_timeline:'Strateji Zaman Cizgisi',cdn_finder:'CDN Bulucu',cdn_help_desc:'Asagidaki scripti kopyala, hedef siteyi ac, F12 bas, Console sekmesine yapistir ve Enter bas.',cdn_step1:'Scripti kopyala',cdn_step2:'Hedef site + F12',cdn_step3:'Console yapistir + Enter',cdn_step4:'Domainleri asagiya ekle',add_cdn:'CDN Ekle',cdn_added:'CDN domaini eklendi!',cdn_select_site:'Site sec...',cdn_domain_exists:'Domain zaten mevcut',cdn_no_domain:'CDN domaini girin',remove_domain:'Domain kaldirildi',site_domains:'Site Domainleri',remove_site:'Siteyi sil',remove_all_sites:'Tumunu Sil',confirm_remove_site:'Siteyi sil',confirm_remove_all_sites:'Tum siteler silinsin mi? Bu islem geri alinamaz.'},
  de:{status:'Status',statistics:'Statistiken',connections:'Verbindungen',tls_fragment:'TLS Fragment',ip_updates:'IP Updates',strategy_attempts:'Strategieversuche',fallbacks:'Rueckfaelle',ping_chart:'Ping-Diagramm (letzte 2min)',ip_pool:'IP-Pool',sites:'Websites',proxy_bypass:'Proxy-Bypass (Ausschluss)',config_mgmt:'Config-Verwaltung',autostart:'Autostart',refresh_ips:'IPs aktualisieren',reload_config:'Config laden',reset_strategies:'Strategien zuruecksetzen',add_site:'Website hinzufuegen',add:'Hinzufuegen',load:'Laden',clear_all:'Alle loeschen',load_preset:'Preset laden...',test_all:'Alle testen',test:'Test',export_config:'Config exportieren',import_config:'Config importieren',copy:'Kopieren',copied:'Kopiert!',on:'An',off:'Aus',active:'Aktiv',error:'Fehler',reconnecting:'Verbinde...',stopped:'Gestoppt',conn:'Verb',success:'OK',fail:'Fehler',avg:'Avg',testing:'Teste...',test_ok:'OK',test_fail:'Fehlgeschlagen',import_ok:'Config importiert!',import_fail:'Import fehlgeschlagen',resolve:'Aufloesen',resolving:'Aufloesen...',confirm_add:'Bestaetigen',cancel:'Abbrechen',no_ips_found:'Keine IPs gefunden fuer',subdomains_found:'Gefundene Subdomains',strategy_timeline:'Strategie-Zeitachse',cdn_finder:'CDN Finder',cdn_help_desc:'Kopieren Sie das Script, oeffnen Sie die Zielseite, druecken Sie F12, fuegen Sie es in die Console ein und druecken Sie Enter.',cdn_step1:'Script kopieren',cdn_step2:'Zielseite + F12',cdn_step3:'In Console einfuegen + Enter',cdn_step4:'Domains unten hinzufuegen',add_cdn:'CDN hinzufuegen',cdn_added:'CDN-Domain hinzugefuegt!',cdn_select_site:'Seite waehlen...',cdn_domain_exists:'Domain existiert bereits',cdn_no_domain:'CDN-Domain eingeben',remove_domain:'Domain entfernt',site_domains:'Seiten-Domains',remove_site:'Seite entfernen',remove_all_sites:'Alle entfernen',confirm_remove_site:'Seite entfernen',confirm_remove_all_sites:'Alle Seiten entfernen? Dies kann nicht rueckgaengig gemacht werden.'}
};
let L=localStorage.getItem('cleannet_lang')||navigator.language.slice(0,2);
if(!I[L])L='en';
function setLang(l){L=l;localStorage.setItem('cleannet_lang',l);applyLang()}
function t(k){return I[L][k]||I.en[k]||k}
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
    const sC={'direct':'#3dd68c','host_split':'#6c8aec','fragment_light':'#f0a030','tls_record_frag':'#38c8d8','fragment_burst':'#ff9800','desync':'#a855f7','fragment_heavy':'#f05858','sni_shuffle':'#ec4899','auto':'#585e78'};
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
        else testHtml='<span class="test-fail" style="font-size:10px;">'+t('test_fail')+'</span>';
      }
      return '<div class="site-detail">'
        +'<div class="name">'
        +'<div style="width:8px;height:8px;border-radius:50%;background:'+bg+';cursor:pointer;flex-shrink:0;" onclick="ts(\''+s+'\')"></div>'
        +'<span style="cursor:pointer;color:#fff;" onclick="ts(\''+s+'\')">'+s+'</span>'
        +'<span style="font-size:9px;color:'+stCol+';font-weight:700;background:'+stCol+'15;padding:2px 8px;border-radius:10px;">['+strat+']</span>'
        +(si.strategy_time_ms?'<span style="font-size:9px;color:var(--text3)">'+si.strategy_time_ms+'ms</span>':'')
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
  if(d.proxy_bypass){renderBypass(d.proxy_bypass)}
  if(d.autostart!==undefined){document.getElementById('as').checked=d.autostart}
  if(d.ping>0){pH.push(d.ping);if(pH.length>mP)pH.shift();dC()}
  if(d.strategy_history){renderST(d.strategy_history)}
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
const _stC={'direct':'#3dd68c','host_split':'#6c8aec','fragment_light':'#f0a030','tls_record_frag':'#38c8d8','fragment_burst':'#ff9800','desync':'#a855f7','fragment_heavy':'#f05858','sni_shuffle':'#ec4899'};
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
function renderBypass(list){
  document.getElementById('bl').innerHTML=list.map(e=>{
    const se=esc(e).replace(/'/g,"\\'");
    return '<div style="display:inline-flex;align-items:center;background:var(--surface2);padding:4px 10px;border-radius:6px;gap:6px;border:1px solid var(--border);">'
      +'<span style="font-size:11px;font-family:var(--mono)">'+esc(e)+'</span>'
      +'<span style="cursor:pointer;color:var(--red);font-weight:bold;font-size:13px;opacity:.6;transition:opacity .2s;" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.6" onclick="removeB(\''+se+'\')">&times;</span>'
      +'</div>';
  }).join(' ');
}
async function addB(){const i=document.getElementById('nb');const v=i.value.trim();if(!v)return;i.value='';await fetch('/api/add-bypass',{method:'POST',body:JSON.stringify({entry:v})})}
async function removeB(e){await fetch('/api/remove-bypass',{method:'POST',body:JSON.stringify({entry:e})})}
async function clearBypass(){if(confirm(t('Are you sure you want to clear the entire bypass list?'))){await fetch('/api/clear-bypass',{method:'POST'})}}
async function loadPreset(){const sel=document.getElementById('preset');const v=sel.value;if(!v)return;sel.value='';await fetch('/api/load-preset',{method:'POST',body:JSON.stringify({preset:v})})}
async function toggleAS(){await fetch('/api/toggle-autostart',{method:'POST'})}
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
applyLang();
</script></body></html>"""

async def handle_http(reader, writer):
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
        'autostart': get_autostart(),
        'strategy_history': list(_strategy_history)[-50:],
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
            "3. DNS onbellegi temizlenecek (ipconfig /flushdns)\n"
            "4. IP adresi serbest birakilip yenilenecek (ipconfig /release & /renew)\n"
            "5. Winsock katalogu sifirlanacak (netsh winsock reset)\n"
            "6. TCP/IP yigini sifirlanacak (netsh int ip reset)\n\n"
            "Not: Ag sifirlamalari yonetici izni gerektirir.\n"
            "Islem sirasinda internet baglantiniz kisa sureligine kesilecektir.\n\n"
            "Devam etmek istiyor musunuz?"
        )
    elif lang == 'de':
        title = "CleanNet - Vollstaendiges Herunterfahren"
        msg = (
            "Folgende Aktionen werden ausgefuehrt:\n\n"
            "1. DPI-Bypass-Proxy wird gestoppt\n"
            "2. Windows-Proxy-Einstellungen werden zurueckgesetzt\n"
            "3. DNS-Cache wird geleert (ipconfig /flushdns)\n"
            "4. IP-Adresse wird freigegeben und erneuert (ipconfig /release & /renew)\n"
            "5. Winsock-Katalog wird zurueckgesetzt (netsh winsock reset)\n"
            "6. TCP/IP-Stack wird zurueckgesetzt (netsh int ip reset)\n\n"
            "Hinweis: Netzwerk-Resets erfordern Administratorrechte.\n"
            "Ihre Internetverbindung wird kurzzeitig unterbrochen.\n\n"
            "Moechten Sie fortfahren?"
        )
    else:
        title = "CleanNet - Full Shutdown"
        msg = (
            "The following actions will be performed:\n\n"
            "1. DPI Bypass proxy will be stopped\n"
            "2. Windows proxy settings will be cleared\n"
            "3. DNS cache will be flushed (ipconfig /flushdns)\n"
            "4. IP address will be released and renewed (ipconfig /release & /renew)\n"
            "5. Winsock catalog will be reset (netsh winsock reset)\n"
            "6. TCP/IP stack will be reset (netsh int ip reset)\n\n"
            "Note: Network resets require administrator privileges.\n"
            "Your internet connection will be briefly interrupted.\n\n"
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
    set_proxy(False)
    if _loop and _shutdown_event:
        _loop.call_soon_threadsafe(_shutdown_event.set)

    import tempfile
    bat_content = (
        '@echo off\r\n'
        'ipconfig /flushdns >nul 2>&1\r\n'
        'ipconfig /release >nul 2>&1\r\n'
        'ipconfig /renew >nul 2>&1\r\n'
        'netsh winsock reset >nul 2>&1\r\n'
        'netsh int ip reset >nul 2>&1\r\n'
        'echo [OK] Network reset completed.\r\n'
        'timeout /t 3 /nobreak >nul\r\n'
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
        pystray.MenuItem('CleanNet v1.0', None, enabled=False),
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
    logger.info("CleanNet v1.0 starting...")
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
