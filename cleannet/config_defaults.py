"""Default configuration and proxy bypass presets."""

from __future__ import annotations

from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "sites": {
        "discord": {
            "enabled": True,
            "domains": [
                "discord.com",
                "discordapp.com",
                "discord.gg",
                "discord.media",
                "discordapp.net",
                "discord.dev",
                "discord.new",
                "discord.gift",
                "discordstatus.com",
                "dis.gd",
                "cdn.discordapp.com",
                "media.discordapp.net",
                "images-ext-1.discordapp.net",
                "images-ext-2.discordapp.net",
                "gateway.discord.gg",
                "status.discord.com",
                "updates.discord.com",
                "dl.discordapp.net",
                "latency.discord.media",
                "remote-auth-gateway.discord.gg",
            ],
            "dns_resolve": [
                "discord.com",
                "gateway.discord.gg",
                "cdn.discordapp.com",
                "media.discordapp.net",
                "updates.discord.com",
                "status.discord.com",
            ],
            "ips": [
                "162.159.128.233",
                "162.159.129.233",
                "162.159.130.233",
                "162.159.136.232",
                "162.159.137.232",
            ],
        }
    },
    "proxy_port": 8080,
    "dashboard_port": 8888,
    "proxy_bypass": [],
    "privacy": {
        "hide_dns": True,
        "hide_sni": True,
    },
    "performance": {
        "low_latency_mode": True,
        "background_training": False,
        "health_check_interval": 120,
        "ip_update_interval": 1800,
        "ping_target_host": "1.1.1.1",
    },
}


ALWAYS_BYPASS = [
    "localhost", "127.*", "10.*", "192.168.*", "<local>",
    "*.microsoft.com", "*.microsoftonline.com", "*.windows.com",
    "*.windows.net", "*.live.com", "*.office.com", "*.office.net",
    "*.msftconnecttest.com", "*.msauth.net", "*.msftauth.net",
    "*.azureedge.net", "*.msecnd.net", "*.s-microsoft.com",
    "*.azure.com", "*.msedge.net", "*.bing.com", "*.bing.net",
    "*.github.com", "*.github.io", "*.githubusercontent.com", "*.githubassets.com",
    "*.openai.com", "*.chatgpt.com", "*.oaistatic.com", "*.oaiusercontent.com",
    "*.openaiusercontent.com", "*.statsigapi.net",
    "*.visualstudio.com", "*.vscode.dev", "*.vscode-cdn.net",
    "*.vsassets.io", "*.gallerycdn.vsassets.io",
    "*.google.com", "*.googleapis.com", "*.gstatic.com", "*.google-analytics.com",
    "*.apple.com",
    "*.minecraft.net", "*.mojang.com", "*.minecraftservices.com",
    "*.xbox.com", "*.xboxlive.com", "*.xboxservices.com", "*.playfabapi.com",
    "*.akamaized.net", "*.akamai.net", "*.akamaihd.net",
    "*.cloudfront.net", "*.cloudflare.com", "*.fastly.net", "*.amazonaws.com",
]


BYPASS_PRESET_DEFINITIONS = {
    "gaming": [
        "*.riotgames.com", "*.leagueoflegends.com", "*.pvp.net",
        "*.riotcdn.net", "*.lolesports.com", "*.playvalorant.com",
        "*.epicgames.com", "*.epicgames.dev", "*.unrealengine.com",
        "*.fortnite.com", "*.easyanticheat.net", "*.ol.epicgames.com",
        "*.steampowered.com", "*.steamcommunity.com", "*.steamcontent.com",
        "*.steamstatic.com", "*.valvesoftware.com", "*.steamgames.com",
        "*.steamusercontent.com", "*.steamchina.com",
        "*.ea.com", "*.origin.com", "*.tnt-ea.com",
        "*.dice.se", "*.bioware.com", "*.respawn.com",
        "*.ubisoft.com", "*.ubi.com", "*.uplay.com",
        "*.ubisoftconnect.com", "*.ubisoft-connect.com",
        "*.ubisoft.org", "*.ubisoft-dns.com",
        "*.cdn-ubisoft.com", "*.static-dm.ubisoft.com",
        "*.upc.ubisoft.com",
        "*.blizzard.com", "*.battle.net", "*.blizzard.cn",
        "*.blz-contentstack.com",
        "*.xbox.com", "*.xboxlive.com", "*.xboxservices.com",
        "*.playfabapi.com", "*.playfab.com", "*.halowaypoint.com",
        "*.gamepass.com", "*.msgamestudios.com",
        "*.playstation.com", "*.playstation.net",
        "*.playstationnetwork.com", "*.sonyentertainmentnetwork.com",
        "*.sie.com", "*.scea.com",
        "*.nintendo.com", "*.nintendo.net", "*.nintendo.co.jp",
        "*.nintendoswitch.com",
        "*.gog.com", "*.cdprojektred.com", "*.cdprojekt.com",
        "*.rockstargames.com", "*.rsg.sc", "*.socialclub.rockstargames.com",
        "*.bethesda.net", "*.bethsoft.com", "*.zenimax.com",
        "*.square-enix.com", "*.square-enix-games.com",
        "*.finalfantasyxiv.com", "*.playonline.com",
        "*.bandainamcoent.com", "*.bandainamco.net",
        "*.bandainamcoent.eu", "*.bandainamcogames.com",
        "*.sega.com", "*.atlus.com",
        "*.wargaming.net", "*.worldoftanks.com", "*.worldoftanks.eu",
        "*.worldofwarships.com", "*.worldofwarplanes.com", "*.wg.gg",
        "*.gaijin.net", "*.warthunder.com", "*.enlisted.net",
        "*.garena.com", "*.garena.sg",
        "*.nexon.com", "*.nexon.net",
        "*.ncsoft.com", "*.plaync.com", "*.arenanet.com",
        "*.hoyoverse.com", "*.mihoyo.com", "*.hoyolab.com",
        "*.genshinimpact.com", "*.honkaiimpact3.com",
        "*.kurogames.com",
        "*.krafton.com", "*.pubg.com", "*.pubgesports.com",
        "*.supercell.com", "*.supercell.net",
        "*.brawlstars.com", "*.clashofclans.com", "*.clashroyale.com",
        "*.roblox.com", "*.rbxcdn.com",
        "*.minecraft.net", "*.mojang.com", "*.minecraftservices.com",
        "*.battleye.com", "*.xigncode.com", "*.nprotect.com",
        "*.vanguard.gg",
        "*.unity3d.com", "*.photonengine.com", "*.faceit.com",
        "*.mod.io", "*.nexusmods.com", "*.curseforge.com",
    ],
    "cdn": [
        "*.akamaihd.net", "*.cloudflare.com", "*.fastly.net", "*.cloudfront.net",
        "*.cdn77.org", "*.b-cdn.net", "*.bunnycdn.com", "*.jsdelivr.net",
        "*.unpkg.com", "*.cdnjs.com", "*.stackpathcdn.com", "*.edgekey.net",
        "*.edgesuite.net", "*.hwcdn.net", "*.imgix.net", "*.cloudinary.com",
        "*.cloudflarestream.com", "*.r2.dev",
    ],
    "streaming": [
        "*.netflix.com", "*.nflxvideo.net", "*.nflximg.net", "*.nflxso.net",
        "*.spotify.com", "*.scdn.co", "*.twitch.tv", "*.ttvnw.net",
        "*.youtube.com", "*.youtu.be", "*.youtube-nocookie.com", "*.googlevideo.com",
        "*.ytimg.com", "*.youtubei.googleapis.com", "*.disneyplus.com",
        "*.disney-plus.net", "*.dssott.com", "*.primevideo.com", "*.amazonvideo.com",
        "*.media-amazon.com", "*.hulu.com", "*.max.com", "*.hbomax.com",
        "*.hbo.com", "*.paramountplus.com", "*.peacocktv.com", "*.dailymotion.com",
        "*.vimeo.com", "*.soundcloud.com", "*.deezer.com", "*.tidal.com",
    ],
    "social": [
        "*.instagram.com", "*.cdninstagram.com", "*.facebook.com", "*.fbcdn.net",
        "*.messenger.com", "*.threads.net", "*.x.com", "*.twitter.com", "*.twimg.com",
        "*.tiktok.com", "*.tiktokcdn.com", "*.tiktokv.com", "*.reddit.com",
        "*.redd.it", "*.telegram.org", "*.t.me", "*.whatsapp.com", "*.snapchat.com",
        "*.pinterest.com", "*.pinimg.com",
    ],
    "work": [
        "*.slack.com", "*.slack-edge.com", "*.zoom.us", "*.notion.so",
        "*.notion-static.com", "*.dropbox.com", "*.dropboxusercontent.com",
        "*.figma.com", "*.figmausercontent.com", "*.linear.app", "*.atlassian.com",
        "*.trello.com", "*.loom.com", "*.calendly.com",
    ],
}


BYPASS_PRESET_META = {
    "gaming": {
        "label": "Gaming",
        "description": "Launchers, stores, multiplayer services, anti-cheat, and common game CDNs.",
    },
    "cdn": {
        "label": "CDN",
        "description": "Common generic CDN and asset hosts that usually should stay untouched.",
    },
    "streaming": {
        "label": "Streaming",
        "description": "Video and music platforms with high-volume media delivery domains.",
    },
    "social": {
        "label": "Social",
        "description": "Social networks, messaging, image/video CDNs, and short-form media hosts.",
    },
    "work": {
        "label": "Work",
        "description": "Collaboration, meetings, design, storage, and productivity services.",
    },
}


BYPASS_PRESETS = {
    name: list(entries)
    for name, entries in BYPASS_PRESET_DEFINITIONS.items()
}


def get_bypass_preset_options(always_bypass: list[str] | None = None) -> list[dict[str, Any]]:
    always = set(always_bypass or [])
    options: list[dict[str, Any]] = []
    for name, entries in BYPASS_PRESETS.items():
        meta = BYPASS_PRESET_META.get(name, {})
        built_in = [entry for entry in entries if entry in always]
        addable = [entry for entry in entries if entry not in always]
        options.append({
            "name": name,
            "label": meta.get("label", name.title()),
            "description": meta.get("description", ""),
            "entry_count": len(entries),
            "addable_count": len(addable),
            "built_in_count": len(built_in),
        })
    return options
