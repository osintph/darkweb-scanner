"""
Threat actor profiles — SEA/PH focused intelligence database.
"""

THREAT_ACTORS = [
    {
        "name": "APT40",
        "slug": "apt40",
        "aliases": ["BRONZE MOHAWK", "GADOLINIUM", "Kryptonite Panda", "Leviathan"],
        "origin": "China",
        "type": "nation-state",
        "status": "active",
        "risk_level": "critical",
        "first_seen": "2013",
        "targeting_sea": True,
        "sectors": ["government", "defense", "maritime", "research"],
        "countries_targeted": ["Philippines", "Malaysia", "Cambodia", "Indonesia"],
        "description": (
            "Chinese state-sponsored APT group attributed to China's Ministry of State Security "
            "Hainan bureau. Highly active in South China Sea geopolitical conflicts. Targets "
            "Philippine government and maritime agencies related to SCS disputes. Known for "
            "web shell deployment and living-off-the-land techniques."
        ),
        "ttps": [
            "spear phishing", "web shell deployment", "credential harvesting",
            "living-off-the-land", "VPN exploitation", "supply chain compromise"
        ],
        "known_malware": ["BADFLICK", "PHOTO", "HOMEFRY", "LUNCHMONEY"],
        "keywords": ["apt40", "leviathan", "kryptonite panda"],
    },
    {
        "name": "APT41",
        "slug": "apt41",
        "aliases": ["Double Dragon", "BARIUM", "Winnti Group", "WICKED PANDA"],
        "origin": "China",
        "type": "nation-state",
        "status": "active",
        "risk_level": "critical",
        "first_seen": "2012",
        "targeting_sea": True,
        "sectors": ["healthcare", "telecoms", "technology", "gaming", "finance"],
        "countries_targeted": ["Philippines", "Thailand", "Malaysia", "Singapore", "Indonesia"],
        "description": (
            "Unique dual-purpose APT — conducts both state-sponsored espionage and financially "
            "motivated cybercrime. Active across SEA in telecoms and financial sector. "
            "Known for supply chain attacks and exploitation of public-facing applications."
        ),
        "ttps": [
            "supply chain attacks", "living-off-the-land", "rootkits",
            "bootkit deployment", "SQL injection", "spear phishing"
        ],
        "known_malware": ["CROSSWALK", "MESSAGETAP", "POISONPLUG", "DUSTPAN"],
        "keywords": ["apt41", "winnti", "barium", "double dragon", "wicked panda"],
    },
    {
        "name": "Mustang Panda",
        "slug": "mustang-panda",
        "aliases": ["TA416", "BRONZE PRESIDENT", "HoneyMyte", "Stately Taurus"],
        "origin": "China",
        "type": "nation-state",
        "status": "active",
        "risk_level": "critical",
        "first_seen": "2014",
        "targeting_sea": True,
        "sectors": ["government", "NGO", "military", "telecoms"],
        "countries_targeted": ["Philippines", "Myanmar", "Vietnam", "Malaysia", "Taiwan"],
        "description": (
            "China-aligned APT with intense focus on SEA governments and military. "
            "Heavily active in Philippines, particularly targeting government agencies "
            "involved in South China Sea policy. Uses PlugX malware extensively and "
            "USB-based propagation. Documented attacks on PH National Security Council."
        ),
        "ttps": [
            "PlugX malware", "USB propagation", "spear phishing", "DLL side-loading",
            "living-off-the-land", "diplomatic lure documents"
        ],
        "known_malware": ["PlugX", "TONEINS", "TONESHELL", "PUBLOAD"],
        "keywords": ["mustang panda", "ta416", "bronze president", "plugx", "stately taurus"],
    },
    {
        "name": "Lazarus Group",
        "slug": "lazarus",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "APT38"],
        "origin": "North Korea",
        "type": "nation-state",
        "status": "active",
        "risk_level": "critical",
        "first_seen": "2009",
        "targeting_sea": True,
        "sectors": ["finance", "cryptocurrency", "defense", "aerospace"],
        "countries_targeted": ["Philippines", "Thailand", "Singapore", "Indonesia", "Vietnam"],
        "description": (
            "North Korean state-sponsored group primarily targeting financial institutions "
            "for currency generation. SWIFT banking attacks in SEA attributed to Lazarus. "
            "Bangladesh Bank heist funds were routed through Philippine casinos. "
            "Heavy cryptocurrency targeting across SEA exchanges."
        ),
        "ttps": [
            "SWIFT targeting", "cryptocurrency theft", "supply chain attacks",
            "watering hole", "macOS malware", "job-themed spear phishing"
        ],
        "known_malware": ["BLINDINGCAN", "COPPERHEDGE", "TYPEFRAME", "AppleJeus"],
        "keywords": ["lazarus group", "hidden cobra", "apt38", "zinc", "guardians of peace"],
    },
    {
        "name": "APT32 / OceanLotus",
        "slug": "apt32",
        "aliases": ["OceanLotus", "SeaLotus", "BISMUTH", "Canvas Cyclone"],
        "origin": "Vietnam",
        "type": "nation-state",
        "status": "active",
        "risk_level": "high",
        "first_seen": "2014",
        "targeting_sea": True,
        "sectors": ["government", "corporate espionage", "media", "NGO"],
        "countries_targeted": ["Philippines", "Cambodia", "Laos", "Germany", "China"],
        "description": (
            "Vietnam-attributed APT group conducting regional espionage. Targets foreign "
            "governments and corporations for economic and political intelligence. "
            "Known for sophisticated macOS malware and fake news/media lures targeting "
            "SEA journalists and activists."
        ),
        "ttps": [
            "spear phishing", "macOS malware", "custom backdoors",
            "strategic web compromise", "signed malware", "Cobalt Strike"
        ],
        "known_malware": ["SOUNDBITE", "PHOREAL", "WINDSHIELD", "KOMPROGO"],
        "keywords": ["apt32", "oceanlotus", "sealotus", "bismuth"],
    },
    {
        "name": "DragonForce",
        "slug": "dragonforce-apt",
        "aliases": ["DragonForce Malaysia"],
        "origin": "Malaysia",
        "type": "hacktivist",
        "status": "active",
        "risk_level": "high",
        "first_seen": "2021",
        "targeting_sea": True,
        "sectors": ["government", "critical infrastructure", "finance"],
        "countries_targeted": ["Philippines", "Israel", "India", "Bangladesh"],
        "description": (
            "Malaysian hacktivist collective that evolved into a ransomware operation. "
            "Originally targeted Israeli entities in solidarity campaigns, then pivoted to "
            "Philippine government infrastructure. Defaced hundreds of PH government sites. "
            "Now operates a full RaaS platform alongside hacktivist operations."
        ),
        "ttps": [
            "web defacement", "DDoS", "SQL injection", "ransomware deployment",
            "data exfiltration", "Telegram coordination"
        ],
        "known_malware": ["DragonForce ransomware (LockBit variant)"],
        "keywords": ["dragonforce malaysia", "dragonforce hacktivists"],
    },
    {
        "name": "TA505",
        "slug": "ta505",
        "aliases": ["Hive0065", "GRACEFUL SPIDER"],
        "origin": "Russia",
        "type": "cybercriminal",
        "status": "active",
        "risk_level": "high",
        "first_seen": "2014",
        "targeting_sea": True,
        "sectors": ["finance", "retail", "healthcare"],
        "countries_targeted": ["Philippines", "Thailand", "Singapore"],
        "description": (
            "Financially motivated threat actor known for large-scale malspam campaigns. "
            "Responsible for Dridex, Locky, and FlawedAmmyy deployments. "
            "Targets Philippine financial institutions with credential harvesting campaigns."
        ),
        "ttps": [
            "malspam campaigns", "macro documents", "Dridex delivery",
            "Get2 downloader", "FlawedAmmyy RAT", "SDBbot"
        ],
        "known_malware": ["Dridex", "FlawedAmmyy", "SDBbot", "Get2"],
        "keywords": ["ta505", "graceful spider"],
    },
    {
        "name": "Kimsuky",
        "slug": "kimsuky",
        "aliases": ["Velvet Chollima", "Black Banshee", "Thallium", "APT43"],
        "origin": "North Korea",
        "type": "nation-state",
        "status": "active",
        "risk_level": "high",
        "first_seen": "2012",
        "targeting_sea": True,
        "sectors": ["government", "think tanks", "defense", "nuclear research"],
        "countries_targeted": ["South Korea", "Japan", "Singapore", "Philippines"],
        "description": (
            "North Korean intelligence collection group focused on geopolitical intelligence. "
            "Increasingly active in SEA, targeting think tanks and government bodies with "
            "policy relevance to North Korea sanctions and nuclear programs."
        ),
        "ttps": [
            "spear phishing", "social engineering", "Chrome extension malware",
            "browser credential theft", "BabyShark malware"
        ],
        "known_malware": ["BabyShark", "AppleSeed", "SHARPEXT", "RandomQuery"],
        "keywords": ["kimsuky", "velvet chollima", "thallium", "apt43"],
    },
    {
        "name": "Philippine Cybercrime Groups",
        "slug": "ph-cybercrime",
        "aliases": ["Various local eCrime syndicates"],
        "origin": "Philippines",
        "type": "cybercriminal",
        "status": "active",
        "risk_level": "medium",
        "first_seen": "2015",
        "targeting_sea": True,
        "sectors": ["financial", "BPO", "e-commerce", "romance scams"],
        "countries_targeted": ["Philippines", "USA", "Australia", "UK"],
        "description": (
            "Loosely organized domestic cybercrime groups primarily focused on financial fraud, "
            "BEC (Business Email Compromise), and romance scams. Some groups operate from "
            "Philippine-based POGO (offshore gaming) compounds. Active on Telegram and "
            "underground forums offering hacking services."
        ),
        "ttps": [
            "BEC", "romance scam", "SIM swapping", "credential stuffing",
            "phishing kits", "money muling"
        ],
        "known_malware": ["Commercial RATs", "phishing kits"],
        "keywords": ["pinoy hackers", "philippine hackers", "manila hackers"],
    },
    {
        "name": "ShinyHunters",
        "slug": "shinyhunters",
        "aliases": ["Shiny Hunters"],
        "origin": "Unknown (suspected French)",
        "type": "cybercriminal",
        "status": "active",
        "risk_level": "high",
        "first_seen": "2020",
        "targeting_sea": True,
        "sectors": ["technology", "e-commerce", "finance"],
        "countries_targeted": ["Global", "Philippines", "Indonesia", "Thailand"],
        "description": (
            "Prolific data breach group that steals and sells large databases. "
            "Responsible for breaches of major SEA platforms including Tokopedia, "
            "Bukalapak, and regional e-commerce. Data frequently surfaces on BreachForums."
        ),
        "ttps": [
            "cloud misconfiguration exploitation", "credential stuffing",
            "database exfiltration", "BreachForums sales"
        ],
        "known_malware": [],
        "keywords": ["shinyhunters", "shiny hunters", "breachforums shinyhunters"],
    },
    {
        "name": "Volt Typhoon",
        "slug": "volt-typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda", "DEV-0391"],
        "origin": "China",
        "type": "nation-state",
        "status": "active",
        "risk_level": "critical",
        "first_seen": "2021",
        "targeting_sea": True,
        "sectors": ["critical infrastructure", "maritime", "communications", "utilities"],
        "countries_targeted": ["Philippines", "Guam", "USA", "Pacific region"],
        "description": (
            "Chinese state-sponsored APT focused on pre-positioning for potential conflict. "
            "Targets critical infrastructure using living-off-the-land techniques to avoid "
            "detection. Active in Philippines and Pacific region with focus on maritime and "
            "communications infrastructure — significant concern for SCS conflict scenarios."
        ),
        "ttps": [
            "living-off-the-land (LOTL)", "SOHO router compromise",
            "Fortinet exploitation", "proxying through compromised infrastructure",
            "minimal malware footprint"
        ],
        "known_malware": ["KV-botnet", "LOTL tools only"],
        "keywords": ["volt typhoon", "vanguard panda", "bronze silhouette"],
    },
    {
        "name": "Earth Lusca",
        "slug": "earth-lusca",
        "aliases": ["TAG-22", "CHARCOAL TYPHOON"],
        "origin": "China",
        "type": "nation-state",
        "status": "active",
        "risk_level": "high",
        "first_seen": "2019",
        "targeting_sea": True,
        "sectors": ["government", "education", "media", "telecoms"],
        "countries_targeted": ["Philippines", "Thailand", "Vietnam", "Hong Kong", "Taiwan"],
        "description": (
            "Chinese APT targeting government and media entities in SEA. Known for "
            "watering hole attacks on news sites and government portals frequented by "
            "targets. Uses open-source tools alongside custom malware."
        ),
        "ttps": [
            "watering hole attacks", "spear phishing", "ProxyShell exploitation",
            "Cobalt Strike", "ShadowPad"
        ],
        "known_malware": ["ShadowPad", "Winnti", "Cobalt Strike"],
        "keywords": ["earth lusca", "charcoal typhoon", "tag-22"],
    },
]

# All keywords for cross-referencing with hit database
THREAT_ACTOR_KEYWORDS = list({
    kw
    for actor in THREAT_ACTORS
    for kw in actor.get("keywords", [])
})
