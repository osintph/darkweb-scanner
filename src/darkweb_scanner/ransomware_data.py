"""
Ransomware group intelligence database — SEA/PH focused.
Known groups, their onion leak sites, and victim targeting patterns.
"""

RANSOMWARE_GROUPS = [
    {
        "name": "LockBit",
        "slug": "lockbit",
        "status": "active",
        "origin": "Russia",
        "first_seen": "2019",
        "targeting_sea": True,
        "risk_level": "critical",
        "description": (
            "Most prolific ransomware group globally. Operates RaaS model. "
            "Known to target Philippine government agencies, banks, and regional telcos. "
            "LockBit 3.0 (Black) variant widely deployed across SEA."
        ),
        "ttps": ["RaaS", "double extortion", "StealBit exfiltration", "affiliate model"],
        "keywords": ["lockbit", "lockbit3", "lockbit 3.0", "lockbit black"],
        "onion_seeds": [
            "http://lockbitapt2d73krlbewgv27tquljgxr33xbwwsp6rkyieto7u4ncead.onion",
            "http://lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd.onion",
        ],
        "sea_victims": ["Philippine Health Insurance Corp", "Bank of the Philippine Islands (alleged)"],
    },
    {
        "name": "RansomHub",
        "slug": "ransomhub",
        "status": "active",
        "origin": "Unknown",
        "first_seen": "2024",
        "targeting_sea": True,
        "risk_level": "critical",
        "description": (
            "Emerged in 2024 as one of the fastest-growing RaaS operations. "
            "Absorbed former LockBit and ALPHV affiliates after law enforcement takedowns. "
            "Active targeting of healthcare and government in SEA."
        ),
        "ttps": ["RaaS", "double extortion", "zero-day exploitation", "speed-focused encryption"],
        "keywords": ["ransomhub", "ransom hub"],
        "onion_seeds": [
            "http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "Akira",
        "slug": "akira",
        "status": "active",
        "origin": "Unknown",
        "first_seen": "2023",
        "targeting_sea": True,
        "risk_level": "high",
        "description": (
            "Fast-growing group with retro-aesthetic leak site. Targets SMBs and mid-market. "
            "Uses Cisco VPN vulnerabilities as initial access. Active in Philippines and Indonesia."
        ),
        "ttps": ["RaaS", "double extortion", "Cisco VPN abuse", "AnyDesk/Splashtop abuse"],
        "keywords": ["akira ransomware", "akira gang"],
        "onion_seeds": [
            "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "DragonForce",
        "slug": "dragonforce",
        "status": "active",
        "origin": "Malaysia",
        "first_seen": "2023",
        "targeting_sea": True,
        "risk_level": "critical",
        "description": (
            "Malaysian-origin hacktivist-turned-ransomware group. Highly active in SEA with "
            "documented attacks on Philippine government infrastructure. Originally operated as "
            "hacktivists before shifting to financial extortion. Strong regional knowledge."
        ),
        "ttps": ["RaaS", "hacktivist origins", "defacement", "data leak", "DDoS combination"],
        "keywords": ["dragonforce", "dragon force"],
        "onion_seeds": [
            "http://dragonforce2epbji7cuocpfhuvajpqxjexrxvepxuqmx5rqrjwtnepid.onion",
        ],
        "sea_victims": ["Philippine Statistics Authority", "COMELEC (alleged)", "Various PH gov portals"],
    },
    {
        "name": "Cl0p",
        "slug": "cl0p",
        "status": "active",
        "origin": "Russia/Ukraine",
        "first_seen": "2019",
        "targeting_sea": True,
        "risk_level": "high",
        "description": (
            "Sophisticated group known for mass exploitation of file transfer software vulnerabilities "
            "(MOVEit, GoAnywhere, Accellion). Targets large enterprises. "
            "Several SEA financial institutions impacted via supply chain."
        ),
        "ttps": ["zero-day exploitation", "supply chain attacks", "MOVEit exploitation", "mass extortion"],
        "keywords": ["cl0p", "clop ransomware", "clop gang"],
        "onion_seeds": [
            "http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "BlackCat / ALPHV",
        "slug": "blackcat",
        "status": "disrupted",
        "origin": "Russia",
        "first_seen": "2021",
        "targeting_sea": False,
        "risk_level": "high",
        "description": (
            "Sophisticated Rust-based ransomware. Disrupted by FBI in Dec 2023 but affiliates "
            "migrated to RansomHub. First group to publicly leak victim data on clearnet. "
            "Some affiliates still active under rebranded operations."
        ),
        "ttps": ["RaaS", "Rust-based malware", "triple extortion", "clearnet leak sites"],
        "keywords": ["blackcat", "alphv", "black cat ransomware"],
        "onion_seeds": [],
        "sea_victims": [],
    },
    {
        "name": "Play",
        "slug": "play",
        "status": "active",
        "origin": "Unknown",
        "first_seen": "2022",
        "targeting_sea": True,
        "risk_level": "high",
        "description": (
            "Closed RaaS operation (no public affiliate program). Known for targeting MSPs "
            "to reach downstream clients. Active in manufacturing and logistics across SEA. "
            "Exploits ProxyNotShell and OWASSRF vulnerabilities."
        ),
        "ttps": ["closed RaaS", "MSP targeting", "Exchange exploitation", "intermittent encryption"],
        "keywords": ["play ransomware", "playcrypt"],
        "onion_seeds": [
            "http://mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "BlackBasta",
        "slug": "blackbasta",
        "status": "active",
        "origin": "Russia",
        "first_seen": "2022",
        "targeting_sea": False,
        "risk_level": "high",
        "description": (
            "Believed to be connected to Conti gang after its dissolution. Targets critical "
            "infrastructure. Primarily US/EU focused but growing global reach."
        ),
        "ttps": ["double extortion", "QakBot delivery", "Cobalt Strike", "PrintNightmare exploitation"],
        "keywords": ["black basta", "blackbasta"],
        "onion_seeds": [
            "http://stniiolomwsumtbaegbcmqzlqdtzcpbdub7puoopcut6zjczkmjutvad.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "Medusa",
        "slug": "medusa",
        "status": "active",
        "origin": "Unknown",
        "first_seen": "2021",
        "targeting_sea": True,
        "risk_level": "high",
        "description": (
            "Growing RaaS operation with public Telegram channel for victim announcements. "
            "Targets education, healthcare, and government. Active posting of SEA victims."
        ),
        "ttps": ["RaaS", "Telegram announcements", "living-off-the-land", "RDP exploitation"],
        "keywords": ["medusa ransomware", "medusa gang", "medusalocker"],
        "onion_seeds": [
            "http://medusaxko7jxtrojdkxo66j9cvp飛.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "8Base",
        "slug": "8base",
        "status": "active",
        "origin": "Unknown",
        "first_seen": "2022",
        "targeting_sea": True,
        "risk_level": "medium",
        "description": (
            "Rapidly emerging group that became prolific in 2023. Targets SMBs across "
            "multiple sectors. Uses Phobos ransomware variant. Active in Thai and "
            "Philippine markets."
        ),
        "ttps": ["Phobos variant", "SMB targeting", "double extortion", "email phishing"],
        "keywords": ["8base", "8 base ransomware"],
        "onion_seeds": [
            "http://basemmezqooekhde7dembyzn7fdklzjntamzo4tdbhqucpkmxxmrpuad.onion",
        ],
        "sea_victims": [],
    },
    {
        "name": "NoName057(16)",
        "slug": "noname",
        "status": "active",
        "origin": "Russia",
        "first_seen": "2022",
        "targeting_sea": False,
        "risk_level": "medium",
        "description": (
            "Pro-Russia hacktivist group conducting DDoS attacks. Not ransomware but "
            "significant threat to critical infrastructure. Targets NATO-aligned entities "
            "and any countries supporting Ukraine."
        ),
        "ttps": ["DDoS", "DDoSia tool", "hacktivism", "Telegram coordination"],
        "keywords": ["noname057", "no name 057"],
        "onion_seeds": [],
        "sea_victims": [],
    },
    {
        "name": "Hunters International",
        "slug": "hunters",
        "status": "active",
        "origin": "Unknown",
        "first_seen": "2023",
        "targeting_sea": True,
        "risk_level": "high",
        "description": (
            "Believed to have acquired Hive ransomware codebase after FBI disruption. "
            "Focuses on data theft and extortion over encryption. Growing SEA presence "
            "with healthcare and finance sector targeting."
        ),
        "ttps": ["data theft focused", "Hive codebase", "double extortion", "Rust-based"],
        "keywords": ["hunters international", "hunters ransomware"],
        "onion_seeds": [
            "http://hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion",
        ],
        "sea_victims": [],
    },
]

# Known ransomware .onion seeds for crawler (clean list, no invalid URLs)
RANSOMWARE_ONION_SEEDS = [
    url
    for group in RANSOMWARE_GROUPS
    for url in group.get("onion_seeds", [])
    if url and "飛" not in url  # filter malformed test URLs
]

# All keywords for auto-tagging in keyword scanner
RANSOMWARE_KEYWORDS = list({
    kw
    for group in RANSOMWARE_GROUPS
    for kw in group.get("keywords", [])
})

SEA_COUNTRIES = ["Philippines", "Thailand", "Indonesia", "Malaysia", "Vietnam", "Singapore",
                  "Myanmar", "Cambodia", "Laos", "Brunei", "Timor-Leste"]
