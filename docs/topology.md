Your Windows 11 Host

│

├── Management Network (Host-Only: 192.168.56.0/24)

│   ├── Security Onion (management interface)

│   └── REMnux (management interface)

│

└── Isolated Analysis Network (Internal: 10.0.0.0/24)

&#x20;   ├── Security Onion (monitoring interface — promiscuous)

&#x20;   ├── REMnux (INetSim provider — DNS/HTTP/SMTP)

&#x20;   └── FlareVM / Detonation VM (the sandbox — ONLY network it touches)

