these programs are utilities to query network routers and projectors to check firmware version for securtity patching.


Mikrotik Firmware Checker

# Default — reads routers.csv, writes results.json
python3 mikrotik_checker.py

# Override input file only
python3 mikrotik_checker.py --csv my_other_routers.csv

# Override output file only
python3 mikrotik_checker.py --output my_report.json

# Override both
python3 mikrotik_checker.py --csv site_a.csv --output site_a_results.json

# Debug mode
python3 mikrotik_checker.py --verbose

# Include raw SSH output in JSON
python3 mikrotik_checker.py --include-raw

# Everything at once
python3 mikrotik_checker.py --csv site_b.csv --output site_b.json --verbose --include-raw

your_folder/
├── mikrotik_checker.py    ← the script
├── routers.csv            ← your input (you create this)
└── results.json           ← auto-generated when you run the script

host,username,password,port
10.0.0.1,admin,MyP@ss1,22
10.0.0.2,admin,MyP@ss2,22
192.168.88.1,admin,,22

# Run with all defaults (reads projectors.csv, writes results.json)
python pjlink_query.py

# Specify different input
python pjlink_query.py -i my_devices.csv

# Specify different output
python pjlink_query.py -o report.json

# Both
python pjlink_query.py -i my_devices.csv -o report.json

# All commands + debug
python pjlink_query.py --all --debug

# Diagnostic mode
python pjlink_query.py --diagnostic --debug

{
    "host": "192.168.1.100",
    "port": 4352,
    "query_timestamp": "2024-01-15T10:30:00+00:00",
    "pjlink_class": "2",
    "manufacturer": "Epson",
    "product_name": "EB-L260F",
    "software_version": "1.05",
    "other_info": "FW:1.05 Build:2023.10.01",
    "firmware_version": "1.05"
}

host,port,password
192.168.1.100,4352,
192.168.1.101,4352,mypassword
192.168.1.102,,secretpass
10.0.0.50,,
projector-room1.local,4352,admin123


