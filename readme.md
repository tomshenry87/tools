these programs are utilities to query network routers and projectors to check firmware version for securtity patching.


Mikrotik Firmware Checker

# Just run it — reads routers.csv, writes results.json
python3 mikrotik_checker.py

# With debug logging
python3 mikrotik_checker.py --verbose

# With raw SSH output saved in results.json
python3 mikrotik_checker.py --include-raw

# Both
python3 mikrotik_checker.py --verbose --include-raw

your_folder/
├── mikrotik_checker.py    ← the script
├── routers.csv            ← your input (you create this)
└── results.json           ← auto-generated when you run the script

host,username,password,port
10.0.0.1,admin,MyP@ss1,22
10.0.0.2,admin,MyP@ss2,22
192.168.88.1,admin,,22


Pjlink Projector Firmware Version

# Query firmware version from a projector
python pjlink_firmware.py 192.168.1.100

# With authentication
python pjlink_firmware.py 192.168.1.100 --password mypassword

# Custom port and output file
python pjlink_firmware.py 192.168.1.100 -p 4352 -o my_projector.json

# Get ALL available information
python pjlink_firmware.py 192.168.1.100 --all

# With custom timeout
python pjlink_firmware.py 192.168.1.100 -t 15

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


