# Iron Dome

> Better safe than sorry.

OS monitoring system for detecting anomalous activities, such as disk read abuse, intensive use of cryptographic activity and significant change in the entropy of files - common signs of a potential ransomware attack.

*developed for 42 Cybersecurity Piscine by: mcutura*

## Software Requirements Specification

- support Linux
- run only as root and background daemon
- never exceed 100 MB of memory in use
- detect:
  - disk read abuse
  - intensive use of cryptographic activity
  - changes in the entropy of files
- report alerts in `/var/log/irondome/irondome.log`
- [BONUS] incremental backups at configurable intervals of monitored files and directories
