# Wazuh-Log-Analysis-Lab (WIP)

## Introduction

This project focuses on log analysis, threat detection, and security monitoring using Wazuh SIEM. The goal is to collect, analyze, and detect suspicious activities such as failed login attempts, privilege escalation, and PowerShell abuse in a Windows environment. By simulating real-world attack scenarios, this lab demonstrates how a Security Operations Center (SOC) Analyst can investigate Windows Event Logs and respond to security incidents.

Key Skills:
- Log Analysis & SIEM (Wazuh, Graylog, Windows Event Viewer, Sysmon)
- Threat Detection & Incident Response (MITRE ATT&CK, PowerShell Logging, Windows Defender)
- Network Traffic Analysis (Wireshark, Suricata, Zeek, PCAP Analysis)
- Intrusion Detection & Prevention (Wazuh IDS, Security Onion, Attack Simulation with Metasploit)
- Endpoint Security & Monitoring (Windows Logs, PowerShell, LimaCharlie)
- Virtualization & System Administration (VirtualBox, Ubuntu Server, Bash, Windows Security)

#

## Setup
To set up for the lab, we will download [VirtualBox 7.1.6](https://www.virtualbox.org/wiki/Downloads) and set up with the latest [Ubuntu Server (ver. 24.04.1)](https://ubuntu.com/download/server). To ensure that our Ubuntu-SIEM VM has its own ip address to allow for SSH, we change the network settings from NAT to Bridged Adapter. We also check and update current software packages using the command, ``sudo apt update && sudo apt upgrade -y``.
![1](https://github.com/user-attachments/assets/2a2eadcd-9b7b-4dc6-bc1f-2581f4d7e6e9)
![2](https://github.com/user-attachments/assets/a0be7459-929f-4ffd-ae27-65f50702ffb4)

#

### SSH Setup
The next step involves installing SSH server with command, ``sudo apt install -y openssh-server`` and enabling it using the commands ``sudo systemctl enable ssh`` and ``sudo systemctl start ssh``. Due to the previous step taken in network settings, we can find the ip address using ``ip a``. Now from your host machine, you can SSH onto your Ubuntu machine using ``ssh (name)@ipaddress``.
![SSH](https://github.com/user-attachments/assets/66a91707-89bf-4c32-a7c3-316e3e09a8aa)

### Wazuh Installation & Setup
We run the command, ``wget https://packages.wazuh.com/4.11/wazuh-install.sh`` and ``wget https://packages.wazuh.com/4.11/config.yml`` to install Wazuh for SIEM/XDR. Inside config.yml change the names and add the VM's ip address and then run the command, ``sudo bash wazuh-install.sh --generate-config-files`` and ``sudo bash wazuh-install.sh --wazuh-server wazuh-manager -i``
![config](https://github.com/user-attachments/assets/b097bf82-3949-4949-9086-4928e1d8131c)


### mySQL Installation
After, we run the command ``sudo apt install -y mysql-server`` and ``sudo mysql_secure_installation`` to install mySQL. During the installation process we answer 2 for strong password, and answer y to remove anonymous users, to disallow root login remotely, remove test data base and access to it, and to reload privilege tables now.

### mySQL for Wazuh Logs
Now mySQL can be accessed each time using the command ``sudo mysql -u root -p``. The commands ``CREATE DATABASE wazuh_logs;`` and ``USE wazuh_logs;`` are next used to create and work within wazuh_logs databbase.
![3](https://github.com/user-attachments/assets/06a189e2-3349-40fd-9ca3-f6af588565f6)


And now we create a table for security events for the database that came across Wazuh:
```
CREATE TABLE security_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_id INT,
    event_description VARCHAR(255),
    source_ip VARCHAR(45),
    username VARCHAR(100)
);
```
This is a visual example of how the table created will be shown:
|  id  |       timestamp       |  event_id  |    event_description    |    source_ip   |   username  |
|------|:---------------------:|:----------:|:-----------------------:|:--------------:|:-----------:|
|   1  |  2025-02-14 10:00:00  |    4625    |   Failed login attempt  |  192.168.1.01  |    admin    |
|   2  |  2025-02-14 10:02:30  |    4624    |     Successful login    |  192.168.1.01  |    admin    |
|   3  |  2025-02-14 10:40:45  |    4625    |   Failed login attempt  |  192.168.1.02  |    user1    |

The next step is to configure Wazuh's file for logs to send to mySQL, ``sudo nano /var/ossec/etc/ossec.conf``.

### Challenges & Solutions
**Challenge 1:** VM does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores when installing Wazuh.

**Solution 1:** Use the command included with ``-i`` to ignore requirements, ``sudo bash wazuh-install.sh --wazuh-server wazuh-manager -i``
