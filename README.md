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
To set up for the lab, we will download [VirtualBox](https://www.virtualbox.org/wiki/Downloads) and set up with the latest [Ubuntu Server (ver. 24.04.1)](https://ubuntu.com/download/server). To ensure that our Ubuntu-SIEM VM has its own ip address to allow for SSH, we change the network settings from NAT to Bridged Adapter. We also check and update current software packages using the command, ``sudo apt update && sudo apt upgrade -y``.
![1](https://github.com/user-attachments/assets/2a2eadcd-9b7b-4dc6-bc1f-2581f4d7e6e9)
![2](https://github.com/user-attachments/assets/a0be7459-929f-4ffd-ae27-65f50702ffb4)

#

### SSH Setup
The next step involves installing SSH server with command, ``sudo apt install -y openssh-server`` and enabling it using the commands ``sudo systemctl enable ssh`` and ``sudo systemctl start ssh``. Due to the previous step taken in network settings, we can find the ip address using ``ip a``.\
![SSH](https://github.com/user-attachments/assets/66a91707-89bf-4c32-a7c3-316e3e09a8aa)

### Wazuh & mySQL Setup
We run the command, ``curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh`` to install Wazuh for SIEM/XDR.  After, we run the command ``sudo apt install -y mysql-server`` and ``sudo mysql_secure_installation`` to install mySQL. During the installation process we answer 2 for strong password, and answer y to remove anonymous users, to disallow root login remotely, remove test data base and access to it, and to reload privilege tables now.
