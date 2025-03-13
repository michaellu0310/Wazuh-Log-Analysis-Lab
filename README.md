# Wazuh-Log-Analysis-Lab (WIP)

## Introduction

This project focuses on log analysis, threat detection, and security monitoring using Wazuh SIEM. The goal is to collect, analyze, and detect suspicious activities such as failed login attempts, privilege escalation, and PowerShell abuse in a Windows environment. By simulating real-world attack scenarios, this lab demonstrates how a Security Operations Center (SOC) Analyst can investigate Windows Event Logs and respond to security incidents.

**Key Skills:**
- Log Analysis & SIEM (Wazuh, MySQL - Querying & Log Storage, Wazuh Event Forwarding)
- Intrusion Detection & Prevention (Wazuh IDS - Log-based Threat Detection)
- Threat Detection & Incident Response (MITRE ATT&CK, Security Event Logging, Custom Alerting in Wazuh)
- Database Management & Automation (MySQL - Querying, Log Storage & Analysis, Automation with Bash Scripts)
- System Administration & Security (Ubuntu Server, Bash Scripting, Service Management, Configuration Files)

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
We run the command, ``wget https://packages.wazuh.com/4.11/wazuh-install.sh`` and ``wget https://packages.wazuh.com/4.11/config.yml`` to install Wazuh for SIEM/XDR. Inside config.yml change the names and add the VM's ip address and then run the command, ``sudo bash wazuh-install.sh --generate-config-files`` and ``sudo bash wazuh-install.sh --wazuh-server wazuh-manager -i``.
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
|   1  |  2025-02-14 10:00:00  |    4625    |   Failed login attempt  |  192.168.1.1   |    admin    |
|   2  |  2025-02-14 10:02:30  |    4624    |     Successful login    |  192.168.1.1   |    admin    |
|   3  |  2025-02-14 10:40:45  |    4625    |   Failed login attempt  |  192.168.1.2   |    user1    |

The next step is to add an executable using ``sudo nano /var/ossec/bin/send_to_mysql.sh``. Add the following lines:
```
#!/bin/bash

mysql -u root -padmin -D wazuh_logs -e "INSERT INTO security_events (event_id, event_description, source_ip, username) VALUES ('$1', '$2', '$3', '$4');"
```
and run ``sudo chmod +x /var/ossec/bin/send_to_mysql.sh`` to make the script executable.

Next we configure Wazuh's file for logs to send to mySQL, ``sudo nano /var/ossec/etc/ossec.conf`` and add the following lines:

```
<command>
    <name>send_to_mysql</name>
    <executable>/var/ossec/bin/send_to_mysql.sh</executable>
</command>
```

After, restart Wazuh for these updated commands to log using ``sudo /var/ossec/bin/wazuh-control restart``. Throughout the process the command ``sudo systemctl status wazuh-manager`` can be used to check on the status.

### Verify Data

We manually add a log onto mysql, ``sudo /var/ossec/bin/send_to_mysql.sh "1001" "Test Event" "192.168.1.1" "admin"``.  Next log into mySQL and run the command, ``SELECT * FROM security_events;`` and this should display the one log we created.

![testlog](https://github.com/user-attachments/assets/96019196-8f4b-4f25-8494-69255f68197b)

# Automate & Monitor Logs in Real Time

Now that we have checked that the original log showed, we can automate the process now every 2 seconds using, ``sudo watch -n 2 "mysql -u root -D wazuh_logs -e 'SELECT * FROM security_events;'"``

![automated](https://github.com/user-attachments/assets/d428632c-59ce-4a28-ba3b-227a4e8b96c8)

# Grafana Dashboard Visualizer Setup
The next part in the project is to set up Grafana to visualize the Wazuh logs. We can add the Grafana APT repository using the commands, ``sudo apt-get install -y software-properties-common`` and ``sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"`` followed by ``sudo apt-get install -y grafana``. Now that Grafan is installed, we can start the server using ``sudo systemctl start grafana-server`` and ``sudo systemctl enable --now grafana-server``. We can check the status using ``sudo systemctl status grafana-server``. We want to set a up a login for the dashboard so we utilize the command ``ssh -L 3000:localhost:3000 admin@<VM-ip-address>``. Enter yes for fingerprint, enter a password, and restart the VM. Now that Grafana is officially running, on our host machine we can use any browser and navigate to ``http://<VM-ip-address>:3000`` to access Grafana.

![grafanalogin](https://github.com/user-attachments/assets/34243bda-220e-41a4-93f1-9623b7551403)
![grafana](https://github.com/user-attachments/assets/459d95e9-dee3-474c-8ad0-02dacca2aca1)

Now within Grafana, add new data source and add mysql as a data source with the configuration shown and click 'save & next'.

![datasource](https://github.com/user-attachments/assets/99c60d97-f952-490b-a68b-037b12a786ed)
![datasourcemysql](https://github.com/user-attachments/assets/eea91296-52ee-4e37-a636-a531ddf798d0)
![datasourceconfig](https://github.com/user-attachments/assets/157dec3d-0334-4fdd-8c09-4f4476ea3243)



### Challenges & Solutions
**Challenge 1:** VM does not have a dedicated IP address within network.

**Solution 1:** In VirtualBox Manager change the Ubuntu's network settings from NAT to Bridged Adapter.

**Challenge 2:** VM does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores when installing Wazuh.

**Solution 2:** Use the command included with ``-i`` to ignore requirements, ``sudo bash wazuh-install.sh --wazuh-server wazuh-manager -i``.

**Challenge 3:** Element '< parameters >' is not supported when configuring ossec.conf.

**Solution 3:** Work around with an executable script send_to_mysql.sh.

**Challenge 4:** When configuring Grafana mysql data source, an error says 'query failed - please inspect Grafana server log for details'.

**Solution 4:** Using ``sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf``, edit bind-address to 0.0.0.0
![queryfailed](https://github.com/user-attachments/assets/1aa405f5-e999-41a3-858d-8c2b46377c9d)
