# Graylog-Docker
Graylog is an open-source log management platform that helps collect, index, and analyze machine data from various sources in real-time. It provides a scalable and efficient solution for log aggregation, monitoring, and security analysis.

## Install Docker.io on your system
```bash
sudo apt update
```
```bash
sudo apt install docker.io -y
```
```bash
sudo usermod -aG docker $USER
newgrp docker
docker --version
```
- Start and enable the docker
  ```bash
  systemctl enable docker
  systemctl start docker
  ```   
## Install Docker Compose 
- Install the dependencies
  ```bash
  sudo apt install -y curl git ca-certificates
  ```
- Now proceed with the installation of docker-compose
  ```bash
  sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  ``` 
- Set the right permissions
  ```bash
  sudo chmod +x /usr/local/bin/docker-compose
  ```
- Confirm the installation
  ```bash
  docker-compose --version
  ```

## Provision the graylog Container
- The graylog container will consist of the graylog server, elasticsearch and Mongodb. To be able to achieve this, we will capture the information and settings into a YML file.
- Make a separate directory to store the docker-compose.yml file
  ```bash
  mkdir graylog
  cd graylog
  ```
- Create a docker-compose.yml file
  ```bash
  nano docker-compose.yml
  ```
- In the docker-compose.yml file add the desired content. To get the docker-compose.yml content click [here](https://github.com/effaaykhan/Graylog-Docker/blob/main/docker-compose.yml)
- Create .env file
  ```bash
  nano .env
  ```
- Add the conent in .env file. To get the .env file click [here](https://github.com/effaaykhan/Graylog-Docker/blob/main/.env)
- In the .env file we need to add GRAYLO_PASSWORD_SECRET & GRAYLOG_ROOT_PASSWORD_SHA. Without them graylog will not start.
  - GRAYLOG_PASSWORD_SECRET
    ```bash
    < /dev/urandom tr -dc A-Z-a-z-0-9 | head -c${1:-96};echo;
    ```
  - GRAYLOG_ROOT_PASSWORD_SHA
    ```bash
    echo -n "Enter Password: " && head -1 </dev/stdin | tr -d '\n' | sha256sum | cut -d" " -f1
    ```
- After the setup run the following command:
  ```bash
  docker-compose up -d
  ```

## Extractors
- [Regular Expression](https://github.com/Sujal242003/Graylog-Docker/blob/main/Extractors/Regex%20Extractor) extractor for fortigate logs



# Forward LLM enriched logs to graylog.
- Step 1: Create a python file in /var/ossec/:
  
  nano /var/ossec/yara_to_graylog.py
  
- Step 2: Paste the [yara_to_graylog.py](https://github.com/sujalthakur-03/Graylog-Docker/blob/main/yara_to_graylog.py) in the newly created file.
- Step 3: Now create a service in /etc/systemd/system/
  
  sudo nano /etc/systemd/system/yara-graylog.service
  
- Step 4: Paste the [yara-graylog.service](https://github.com/sujalthakur-03/Graylog-Docker/blob/main/yara-graylog.service) in the newly created file.
