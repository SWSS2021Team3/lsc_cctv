# CCTV
CCTV is a server that transmits the image recognized from the camera to the monitoring system.

# Getting started

## Build and run in foreground.
### 1. Create account cctv execution.
```bash
$ sudo adduser cctv
...
$ sudo adduser manager
...
```
### 2. Add "cctv" account to sudoers group
### 3. Log in with "cctv" account
### 4. Download source code into the account path.
```bash
$ cd ~/work
$ git clone https://github.com/hijang/lsc_cctv.git
```
### 5. Dependencies
- Dependencies of the Tartan project as below is needed
    ```
        cuda 10.2 + cudnn 8.0 
        TensorRT 7.x
        OpenCV 4.1.1
        TensorFlow r1.14 (for Python to convert model from .pb to .uff)
        keyutils 1.5.9
        glib v2.56.4
        openssl 1.1.1
    ```
- Install openssl library
```bash
$ sudo apt install libssl-dev
```
- Install glib library
```bash
$ sudo apt-get install libglib2.0-*
```
### 6. Build
1. Go to the source code and make a directory to build.
```bash
$ cd ~/work/lsc_cctv/LgFaceRecDemoTCP_Jetson_NanoV2
$ mkdir build
```
2. Build with cmake and make.
```
$ cmake ..
$ make -j 4
```
### 7. Apply ACLs
1. Go to the source code and make a directory to build.
```bash
$ cd ~/work/lsc_cctv/LgFaceRecDemoTCP_Jetson_NanoV2
$ sudo ./acl.sh
```
### 8. Register keys and certificates
- For security, register keys for SSL connection and file encryption.
- The keys for file encryption can be modified arbitrarily by edit fk.blob and fnk.blob.
- **Note that, the keys and certificates for SSL connections should not be changed.**
#### 
1. Go to `./keys` dir
2. Run script to register keys.
```bash
$ cd ~/work/lsc_cctv/keys
$ ./register_server_key.sh
```
### 9. Remove "cctv" account from sudoers group

## Run in background using system daemon
CCTV service can be run in background using system daemon, which make the system executed automatically after the device is boot up. Before you set up, please make sure the cctv binary can execute without error.

### 1. Write cctv.service
1. Make cctv.service file in `/etc/systemd/system/`
```
[Unit]
Description=CCTV
After=network.target

StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
User=cctv
ExecStart=/home/cctv/cctv.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```
2. Make a symblic link for system daemon to execute.
```bash
$ ln /home/cctv/cctv.sh /home/cctv/work/lsc_cctv/cctv.sh
```

### 2. Set dependency to camera daemon
Make dependancy to `/etc/systemd/system/nvargus-daemon.service` for stop or restart of cctv. Otherwise, cctv service can not be loaded due to camera function.
```
[Unit]
Description=Argus daemon
...
PartOf=cctv.service
```
### 3. Reload daemon and start service
```bash
$ sudo systemctl daemon-reload
$ sudo systemctl start cctv
```
- Service status can be checked with command below
```bash
$ systemctl status cctv
● cctv.service - CCTV
   Loaded: loaded (/etc/systemd/system/cctv.service; enabled; vendor preset: enabled)
   Active: active (running) since Thu 2021-06-17 04:38:18 EDT; 1h 54min ago
 Main PID: 8833 (cctv.sh)
    Tasks: 14 (limit: 4181)
   CGroup: /system.slice/cctv.service
           ├─8833 /bin/bash -x /home/cctv/cctv.sh
           └─8852 ./LgFaceRecDemoTCP_Jetson_NanoV2
```
- For more information, it can be monitored with log
```bash
$ sudo journalctl -u cctv -f
-- Logs begin at Thu 2021-06-17 05:34:54 EDT. --
Jun 17 06:14:37 LgFaceRecProject cctv.sh[8833]: [FATAL] Jun/17/2021 06:14:37 [printLog:23] : there is (1) unauthorized person
Jun 17 06:14:37 LgFaceRecProject cctv.sh[8833]: [FATAL] Jun/17/2021 06:14:37 [printLog:23] : there is (1) unauthorized person
Jun 17 06:14:37 LgFaceRecProject cctv.sh[8833]: [FATAL] Jun/17/2021 06:14:37 [printLog:23] : there is (1) unauthorized person
```
### 4. Setting reset service 

CCTV should be restarted once a day as a policy.
You need to configure it to restart at a set time using the cron command.
