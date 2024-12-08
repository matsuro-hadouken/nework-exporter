# A3MC Network Exporter

Prometheus network exporter to debug **edge cases** with basic auth

#### Installation

Requirements:

* Use dedicated user to follow best practices
* Install Rust in user environment or build aside
* Use direct path to builded binary, symlink or copy to somewhere
* User should have access to config file

```bash
git clone https://github.com/matsuro-hadouken/nework-exporter.git
```

#### Build
```bash
cargo build --release
```

#### Run

Set permissions to `config.yaml`

```bash
chmod 0600 config.yaml
```
Edit `config.yaml` adjust host port user password

Example:

```yaml
host: "127.0.0.1"
port: 1234
user: "UserName"
password: "Password"
```
Create systemd unit:
```bash
nano /etc/systemd/system/a3mc-network-exporter.service`
```
Adjust: user, path to config and binary

```
[Unit]
Description=A3MC Network Exporter
After=network.target

[Service]
ExecStart=/home/user_name/bin/a3mc-network-exporter --config /path/to/config.yaml

WorkingDirectory=/home/user_name/bin

User=user_name
Group=user_name

Restart=on-failure

RestartSec=12

StandardOutput=journal
StandardError=journal

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
Start:
```bash
systemctl daemon-reload
systemctl enable a3mc-network-exporter.service
systemctl start a3mc-network-exporter.service
```
Test availability:
```bash
curl -u UserName:Password http://127.0.0.1:1234/metrics
```

### To do:

* How to configure Prometheus
* Commmit Grafana dashboard