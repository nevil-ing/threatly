#!/bin/bash

# Start Apache HTTP server
sudo systemctl start httpd &>> ~/service_log.txt

# Start Logstash
sudo systemctl start logstash &>> ~/service_log.txt

# Start Filebeat
sudo systemctl start filebeat &>> ~/service_log.txt

