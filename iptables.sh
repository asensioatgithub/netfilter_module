#!/bin/bash
#encoding:utf-8

#1 定义变量
iptables="/sbin/iptables"
HOST_IP="192.168.1.120"
WEB_IP="192.168.1.106"
IFACE="eth2"
#SERVICE_TCP_PORTS="22,21,25,80,443" #ssh ftp smtp http https


#2 清除规则
$iptables -F # 清除filter表中规则链中所有的规则
$iptables -t nat -F #清除nat表中规则链中所有的规则
$iptables -X # 清除filter表中使用者自定义链中的规则
$iptables -t nat -X #清除nat表中使用者自定义链中的规则

#3 定义默认策略
$iptables -P INPUT ACCEPT
$iptables -P OUTPUT ACCEPT
$iptables -P FORWARD ACCEPT

#-------------（一）外网不能访问本机，但是本机主动发起的连接正常进行--------------
$iptables -A INPUT -i $IFACE -p tcp -s 0/0 -d $HOST_IP -m multiport --dport 1:4566,4568:65535 -m state --state NEW -j DROP
#	or
#$iptables -A INPUT -i $IFACE -p tcp -s 0/0 -d $HOST_IP -m multiport --dport 1:4566,4568:65535 --syn -j DROP

#-------------（二）限制对icmp echo request的回复为一分钟5次---------------------
$iptables -A INPUT -i $IFACE -p icmp -s 0/0 -d $HOST_IP --icmp-type 8 -m limit --limit 5/m --limit-burst 7 -j ACCEPT
$iptables -A INPUT -i $IFACE -p icmp -s 0/0 -d $HOST_IP --icmp-type 8 -j DROP

#-------------（三）通过访问A电脑未开放的4567端口，实际可以访问到B电脑的80端口上的网页---------------------
$iptables -t nat -A PREROUTING -i $IFACE -p tcp -s 0/0 -d $HOST_IP --dport 4567 -j DNAT --to-destination $WEB_IP:80
$iptables -t nat -A POSTROUTING -p tcp -s 0/0 -d $WEB_IP --dport 80 -j SNAT --to-source $HOST_IP
