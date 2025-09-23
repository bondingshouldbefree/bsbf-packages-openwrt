include $(TOPDIR)/rules.mk

PKG_NAME:=xpedite-bonding
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/xpedite-bonding
  TITLE:=Xpedite Bonding
  SECTION:=net
  CATEGORY:=Network
endef

define Package/xpedite-bonding/config
	select PACKAGE_curl
	select PACKAGE_mptcpize
	select PACKAGE_htop
	select PACKAGE_ip-full
	select KERNEL_BPF_EVENTS
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_sing-box-minimal
	select PACKAGE_luci-app-fusionX
	select PACKAGE_luci-ssl
	select PACKAGE_luci-theme-argon
	select PACKAGE_mptcpd
	select PACKAGE_tcpdump
	select PACKAGE_tc-full
	select PACKAGE_kmod-sched
	select PACKAGE_kmod-sched-bpf
endef

define Package/xpedite-bonding/postinst
#!/bin/sh
cp /etc/xpedite-bonding/firewall /etc/config/firewall
cp /etc/xpedite-bonding/mptcpd.conf /etc/mptcpd/mptcpd.conf
cp /etc/xpedite-bonding/config.json /etc/sing-box/config.json
endef

$(eval $(call BuildPackage,xpedite-bonding))
