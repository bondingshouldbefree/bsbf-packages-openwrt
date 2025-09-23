include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-bonding
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-bonding
  SECTION:=net
  CATEGORY:=Network
  TITLE:=BondingShouldBeFree Bonding
endef

define Package/bsbf-bonding/config
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

define Package/bsbf-bonding/postinst
#!/bin/sh
cp /etc/bsbf-bonding/firewall /etc/config/firewall
cp /etc/bsbf-bonding/mptcpd.conf /etc/mptcpd/mptcpd.conf
cp /etc/bsbf-bonding/config.json /etc/sing-box/config.json
endef

$(eval $(call BuildPackage,bsbf-bonding))
