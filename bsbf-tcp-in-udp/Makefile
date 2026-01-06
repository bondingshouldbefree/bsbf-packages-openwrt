include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-tcp-in-udp
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-tcp-in-udp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-tcp-in-udp
endef

define Build/Compile
endef

define Package/bsbf-tcp-in-udp/install
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/99-bsbf-tcp-in-udp $(1)/etc/hotplug.d/iface

	$(INSTALL_DIR) $(1)/usr/local/share/tcp-in-udp
ifeq ($(CONFIG_BIG_ENDIAN),y)
	$(INSTALL_DATA) ./files/usr/local/share/tcp-in-udp/tcp_in_udp_tc_be.o $(1)/usr/local/share/tcp-in-udp/tcp_in_udp_tc.o
else
	$(INSTALL_DATA) ./files/usr/local/share/tcp-in-udp/tcp_in_udp_tc_le.o $(1)/usr/local/share/tcp-in-udp/tcp_in_udp_tc.o
endif

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-tcp-in-udp $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-tcp-in-udp))
