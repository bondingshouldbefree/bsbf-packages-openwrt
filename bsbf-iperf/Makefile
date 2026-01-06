include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-iperf
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-iperf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-iperf
endef

define Build/Compile
endef

define Package/bsbf-iperf/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-iperf $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-iperf))
