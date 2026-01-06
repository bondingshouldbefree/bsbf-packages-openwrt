include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-netspeed
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-netspeed
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-netspeed
endef

define Build/Compile
endef

define Package/bsbf-netspeed/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-netspeed $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-netspeed))
