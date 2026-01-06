include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-route
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-route
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-route
endef

define Build/Compile
endef

define Package/bsbf-route/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bsbf-route $(1)/etc/init.d

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-route $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-route))
