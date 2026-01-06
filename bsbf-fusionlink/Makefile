include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-fusionlink
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-fusionlink
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-fusionlink
endef

define Build/Compile
endef

define Package/bsbf-fusionlink/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bsbf-fusionlink $(1)/etc/init.d

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-fusionlink $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-fusionlink))
