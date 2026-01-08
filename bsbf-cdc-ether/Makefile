include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-cdc-ether
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-cdc-ether
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-cdc-ether
endef

define Build/Compile
endef

define Package/bsbf-cdc-ether/install
	$(INSTALL_DIR) $(1)/etc/hotplug.d/usb
	$(INSTALL_BIN) ./files/etc/hotplug.d/usb/99-bsbf-cdc-ether $(1)/etc/hotplug.d/usb

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bsbf-cdc-ether $(1)/etc/init.d

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-cdc-ether $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-cdc-ether))
