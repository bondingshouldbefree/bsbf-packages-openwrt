include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-usb-netdev-autodhcp
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-usb-netdev-autodhcp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-usb-netdev-autodhcp
endef

define Build/Compile
endef

define Package/bsbf-usb-netdev-autodhcp/install
	$(INSTALL_DIR) $(1)/etc/hotplug.d/net
	$(INSTALL_BIN) ./files/etc/hotplug.d/net/99-bsbf-usb-netdev-autodhcp $(1)/etc/hotplug.d/net
endef

$(eval $(call BuildPackage,bsbf-usb-netdev-autodhcp))
