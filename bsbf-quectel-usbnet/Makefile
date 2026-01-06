include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-quectel-usbnet
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-quectel-usbnet
  SECTION:=net
  CATEGORY:=Network
  TITLE:=bsbf-quectel-usbnet
endef

define Build/Compile
endef

define Package/bsbf-quectel-usbnet/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bsbf-quectel-usbnet $(1)/etc/init.d

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/bsbf-quectel-usbnet $(1)/usr/sbin
endef

$(eval $(call BuildPackage,bsbf-quectel-usbnet))
