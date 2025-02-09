include $(TOPDIR)/rules.mk

PKG_NAME:=udp-encapsulation-tunnel
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/bondingshouldbefree/udp-encapsulation-tunnel.git
PKG_SOURCE_VERSION:=main

include $(INCLUDE_DIR)/package.mk

define Package/udp-encapsulation-tunnel
  SECTION:=net
  CATEGORY:=Network
  TITLE:=UDP Encapsulation Tunnel
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/udp-encapsulation-tunnel \
		$(PKG_BUILD_DIR)/udp-encapsulation-tunnel.c
endef

define Package/udp-encapsulation-tunnel/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/udp-encapsulation-tunnel $(1)/usr/bin
#	$(INSTALL_DIR) $(1)/etc/init.d
#	$(INSTALL_BIN) ./files/udp-encapsulation-tunnel.init $(1)/etc/init.d/udp-encapsulation-tunnel
endef

$(eval $(call BuildPackage,udp-encapsulation-tunnel))
