include $(TOPDIR)/rules.mk

PKG_NAME:=bsbf-bonding
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bsbf-bonding
  SECTION:=net
  CATEGORY:=Network
  TITLE:=BondingShouldBeFree Bonding
endef

define Build/Compile
endef

define Package/bsbf-bonding/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-bsbf-bonding $(1)/etc/uci-defaults
endef

$(eval $(call BuildPackage,bsbf-bonding))
