include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Support for fusionX
LUCI_DEPENDS:=+luci-compat +luci-lib-ipkg +curl +jsonfilter
LUCI_PKGARCH:=all
PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=Your Name <your.email@example.com>

include $(TOPDIR)/feeds/luci/luci.mk

define Package/fusionX/install
    $(INSTALL_DIR) $(1)/etc/init.d
    $(INSTALL_BIN) ./etc/init.d/fusionX $(1)/etc/init.d/fusionX
endef
# call BuildPackage - OpenWrt buildroot signature
$(eval $(call BuildPackage,luci-app-fusionX))

