include $(TOPDIR)/rules.mk

PKG_NAME:=meig_firehose
PKG_VERSION:=1.3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/meig_firehose
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=MeiG Firehose Recovery application
endef

define Package/meig_firehose/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/Meig_firehose $(1)/usr/bin/meig_firehose
endef

$(eval $(call BuildPackage,meig_firehose))
