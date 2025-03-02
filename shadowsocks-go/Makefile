# SPDX-License-Identifier: GPL-3.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocks-go
PKG_VERSION:=main
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/database64128/shadowsocks-go.git
PKG_SOURCE_VERSION:=main

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/database64128/shadowsocks-go/cmd/shadowsocks-go
GO_PKG_BUILD_PKG:=$(GO_PKG)/main
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG).build=OpenWrt \
	$(GO_PKG).version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include ../golang/golang-package.mk

define Package/shadowsocks-go
  TITLE:=A versatile and efficient proxy platform for secure communications.
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=$(GO_ARCH_DEPENDS)
endef

define Package/shadowsocks-go/conffiles
/etc/config/shadowsocks-go
/etc/shadowsocks-go/config.json
endef

define Package/shadowsocks-go/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/main $(1)/usr/bin/shadowsocks-go

	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_CONF) $(CURDIR)/files/shadowsocks-go.conf $(1)/etc/config/shadowsocks-go
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(CURDIR)/files/shadowsocks-go.init $(1)/etc/init.d/shadowsocks-go
endef

$(eval $(call BuildPackage,shadowsocks-go))
