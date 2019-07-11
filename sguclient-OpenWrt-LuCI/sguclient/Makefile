include $(TOPDIR)/rules.mk

PKG_NAME:=sguclient
PKG_VERSION:=0.20
PKG_RELEASE:=r0.20-luci

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
SECTION:=utils
CATEGORY:=Utilities
TITLE:=sguclient
MAINTAINER:=young
DEPENDS:=+libpcap +libpthread
endef 
 
define Package/$(PKG_NAME)/description
sguclient general program
endef
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(foreach po,$(wildcard ${CURDIR}/i18n/zh-cn/*.po), \  
		po2lmo $(po) $(PKG_BUILD_DIR)/$(patsubst %.po,%.lmo,$(notdir $(po)));)  
endef

define Package/sguclient/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sguclient $(1)/bin/
	$(INSTALL_CONF) ./luci_files/root/etc/config/sguclient $(1)/etc/config/sguclient
	$(INSTALL_BIN) ./luci_files/root/etc/init.d/sguclient $(1)/etc/init.d/sguclient
	$(INSTALL_DATA) ./luci_files/root/usr/lib/lua/luci/model/cbi/sguclient.lua $(1)/usr/lib/lua/luci/model/cbi/sguclient.lua
	$(INSTALL_DATA) ./luci_files/root/usr/lib/lua/luci/controller/sguclient.lua $(1)/usr/lib/lua/luci/controller/sguclient.lua
	$(INSTALL_DATA) ./i18n/zh-cn/*.lmo $(1)/usr/lib/lua/luci/i18n/
endef

$(eval $(call BuildPackage,sguclient))
