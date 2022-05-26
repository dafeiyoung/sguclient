include $(TOPDIR)/rules.mk

PKG_NAME:=sguclient
PKG_VERSION:=1.00
PKG_RELEASE:=r1.00-luci-release
TARGET_CFLAGS += -std=gnu99

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=sguclient
	MAINTAINER:=young,FurryAcetylCoA,IDeLoveYou
	DEPENDS:=+libpcap +libpthread
endef 
 
define Package/$(PKG_NAME)/description
	sguclient general program
endef
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/share/sguclient
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/sguclient
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sguclient $(1)/bin/
	$(INSTALL_CONF) ./files/root/etc/config/sguclient $(1)/etc/config/sguclient
	$(INSTALL_BIN)  ./files/root/etc/init.d/sguclient $(1)/etc/init.d/sguclient
	$(INSTALL_BIN)  ./files/root/usr/share/sguclient/sgud.sh $(1)/usr/share/sguclient/sgud.sh
	$(INSTALL_DATA) ./files/root/usr/lib/lua/luci/model/cbi/sguclient/log.lua $(1)/usr/lib/lua/luci/model/cbi/sguclient/log.lua
	$(INSTALL_DATA) ./files/root/usr/lib/lua/luci/model/cbi/sguclient/sguclient.lua $(1)/usr/lib/lua/luci/model/cbi/sguclient/sguclient.lua
	$(INSTALL_DATA) ./files/root/usr/lib/lua/luci/controller/sguclient.lua $(1)/usr/lib/lua/luci/controller/sguclient.lua
	$(INSTALL_DATA) ./i18n/zh-cn/*.lmo $(1)/usr/lib/lua/luci/i18n/
endef

define Package/$(PKG_NAME)/postrm
	#!/bin/sh
	echo "Removeing sguclient temporary file."
	rm -r /usr/share/sguclient >/dev/null 2>&1
	rm -r /overlay/upper/usr/lib/lua/luci/model/cbi/sguclient >/dev/null 2>&1
	rm -f /tmp/.uci/sguclient >/dev/null 2>&1
	rm -f /var/run/sguclient.pid >/dev/null 2>&1
	rm -f /var/run/${DAEMON}.pid >/dev/null 2>&1
	rm -f /var/log/sguclient.log >/dev/null 2>&1   #防止卸载后重装还能看到上一个版本的log引起混淆
endef

$(eval $(call BuildPackage,sguclient))
