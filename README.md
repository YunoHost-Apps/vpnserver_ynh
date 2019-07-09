OpenVPN server for YunoHost
--------------------

OpenVPN allow to create secured tunnel between computers. This is the server part, to which OpenVPN clients may connect to. See [vpnclient_ynh](https://github.com/labriqueinternet/vpnclient_ynh) for the client part.

http://openvpn.net/

**Package by:** 

**Categories:** diy-isp

**Upgrade this package:**
`sudo yunohost app upgrade --verbose OpenVPN -u https://github.com/YunoHost-Apps/openvpn_ynh`

**Multi-user:** Yes.

**SSO/LDAP:** SSO and LDAP are configured. Each YunoHost user can have one VPN account.


Configuration:

* Download CA from `https://<your_server.tld>/yunohost/admin/ca.crt`
* Configure your VPN with TUN interface, LZO compression and password authentication (with your YunoHost account/passwd), on standard UDP port 1194
