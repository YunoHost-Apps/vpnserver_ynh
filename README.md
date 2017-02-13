OpenVPN for YunoHost
--------------------

OpenVPN allow to create secured tunnel between computers.

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
