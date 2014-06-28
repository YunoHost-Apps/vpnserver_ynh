<!DOCTYPE HTML>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>OpenVPN configuration</title>
</head>
<body>

<h1>OpenVPN configuration</h1>

<p>
Your IP address is : <?php echo $_SERVER['REMOTE_ADDR']; ?>
</p>

<?php if ($_SERVER['REMOTE_ADDR'] == $_SERVER['SERVER_ADDR']) { ?>
<p>
    <b>You are successfully connected to this VPN server</b>
</p>
<?php } ?>

<br>

<p>
    <a href="ca.crt">Download Certificate Authority (CA) of this server</a>
    <br>
    <a href="<?php echo $_SERVER['SERVER_NAME']; ?>.conf">Download OpenVPN configuration for NetworkManager</a>
    <br>
    <a href="<?php echo $_SERVER['SERVER_NAME']; ?>.ovpn">Download OpenVPN configuration for command-line client</a>
</p>

<br>
<hr>
<br>

<p><b><a href="https://yunohost.org/app_openvpn" target="_blank">More information</a></b></p>

</body>
</html>
