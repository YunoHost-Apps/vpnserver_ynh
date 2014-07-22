<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8">
    <title>OpenVPN configuration</title>
    <link href="assets/css/main.css" media="all" rel="stylesheet" type="text/css" />
</head>
<body>

    <header>
        <img src="assets/img/Ovpntech_logo-s_REVISED.png" />
    </header>

    <section class="status">
        <?php if ($_SERVER['REMOTE_ADDR'] == $_SERVER['SERVER_ADDR']): ?>
        <p class="message success">You are successfully connected to the VPN server</p>
        <?php else: ?>
        <p class="message error">You are not connected to the VPN server</p>
        <?php endif; ?>
        <p>Your IP address is : <strong><?php echo $_SERVER['REMOTE_ADDR']; ?></strong></p>
    </section>

    <section class="configuration">
        <h1>Configuration</h1>
        <ul>
            <li><a href="ca.crt">Download Certificate Authority (CA) of this server</a></li>
            <li><a href="<?php echo $_SERVER['SERVER_NAME']; ?>.conf">Download OpenVPN configuration for NetworkManager</a></li>
            <li><a href="<?php echo $_SERVER['SERVER_NAME']; ?>.ovpn">Download OpenVPN configuration for command-line client</a></li>
        </ul>
    </section>

    <section class="documentation">
        <h1>Documentation</h1>
        <ul>
            <li><a href="https://yunohost.org/app_openvpn" target="_blank">Documentation on YunoHost.org</a></li>
            <li><a href="https://openvpn.net" target="_blank">OpenVPN official website</a></li>
            <li><a href="https://en.wikipedia.org/wiki/OpenVPN" target="_blank">Wikipedia page</a></li>
        </ul>
    </section>

</body>
</html>
