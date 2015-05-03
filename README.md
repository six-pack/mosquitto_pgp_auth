# mosquitto_pgp_auth module
Basic PGP authentication type for Mosquitto server

This Python authentication module is used by mosquitto_pyauth to ensure that connecting mqtt clients using pgp key ids for usernames do actually hold the private key. The module also governs the ACLs that are applied to queues and messages.

Given that MQTT forces us to include all credentials in a single request we do not have the opportunity for a challenge response mechansism. We try to make up for this by requring a timestamp and the target broker hostname to be present in every authentication request. This reduces the risk of a malicious broker or eavesdropper misusing user credentials.

You will need to add the following lines to /etc/mosquitto/mosquitto.conf

    auth_plugin /usr/lib/mosquitto/auth_plugin_pyauth.so
    auth_opt_pyauth_module mosquitto_pgp_auth
    auth_opt_pgp_dir /var/lib/mosquitto/.gnupg
    auth_opt_broker_hosts 127.0.0.1,127.0.0.2     (insert real hostnames)

+ 'auth_plugin' points to your mosquitto_pyauth shared library created when you compiled mosquitto_pyauth
+ 'auth_opt_pyauth_module' points to this module
+ 'auth_opt_pgp_dir' points to the location of the gnupg directory for the mosquitto user
+ 'auth_opt_broker_hosts' contains a comma seperated list of valid hostnames to require in authentication requests. This should be a list of hostnames your broker has.

Each authentication request is a PGP signed JSON message containing, users PGP key, a timestamp (minutes only) and the target broker hostname. This message is validated by this Python module.
