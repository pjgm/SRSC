-----Phase 1 and 2-----
1. First the AuthServer must be started with the parameters:
    PORT TLS_CONFIG_FILE USER_PASSWORDS_FILE ACCESS_CONTROL_FILE KEYSTORE_AND_CONFIG_DIRECTORY

2. Then run MChatCliente with the parameters:
    USER GROUP GROUP_PORT TTL AUTH_SERVER_ADDRESS AUTH_SERVER_PORT TLS_CONFIG_FILE


example:
    java project.servers.AuthServer 9000 src/main/java/test/serverStore/tls.config src/main/java/project/servercfg/auth.cfg src/main/java/project/servercfg/accesscontrol.cfg src/main/java/project/cryptocfgfiles/

    [THEN]

    java -Djava.net.preferIPv4Stack=true project.chat.MChatCliente USER 224.0.0.1 9000 1 localhost 9000 src/main/java/test/clientStore/tls.config


(to set a password for a user use $echo -n PASSWORD | openssl dgst -binary -sha512 | openssl base64 and add it to the USER_PASSWORD_FILE)

by:
António Pacheco (41820) [a.pacheco@campus.fct.unl.pt]
Paulo Martins (41982) [pj.martins@campus.fct.unl.pt]