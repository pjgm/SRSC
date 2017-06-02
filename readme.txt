-----Phase 1-----
1. to run MChatCliente the following parameters must be defined: USERNAME MULTICAST_ADDRESS PORT [TTL]
2. when the program starts for the first time the user is asked to define a password to encrypt the cypher keys.
3. done. the user can now use the chat
4. the .crypto file for that chat can now be deleted
5. to start the chat client again the user needs to input the password he defined the first time the chat was opened
6. with the correct password, the encrypted file with the chat keys is decrypted
(use the -Djava.net.preferIPv4Stack=true flag)

example java -Djava.net.preferIPv4Stack=true project.chat.MChatCliente user1 224.0.0.2 9000

-----Phase 2-----
1. First the AuthServer must be started with the parameters: PORT USER_PASSWORD_FILE ACCESS_CONTROL_FILE

2. repeat the same steps for the chat client as described in Phase 1


example:
    java project.servers.AuthServer 9000 auth.cfg accesscontrol.cfg
    [THEN]
    example java -Djava.net.preferIPv4Stack=true project.chat.MChatCliente user1 224.0.0.2 9000


(to set a password for a user use $echo -n PASSWORD | openssl dgst -binary -sha512 | openssl base64 and add it to the USER_PASSWORD_FILE)

by:
António Pacheco (41820) [a.pacheco@campus.fct.unl.pt]
Paulo Martins (41982) [pj.martins@campus.fct.unl.pt]