##### Messages

1. sender has a message & his private key
2. sender computes hash of the message and signs it (HMAC) & sends it to receiver
3. sender encrypts the message with a symmetric protocol & sends it to receiver

##### Communication Protocols

1. Diffie Hellman Key Exchange 
2. AES
3. HMAC + Unique Nonce (for each message) => no replay & non malleability
4. Password Hashing (Client) + HashMap (Serverside) for client's psw check

###### Requirements:

1. **confidentiality**: Ensure that messages and user credentials are not accessible to unauthorized users
2. **integrity**: Ensure that messages are not altered during transmission
3. **no-replay**: Prevent replay attacks by using unique nonces or timestamps
4. **non-malleability**: Ensure that encrypted messages cannot be tampered with without detection
5. **perfect forward secrecy**: Use ephemeral keys for each session so that compromise of long-term keys does not compromise past sessions
6. **password security**: Never store or transmit passwords in clear text. Use a secure hashing algorithm (e.g., bcrypt) for storing passwords.