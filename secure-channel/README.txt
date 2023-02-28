Secure Channel lab

==================

How it works:
1. Server starts and creates a message queue (which is based on memory mapped files).
2. Server generates two keys:
   - asymmetric for signature;
   - symmetric for encryption.
3. Client starts and opens the message queue.
4. Client generates asymmetric key exchange key.
5. Client exports and sends to server public part of exchange key pair.
6. Server imports exchange public key.
7. Server exports and sends to client symmetric key using exchange key pair.
8. Server exports and sends to client public part of signature key (which can be used to verify signature)
9. Client imports received keys.