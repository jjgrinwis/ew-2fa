# ew-2fa
Akamai EdgeWorker test to limit number of 2FA requests

A small EdgeWorker script to register failed 2FA attempts (!200) using two different event handlers and Akamai EdgeKV:
![image](https://user-images.githubusercontent.com/3455889/218494232-27dac65d-9df7-43cc-9335-b3706765ff6b.png)

Non 200's are registered and if # request >= max_requests your blocked in the onClienRequest state. 
