python-SelfIop (仮)
===================

Simple implementation of something like a Self-Issued OpenID Providor.


## Key features

 * small set of Self-Issued OP functionality defined in OpenID Connect Core 1.0
 * runs as daemon/service.
 * issues Self-Issued ID Token
 * user consent window


## Requirements

 * Python3.3+
 * following python libraries
   - PyCrypto
   - bottle
   - keyring
   - wsgi-request-logger


## How to play it

Start SelfIop service.

    $ python3 selfiopd.py

Access to following URL. (Send an authentication request to SelfIop)

    http://localhost:8080/?
        response_type=id_token
        &client_id=http%3A%2F%2Flocalhost%2Fcb
        &scope=openid


## Examples

 * Demo RP for Self-Issued OpenID Provider ([examples/webapp/](examples/webapp/))
   - use for testing SelfIop.
   - shows how to write RP.

 * openid:// scheme handler registration file ([examples/win32registry/](examples/win32registry/))
   - register your SelfIop running at http://localhost:8080/ as a openid:// scheme handler.


## Platform specific topics

### Debian (Linux)

When you starts SelfIop service first time, following prompt is shown.

    $ python3 selfiopd.py
    Please set a password for your new keyring: ****
    Please confirm the password: ****

SelfIop uses keyring function to store master password for encrypting RSA secret.
Input **new** password and don't forget it.

From the second time, you must input the password.

    $ python3 selfiopd.py
    Please enter password for encrypted keyring: ****


### Windows

On Windows platform, SelfIop can run as a Windows Service with following steps.

Open a Command Prompt window as an administrator and install as a service.

    > python selfiopd_win.py install
    Installing service SelfIop
    Service installed

Starts the service.

    > net start SelfIop
    The SelfIop Service service is starting.
    The SelfIop Service service was started successfully.


## License

This software is released under the MIT License, see LICENSE file.


## changelog

 * release 2
   - [new] Demo RP application.
   - [new] openid:// scheme handling support code.
   - [new] openid:// scheme handler registration file for windows.
   - [modify] small code fixups.

 * first release
