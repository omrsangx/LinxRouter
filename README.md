# LinxRouter

Linux (Ubuntu) server router with a WireGuard vpn client.
This router was configure on a Ubuntu Server 22.04.1 LTS using a Raspberry Pi 4, but it can easily be configured for other Linux distributions.

There are few things to keep in mind:
- This was configured on a clean installation of Ubuntu Server 22.04.1 LTS, but I added the option to backup the configuration files that will be modified.
- This is using both eth0 and wla0. This are the default interface's name set up by Ubuntu for the Raspberry Pi 4. The interface's name will have to be change if you are using a different configuration.
- At the moment of the setup, the server is not connected to WiFi, that is why is doing the network configuration first and then the update/upgrade and installation of the needed packages.

Author: omrsangx (Omar)
