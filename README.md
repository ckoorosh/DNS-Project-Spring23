<br/>
<p align="center">
  <h1 align="center">Secure Messenger</h3>

  <p align="center">
    A console secure messenger developed with Django framework inspired by the <a href="https://signal.org">Signal Messenger</a>
    <br/>
    <br/>
  </p>
</p>

## About The Project

This is an end-to-end encrypted console secure messenger created with the Django framework. It was developed as a project for the "Data and Network Security" course at Sharif University of Technology.
Here are some of the features of this app:
* creating account
* showing online users
* sending messages
* saving messages securely on each client side
* creating and managing groups
* confirming secure session
* renewing session keys


## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

* Python 3.7 or higher
* docker-compose

### Installation

1. Clone the repo

```sh
https://github.com/ckoorosh/DNS-Project-Spring23.git
```

2. Build the docker image file

```sh
docker-compose build
```

3. Run the server

```sh
docker-compose up
```

4. Run the client

```sh
python MessengerClient/client.py
```

## How it works
Most of the protocols that we implemented were inspired by the Signal Messenger [documentation](https://signal.org/docs/).

### Client
On the client side, we keep a public-private key pair for creating sessions with the server and other clients. 
We only use the POST API for sending messages to the server for more security. 
And always, use a JWT token beside our messages and encrypt it with the client-server session key. 

#### Creating Account
For creating and logging into the account, the user has to provide his username and password.
Upon successful account creation, the user sends his 1. public key, 2. signed pre-key, and 4. a list of one-time pre-keys to the server.
And, after logging into the account, the server responds with a token that will be used by the user in upcoming communications.

#### Sending and Receiving Messages
For an end-to-end encrypted communication between two clients, we do as follows.
For sending a message we use the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) protocol.
This protocol provides forward and backward secrecy.
If the other user is offline, we will use the [Triple Diffie-Hellman (3DH)](https://signal.org/docs/specifications/x3dh/) algorithm.
In this method, we will first get the 1. key identity, 2. signed pre-key, and 3. signature pre-key of the offline user from the server.
Afterward, we will perform DF three times:
```math
\begin{align*}
	&DH1 = DH(IK_A, SPK_B) \\
	&DH2 = DH(EK_A, IK_B) \\
	&DH3 = DH(EK_A, SPK_B) \\
	&DH4 = DH(EKA, OPKB) \\
	&SK = KDF(DH1 || DH2 || DH3 || DH4)
\end{align*}
```

Finally, we will have a key with which we can encrypt the messages and send them to the server.
The server will then, send the messages to the other user when he becomes online.
Using the one-time pre-key prevents the replay attack and signing the messages provides cryptographic deniability.

#### Storing Messages and Keys Securely
Each user's message history is encrypted with the key derived from the user's password.
The user keys will also be encrypted with the same derived key.

#### Creating and Managing Groups
To create a group, the user sends the request with the group's name to the server.
For creating the group's key, we use the AES algorithm to initiate a symmetric session key.
The user will be an admin by default and can add other **online** users to the group with their usernames.
After adding a user the group's session key needs to be shared. 

For sharing the key with the new user, we first establish a one-time key with the DH protocol.
Then, the group's session key is shared with this one-time key.

#### Confirming Session
To ensure session security between two clients, users can view the hash of a part of their session keys represented by emojis.
And by comparing these emojis on both sides, they can make sure of the security of the session.

#### Renewing Session Keys
Each user can select the option to establish new session keys with another user.
The following messages will be encrypted with the new keys.
After removing a user from a group, this happens automatically and the group's session key will be updated and shared.

### Server
The server will only accept POST requests and use the established client-server session key to communicate with users.
Notably, the server **does not have access to the end-to-end encrypted messages** between two users.
For each request from the client, the server will check the given token and validate the user.

#### Creating Account
On the server side, after receiving the username and password, a random salt will be created, and the hash of the password and the salt will be stored in the database.
This way, the user passwords will not be exposed even if someone gains access to the database.
Upon logging in, the server puts the given password and the stored salt together and compares the hash with the value saved in the database.

#### Showing Online Users
To show online users, we return users who have an established WebSocket connection.

#### Creating and Managing Groups
Groups are created upon the request of the users.
Information about the groups and the members along with their roles are stored on the server-side.

#### Sending Messages to Users
The server will send the message to the receiver with a WebSocket connection.
Also, it will not store the messages on its side.

## Report
The final report (in persian) is presented in this [documentation](/Report/report.pdf).

## License

Distributed under the MIT License. See [LICENSE](https://github.com/ckoorosh/DNS-Project-Spring23/blob/main/LICENSE) for more information.
