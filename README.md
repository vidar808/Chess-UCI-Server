Project Description
This project implements a server in Python designed to interface with various chess engines, enabling remote clients to interact with these engines over a network. It supports multiple chess engines, including Stockfish and Dragon, and provides a framework for logging communications, managing engine options (such as hash size), and handling client requests in real-time.

The server listens for incoming TCP connections on specified ports, each dedicated to a different chess engine. Upon establishing a connection, the server initiates the chess engine process, sets engine options based on client requests or default values, and relays commands and data between the client and the chess engine. It also logs all communications to facilitate debugging and analysis.

Features
Multi-Engine Support: Compatible with any chess engine that adheres to the UCI (Universal Chess Interface) protocol.
Dynamic Hash Size Configuration: Allows setting the engine's hash size dynamically upon initialization, optimizing performance based on available resources.
Concurrent Client Handling: Utilizes threading to manage multiple client connections simultaneously, ensuring responsive interaction with the chess engines.
Logging: Logs all communications between the client and the chess engine, aiding in troubleshooting and performance tuning.
Customizable Engine Options: Supports sending custom UCI commands to configure engine parameters beyond just the hash size.
Contents
server.py: The main server script that sets up listening sockets, handles incoming connections, and manages the lifecycle of chess engine processes.
README.md: This file, containing project information and setup instructions.
Getting Started
Prerequisites
Python 3.6 or later.
Chess engines (e.g., Stockfish, Dragon) compatible with the UCI protocol.
Setup
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/chess-engine-server.git
cd chess-engine-server
Configure Engines:

Place your chess engine executables in a known directory.
Modify the engines dictionary in server.py to specify the paths to your chess engine executables and the ports they should listen on.
Run the Server:

bash
Copy code
python server.py
Adjust server.py to point to your specific engine paths and desired listening ports.

Usage
Connect to the server using any TCP client capable of sending and receiving text data, such as a custom chess GUI or a simple telnet client. Send commands according to the UCI protocol, and the server will relay these commands to the specified chess engine and return the engine's responses.

Contributing
Contributions are welcome! Please feel free to submit pull requests with bug fixes, improvements, or additional features.
