# Project Description

This project aims to implement a server in Python designed to interface with various chess engines, enabling remote clients to interact with these engines over a network. It supports multiple chess engines, including Stockfish, and provides a framework for logging communications, managing engine options (such as hash size), and handling client requests in real-time.

The server listens for incoming TCP connections on specified ports, each dedicated to a different chess engine. Upon establishing a connection, the server initiates the chess engine process, sets engine options based on client requests or default values, and relays commands and data between the client and the chess engine. It also logs all communications to facilitate debugging and analysis. Project was specifically setup to run with the Droidfish android app.

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

Place your chess engine executables in a known directory.
Modify the engines dictionary in chess.py to specify the paths to your chess engine executables and the ports they should listen on.
Run the Server:

Plase chess.py in a directory and run from the commandline 

From command line run:
python chess.py
Adjust chess.py to point to your specific engine paths and desired listening ports.

Usage
Connect to the server using any TCP client capable of sending and receiving text data, such as a custom chess GUI or a simple telnet client. Send commands according to the UCI protocol, and the server will relay these commands to the specified chess engine and return the engine's responses.

Contributing
Contributions are welcome! Please feel free to submit pull requests with bug fixes, improvements, or additional features.


The configuration is as follows:

# Global configurations
HOST = '0.0.0.0' # to be accessible from any remote host
BASE_LOG_DIR = r"C:\Users\administrator\Desktop\chess\LOG" # the location where UCI communication logs are saved if logging is enabled.
ENABLE_FILE_LOGGING = False  # Set to False to disable file logging

# Define custom variables and their values
CUSTOM_VARIABLES = {
    "Hash": "16384",
    "Threads": "32",
    # Add more custom variables here as needed
}

# Define engines and their configurations. (Engine name, Engine file location, communication port)
ENGINES = {
        "Dragon": {"path": r"C:\Users\administrator\Desktop\chess\dragon-3.3_fb79bacb\Windows\dragon-3.3-64bit-avx2.exe", "port": 9999},
        "Stockfish": {"path": r"C:\Users\administrator\Desktop\chess\stockfish 16\stockfish-windows-x86-64-avx2.exe", "port": 9998},
        "Berserk": {"path": r"C:\Users\administrator\Desktop\chess\berserk 12.1\berserk-12-x64-avx2.exe", "port": 9997},
        "Tal": {"path": r"C:\Users\administrator\Desktop\chess\Chess-System-Tal-2.00-v21\Chess-System-Tal-2.00-v21-E1162-130-EAS.opt-avx2.exe", "port": 9996},
        "Shash": {"path": r"C:\Users\administrator\Desktop\chess\ShashChess 34\ShashChess34.6-x86-64-bmi2.exe", "port": 9995},
        "Ethereal": {"path": r"C:\Users\administrator\Desktop\chess\Ethereal 14.2\Windows\Ethereal-14.25-avx2.exe", "port": 9994},
        "Caissa": {"path": r"C:\Users\administrator\Desktop\chess\Caissa 1.15\Caissa 1.15\caissa-1.15-x64-avx2-bmi2.exe", "port": 9993},
        "Rubi": {"path": r"C:\Users\administrator\Desktop\chess\RubiChess-20240112\windows\RubiChess-20240112_x86-64-bmi2.exe", "port": 9992},
    # Add more engines here as needed
}


Logging types configured in config.json:

1. "display_uci_communication": false
   - This logging type determines whether the UCI (Universal Chess Interface) communication between the client and the chess engine should be displayed in real-time on the console.
   - When set to `true`, the script will print the UCI commands and responses exchanged between the client and the engine as they occur.
   - When set to `false`, the UCI communication will not be displayed on the console, but it may still be logged to files depending on other logging settings.
   - This setting is primarily used for real-time monitoring and debugging purposes.

2. "detailed_log_verbosity": true
   - This logging type controls the verbosity of the detailed logs generated by the script.
   - When set to `true`, the script will include detailed information in the logs, such as the UCI commands received from the client and the responses sent by the chess engine.
   - When set to `false`, the detailed logs will be less verbose and may omit certain details.
   - The detailed logs are typically written to log files and can be useful for analyzing and troubleshooting the behavior of the script and the chess engines.

3. "enable_server_log": true
   - This logging type determines whether the server-related logs should be generated and stored in a log file.
   - When set to `true`, the script will create a log file named "server.log" in the specified "base_log_dir" directory.
   - The server log file will contain information about server events, such as client connections, disconnections, and any server-related errors or exceptions.
   - This log is useful for monitoring the overall operation of the server and identifying any server-specific issues.

4. "enable_uci_log": false
   - This logging type determines whether the UCI communication logs should be generated and stored in separate log files for each chess engine.
   - When set to `true`, the script will create individual log files for each chess engine, named "communication_log_[engine_name].txt" in the specified "base_log_dir" directory.
   - These log files will contain the UCI commands and responses exchanged between the client and each respective chess engine.
   - The UCI communication logs are useful for analyzing the interaction between the client and the chess engines and for debugging engine-specific issues.

In summary, the "display_uci_communication" setting controls the real-time display of UCI communication on the console, while the "detailed_log_verbosity" setting determines the verbosity of the detailed logs. The "enable_server_log" setting enables the generation of a server log file, and the "enable_uci_log" setting enables the generation of separate UCI communication log files for each chess engine.

By configuring these logging types appropriately, you can control the level of logging and the specific information captured in the logs based on your requirements and preferences. Enabling different combinations of these logging types allows you to strike a balance between log verbosity and performance, depending on your needs for monitoring, debugging, and analysis.
