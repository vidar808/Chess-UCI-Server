# Project Description

This project implements a server in Python that interfaces with various chess engines, allowing remote clients to interact with these engines over a network. The server supports multiple chess engines, including popular ones like Stockfish and Dragon, and provides a flexible framework for logging communications, managing engine options, and handling client requests in real-time.

## Key Features

1. **Multi-Engine Support**: The server is compatible with any chess engine that adheres to the Universal Chess Interface (UCI) protocol, making it versatile and adaptable to different engines.

2. **Concurrent Client Handling**: The server utilizes asynchronous programming with asyncio to efficiently manage multiple client connections simultaneously. It ensures responsive interaction with the chess engines by handling each client request concurrently.

3. **Customizable Engine Options**: The server allows for dynamic configuration of engine options, such as hash size and thread count, through the `config.json` file. It supports sending custom UCI commands to fine-tune engine parameters according to specific requirements.

4. **Logging Functionality**: Comprehensive logging mechanisms are implemented to capture various aspects of the server's operation. The server logs all communications between clients and chess engines, server events, and detailed verbosity logs. Log files are generated and stored in a specified directory for easy access and analysis.

5. **Trusted Sources**: The server incorporates a trusted sources feature, which allows restricting access to specific IP addresses. It ensures that only authorized clients can connect to the server and interact with the chess engines.

6. **Auto-Trust Functionality**: The server includes an auto-trust feature that automatically adds client IP addresses to the trusted sources list when they send the "uci" command. This feature simplifies the process of granting access to new clients.

7. **Customizable Network Configuration**: The server's network configuration, such as the host and port numbers for each chess engine, can be easily customized through the `config.json` file. This flexibility allows running multiple instances of the server with different chess engines on separate ports.

## Server Configuration

The server's configuration is defined in the `config.json` file. Here's an explanation of the key configuration options:

- `host`: The IP address or hostname on which the server listens for incoming connections. Set to "0.0.0.0" to listen on all available network interfaces.
- `base_log_dir`: The directory where log files will be stored.
- `display_uci_communication`: When set to `true`, the server will display the UCI communication between clients and chess engines in real-time on the console.
- `enable_trusted_sources`: When set to `true`, the server will enforce access restrictions based on the trusted sources list.
- `enable_auto_trust`: When set to `true`, the server will automatically add client IP addresses to the trusted sources list when they send the "uci" command.
- `enable_server_log`: When set to `true`, the server will generate a log file named "server.log" to capture server events and exceptions.
- `enable_uci_log`: When set to `true`, the server will generate separate log files for each chess engine, capturing the UCI communication between clients and engines.
- `detailed_log_verbosity`: When set to `true`, the server will include detailed information in the logs, such as UCI commands and responses.
- `custom_variables`: Allows defining custom UCI options that will be sent to all chess engines upon initialization.
- `max_connections`: Specifies the maximum number of concurrent client connections allowed by the server.
- `trusted_sources`: A list of IP addresses that are allowed to connect to the server when `enable_trusted_sources` is set to `true`.
- `engines`: A dictionary specifying the configuration for each supported chess engine, including the engine's path, port number, and custom UCI options.

## Logging Types

The server supports different logging types, each serving a specific purpose:

1. **Display UCI Communication** (`display_uci_communication`): When enabled, the server displays the UCI communication between clients and chess engines in real-time on the console. This is useful for monitoring and debugging purposes.

2. **Detailed Log Verbosity** (`detailed_log_verbosity`): When enabled, the server includes detailed information in the logs, such as UCI commands received from clients and responses sent by chess engines. This verbosity helps in analyzing and troubleshooting the behavior of the server and chess engines.

3. **Server Log** (`enable_server_log`): When enabled, the server generates a log file named "server.log" to capture server events, client connections, disconnections, and any server-related errors or exceptions. This log is useful for monitoring the overall operation of the server and identifying server-specific issues.

4. **UCI Log** (`enable_uci_log`): When enabled, the server generates separate log files for each chess engine, named "communication_log_[engine_name].txt". These log files contain the UCI commands and responses exchanged between clients and each respective chess engine. The UCI communication logs are valuable for analyzing the interaction between clients and chess engines and for debugging engine-specific issues.

By configuring these logging types appropriately in the `config.json` file, you can control the level of logging and the specific information captured in the logs based on your requirements and preferences.

## Getting Started

To run the server, follow these steps:

1. Ensure that you have Python 3.7 or later installed on your system.

2. Install the required dependencies by running the following command:
   ```
   pip install -r requirements.txt
   ```

3. Configure the server by modifying the `config.json` file according to your setup. Specify the paths to your chess engine executables, desired ports, and other configuration options.

4. Place the chess.py script in a directory of your choice and run it from the command line using the following command:
   ```
   python chess.py
   ```

5. The server will start listening for incoming connections on the specified ports. You can now connect to the server using any UCI-compatible chess client or a telnet client.

## Contributing

Contributions to this project are welcome! If you encounter any issues, have suggestions for improvements, or would like to add new features, please feel free to submit a pull request. Make sure to follow the existing code style and provide clear descriptions of your changes.

## Acknowledgements

This project was inspired by the need for a flexible and efficient server to interface with various chess engines. Special thanks to the developers of the chess engines supported by this server for their excellent work in the field of computer chess.
