Project Description 

This project seeks to develop a server in Python that seamlessly interfaces with various chess engines, enabling remote clients to interact with these engines over a network. The server boasts a wide range of capabilities, including support for multiple chess engines, flexible logging options, dynamic engine configuration, and advanced security features. It provides a comprehensive solution for managing and interacting with chess engines in a networked environment. The server communicates in clear text and utilizes various schemes to secure the ports used by the server. 

Key Features
1.	Multi-Engine Support:
•	The server is compatible with any chess engine that adheres to the Universal Chess Interface (UCI) protocol, ensuring versatility and adaptability to different engines.
•	It supports popular chess engines such as Stockfish and Dragon, allowing users to leverage the strength and unique characteristics of each engine.
2.	Concurrent Client Handling:
•	Utilizing asynchronous programming with asyncio, the server efficiently manages multiple client connections simultaneously.
•	It ensures responsive interaction with the chess engines by handling each client request concurrently, optimizing performance and resource utilization.
3.	Customizable Engine Options:
•	The server allows for dynamic configuration of engine options through the config.json file, providing flexibility in tailoring the behavior of each chess engine.
•	It supports sending custom UCI commands to fine-tune engine parameters, such as hash size and thread count, according to specific requirements.
•	Engine-specific options can be defined in the engines section of the configuration file, allowing for granular control over each engine's settings.
4.	Comprehensive Logging Functionality:
•	The server implements extensive logging mechanisms to capture various aspects of its operation, facilitating monitoring, debugging, and analysis.
•	It generates detailed log files, including server logs, UCI communication logs, and untrusted connection attempt logs, which are stored in a specified directory for easy access.
•	The verbosity of the logs can be controlled through configuration options, allowing users to customize the level of detail captured.
5.	Enhanced Security Features:
•	The server incorporates a trusted sources mechanism to restrict access to specific IP addresses, ensuring that only authorized clients can connect and interact with the chess engines.
•	It supports both individual IP addresses and subnet-based access control, providing flexibility in managing client permissions.
•	The auto-trust feature automatically adds client IP addresses to the trusted sources list when they send the "uci" command, simplifying the process of granting access to new clients.
6.	Firewall Integration:
•	The server seamlessly integrates with the Windows Firewall to provide an additional layer of security and access control.
•	It automatically configures firewall rules to block untrusted subnet traffic and individual IP addresses based on the specified configuration options.
•	The server dynamically updates the firewall rules as new untrusted connection attempts are detected, ensuring a proactive approach to security.
7.	Connection Attempt Monitoring:
•	The server actively monitors connection attempts from untrusted sources and keeps track of the number of attempts made by each IP address.
•	It allows configuring the maximum number of connection attempts allowed within a specified time period, providing granular control over access restrictions.
•	When the maximum connection attempts threshold is exceeded, the server can automatically block the offending IP address and log the details of the incident.
8.	Customizable Network Configuration:
•	The server's network configuration, including the host and port numbers for each chess engine, can be easily customized through the config.json file.
•	This flexibility enables running multiple instances of the server with different chess engines on separate ports, facilitating scalability and resource allocation.
Configuration (config.json) The server's configuration is defined in the config.json file. Here's a detailed explanation of each configuration option:
•	host: The IP address or hostname on which the server listens for incoming connections. Set to "0.0.0.0" to listen on all available network interfaces.
•	base_log_dir: The directory where log files will be stored.
•	display_uci_communication: When set to true, the server will display the UCI communication between clients and chess engines in real-time on the console.
•	enable_trusted_sources: When set to true, the server will enforce access restrictions based on the trusted sources list.
•	enable_auto_trust: When set to true, the server will automatically add client IP addresses to the trusted sources list when they send the "uci" command.
•	enable_server_log: When set to true, the server will generate a log file named "server.log" to capture server events and exceptions.
•	enable_uci_log: When set to true, the server will generate separate log files for each chess engine, capturing the UCI communication between clients and engines.
•	detailed_log_verbosity: When set to true, the server will include detailed information in the logs, such as UCI commands and responses.
•	enable_firewall_subnet_blocking: When set to true, the server will automatically configure firewall rules to block untrusted subnet traffic.
•	enable_firewall_ip_blocking: When set to true, the server will automatically block individual IP addresses based on the specified connection attempt thresholds.
•	max_connection_attempts: Specifies the maximum number of connection attempts allowed from an untrusted IP address within the specified time period.
•	connection_attempt_period: Specifies the time period (in seconds) for monitoring connection attempts from untrusted IP addresses.
•	Log_untrusted_connection_attempts: When set to true, the server will log details of untrusted connection attempts in a separate log file.
•	custom_variables: Allows defining custom UCI options that will be sent to all chess engines upon initialization.
•	max_connections: Specifies the maximum number of concurrent client connections allowed by the server.
•	trusted_sources: A list of IP addresses that are allowed to connect to the server when enable_trusted_sources is set to true.
•	trusted_subnets: A list of IP subnets that are allowed to connect to the server when enable_trusted_sources is set to true.
•	engines: A dictionary specifying the configuration for each supported chess engine, including the engine's path, port number, and custom UCI options.

Getting Started To run the server, follow these steps:
1.	Ensure that you have Python 3.7 or later installed on your system.
2.	Configure the server by modifying the config.json file according to your setup. Specify the paths to your chess engine executables, desired ports, trusted sources, firewall settings, and other configuration options.
3.	Place the chess.py script in a directory of your choice and run it from the command line using the following command:
python chess.py

The server will start listening for incoming connections on the specified ports. You can now connect to the server using any UCI-compatible chess client or a telnet client.

modifying config.json
1.	host: Specifies the IP address or hostname on which the server listens for incoming connections. Set it to "0.0.0.0" to listen on all available network interfaces.
2.	base_log_dir: Specifies the directory where log files will be stored. Provide the desired path for storing the log files.
3.	display_uci_communication: Set it to true to display the UCI communication between clients and chess engines in real-time on the console. Set it to false to disable this feature.
4.	enable_trusted_sources: Set it to true to enforce access restrictions based on the trusted sources list. Only client IPs specified in the trusted_sources array will be allowed to connect to the server. Set it to false to disable this feature.
5.	enable_auto_trust: Set it to true to automatically add client IP addresses to the trusted sources list in config.json when they send the "uci" command during initialization. Set it to false to disable this feature.
6.	enable_server_log: Set it to true to generate a log file named "server.log" that captures server events and exceptions. Set it to false to disable server logging.
7.	enable_uci_log: Set it to true to generate separate log files for each chess engine, capturing the UCI communication between clients and engines. Set it to false to disable UCI logging.
8.	detailed_log_verbosity: Set it to true to include detailed information in the logs, such as UCI commands and responses. Set it to false to log only basic information.
9.	enable_firewall_subnet_blocking: Set it to true to automatically configure firewall rules to block untrusted subnet traffic. Set it to false to disable this feature.
10.	enable_firewall_ip_blocking: Set it to true to automatically block individual IP addresses based on the specified connection attempt thresholds. Set it to false to disable this feature.
11.	max_connection_attempts: Specifies the maximum number of connection attempts allowed from an untrusted IP address within the specified time period.
12.	connection_attempt_period: Specifies the time period (in seconds) for monitoring connection attempts from untrusted IP addresses.
13.	Log_untrusted_connection_attempts: Set it to true to log details of untrusted connection attempts in a separate log file. Set it to false to disable logging of untrusted connection attempts.
14.	custom_variables: Specifies custom UCI options that will be sent to all chess engines upon initialization. Provide key-value pairs for the desired options.
15.	max_connections: Specifies the maximum number of concurrent client connections allowed by the server.
16.	trusted_sources: An array of IP addresses that are allowed to connect to the server when enable_trusted_sources is set to true. Add the desired IP addresses to this array.
17.	trusted_subnets: An array of IP subnets that are allowed to connect to the server when enable_trusted_sources is set to true. Add the desired subnets in CIDR notation to this array.
18.	engines: A dictionary specifying the configuration for each supported chess engine.
•	path: Specifies the path to the chess engine executable.
•	port: Specifies the port number on which the engine will listen for incoming connections.
•	custom_variables (optional): Specifies custom UCI options specific to the engine. Provide key-value pairs for the desired options.
To configure the config.json file:
1.	Open the config.json file in a text editor.
2.	Update the values of the configuration options according to your requirements and environment.
3.	Ensure that the paths to the chess engine executables are correct and the engines are accessible.
4.	Save the config.json file after making the necessary changes.
5.	Place the config.json file in the same directory as the chess.py script.
6.	Run the chess.py script, and the server will start with the specified configuration.
Note: Make sure to escape backslashes (\) in file paths by using double backslashes (\\) in the JSON configuration.
Remember to restart the server after making changes to the config.json file for the new configuration to take effect.

Network configuration:
Your system router will need port forwarding enabled on the specified ports to forward traffic to the chess engine.

ChessServer.exe is a self-enclosed version of the Python script which should be able to run without installing Python.
The config.json will still need to be in the same directory as ChessServer.exe and config.json will need to be configured to your specific environment.

Conclusion This project seeks to provides a comprehensive and feature-rich server solution for interfacing with various chess engines over a network. With its extensive logging capabilities, advanced security features, and flexible configuration options, it offers a robust platform for managing and interacting with chess engines in a controlled and secure environment. Whether you are a chess enthusiast, a developer working on chess-related applications, or a researcher exploring the world of computer chess, this server provides a solid foundation for your endeavors.
