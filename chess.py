import asyncio
import json
import logging
import os
import signal
import subprocess
import time
import ipaddress

# Load configurations from config.json
with open("config.json") as f:
    config = json.load(f)

HOST = config["host"]
BASE_LOG_DIR = config["base_log_dir"]
ENGINES = config["engines"]
CUSTOM_VARIABLES = config["custom_variables"]
MAX_CONNECTIONS = config["max_connections"]

# Configure logging
if config["enable_server_log"]:
    server_log_file = os.path.join(BASE_LOG_DIR, "server.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(server_log_file),
            logging.StreamHandler()
        ]
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )
sem = asyncio.Semaphore(MAX_CONNECTIONS)

async def watchdog_timer(interval):
    while True:
        await asyncio.sleep(interval)
        logging.info("Watchdog timer: Server is responsive")

async def heartbeat(writer, interval):
    while True:
        try:
            writer.write(b"\nping\n")
            await writer.drain()
            await asyncio.sleep(interval)
        except Exception as e:
            logging.error(f"Heartbeat error: {e}")
            break

async def engine_communication(engine_process, writer, log_file):
    while True:
        try:
            data = await asyncio.wait_for(engine_process.stdout.readline(), timeout=30)
            if not data:
                break

            log_message = f"Engine: {data.decode().strip()}\n"
            logging.info(log_message)

            writer.write(data)
            await writer.drain()

            with open(log_file, "a") as f:
                f.write(log_message)
        except asyncio.TimeoutError:
            logging.warning("Engine communication timeout")
            break
        except Exception as e:
            logging.error(f"Engine communication error: {e}")
            break
            
            

async def client_handler(reader, writer, engine_path, log_file, engine_name):
    client_ip = writer.get_extra_info('peername')[0]
    logging.info(f"Connection opened from {client_ip}")
    print(f"Connection opened from {client_ip}")

    last_activity_time = time.time()  # Initialize last activity time
    
    async def check_inactivity():
        nonlocal last_activity_time
        while True:
            await asyncio.sleep(60)  # Check every minute
            if time.time() - last_activity_time > 900:  # 15 minutes of inactivity
                logging.warning(f"Connection to {client_ip} closed due to inactivity.")
                writer.close()
                await writer.wait_closed()
                return
    
    inactivity_task = asyncio.create_task(check_inactivity())

    # Check if the client IP is in the blocklist
    blocklist_file = os.path.join(BASE_LOG_DIR, "blocklist.txt")
    if config["enable_blocklist"] and os.path.isfile(blocklist_file):
        with open(blocklist_file, "r") as f:
            blocklist = f.read().splitlines()
            if client_ip in blocklist:
                logging.warning(f"Blocked connection attempt from {client_ip}")
                print(f"Blocked connection attempt from {client_ip}")
                writer.close()
                await writer.wait_closed()
                return

    # Check if the client IP belongs to any of the trusted subnets
    is_trusted_subnet = any(
        ipaddress.ip_address(client_ip) in ipaddress.ip_network(subnet)
        for subnet in config["trusted_subnets"]
    )

    if config["enable_trusted_sources"] and not is_trusted_subnet and client_ip not in config["trusted_sources"]:
        try:
            data = await reader.readline()
            try:
                decoded_data = data.decode().strip()
                if decoded_data == "uci":
                    if config["enable_auto_trust"]:
                        config["trusted_sources"].append(client_ip)
                        with open("config.json", "w") as f:
                            json.dump(config, f, indent=2)
                        logging.info(f"Added {client_ip} to trusted sources")
                        print(f"Added {client_ip} to trusted sources")
                    else:
                        logging.warning(f"Auto-trusting disabled. Connection attempt from {client_ip}")
                        print(f"Auto-trusting disabled. Connection attempt from {client_ip}")
                        writer.close()
                        await writer.wait_closed()
                        logging.info(f"Connection closed for untrusted source {client_ip}")
                        print(f"Connection closed for untrusted source {client_ip}")
                        # Add the untrusted IP to the blocklist
                        if config["enable_blocklist"]:
                            with open(blocklist_file, "a") as f:
                                f.write(f"{client_ip}\n")
                        return
                else:
                    logging.warning(f"Untrusted connection attempt from {client_ip}")
                    print(f"Untrusted connection attempt from {client_ip}")
                    writer.close()
                    await writer.wait_closed()
                    logging.info(f"Connection closed for untrusted source {client_ip}")
                    print(f"Connection closed for untrusted source {client_ip}")
                    # Add the untrusted IP to the blocklist
                    if config["enable_blocklist"]:
                        with open(blocklist_file, "a") as f:
                            f.write(f"{client_ip}\n")
                    return
            except UnicodeDecodeError:
                logging.warning(f"Received invalid data from {client_ip}")
                print(f"Received invalid data from {client_ip}")
                writer.close()
                await writer.wait_closed()
                return
        except ConnectionResetError:
            logging.warning(f"Connection reset by untrusted source {client_ip}")
            print(f"Connection reset by untrusted source {client_ip}")
            writer.close()
            await writer.wait_closed()
            return

    async with sem:
        try:
            engine_dir = os.path.dirname(engine_path)
            logging.info(f"Initiating engine {engine_path} for client {client_ip}")
            print(f"Initiating engine {engine_path} for client {client_ip}")

            engine_process = await asyncio.create_subprocess_exec(
                engine_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=engine_dir
            )
            
            # Start heartbeat
            heartbeat_task = asyncio.create_task(heartbeat(writer, 300))

            async def process_command(command):
                try:
                    engine_process.stdin.write(f"{command}\n".encode())
                    await engine_process.stdin.drain()
                    if config["enable_uci_log"]:
                        with open(log_file, "a") as f:
                            f.write(f"Client: {command}\n")
                    if config["detailed_log_verbosity"]:
                        print(f"Client: {command}")
                except Exception as e:
                    logging.error(f"Error processing command: {e}")

            async def process_uci_command():
                await process_command("uci")

                # Send all custom UCI options
                for option_name, option_value in ENGINES[engine_name].get("custom_variables", {}).items():
                    await process_command(f"setoption name {option_name} value {option_value}")

                while True:
                    data = await engine_process.stdout.readline()
                    if not data:
                        break
                    decoded_data = data.decode().strip()
                    writer.write(data)
                    await writer.drain()
                    if config["enable_uci_log"]:
                        with open(log_file, "a") as f:
                            f.write(f"Engine: {decoded_data}\n")
                    if config["detailed_log_verbosity"]:
                        print(f"Engine: {decoded_data}")
                    if "uciok" in decoded_data:
                        break

            await process_uci_command()

            async def process_client_commands():
                while True:
                    data = await reader.readline()
                    if not data:
                        break

                    client_data = data.decode().strip()
                    commands = client_data.split('\n')

                    for command in commands:
                        command = command.strip()
                        if command:
                            if command.startswith('setoption name'):
                                parts = command.split(' ')
                                if len(parts) >= 5 and parts[1] == 'name' and parts[3] == 'value':
                                    option_name = parts[2]
                                    option_value = ' '.join(parts[4:])
                                    if option_name in ENGINES[engine_name].get("custom_variables", {}):
                                        if ENGINES[engine_name]["custom_variables"][option_name] == "override":
                                            await process_command(command)
                                        else:
                                            modified_command = f"setoption name {option_name} value {ENGINES[engine_name]['custom_variables'][option_name]}"
                                            await process_command(modified_command)
                                    elif option_name in CUSTOM_VARIABLES:
                                        modified_command = f"setoption name {option_name} value {CUSTOM_VARIABLES[option_name]}"
                                        await process_command(modified_command)
                                    else:
                                        await process_command(command)
                                else:
                                    await process_command(command)
                            else:
                                await process_command(command)

            async def process_engine_responses():
                while True:
                    data = await engine_process.stdout.readline()
                    if not data:
                        break
                    decoded_data = data.decode().strip()
                    writer.write(data)
                    await writer.drain()
                    if config["enable_uci_log"]:
                        with open(log_file, "a") as f:
                            f.write(f"Engine: {decoded_data}\n")
                    if config["detailed_log_verbosity"]:
                        print(f"Engine: {decoded_data}")

            await asyncio.gather(process_client_commands(), process_engine_responses())

        except ConnectionResetError:
            logging.info(f"Client {client_ip} disconnected")
            print(f"Client {client_ip} disconnected")
        except asyncio.TimeoutError:
            logging.warning(f"Connection timeout for client {client_ip}")
            print(f"Connection timeout for client {client_ip}")
        except Exception as e:
            logging.error(f"Error in client_handler for client {client_ip}: {e}")
            print(f"Error in client_handler for client {client_ip}: {e}")

        finally:
            inactivity_task.cancel()
            heartbeat_task.cancel()
            engine_process.terminate()
            await engine_process.wait()
            writer.close()
            await writer.wait_closed()
            logging.info(f"Connection closed for client {client_ip}")
            print(f"Connection closed for client {client_ip}")
            
            engine_process.terminate()
            await engine_process.wait()  # Ensure the engine process is properly terminated
            
            

async def start_server(host, port, engine_path, log_file, engine_name):
    retries = 5  # Set a retry limit
    while retries > 0:
        try:
            server = await asyncio.start_server(
                lambda r, w: client_handler(r, w, engine_path, log_file, engine_name),
                host, port)

            addr = server.sockets[0].getsockname()
            logging.info(f"Server listening on {addr} for engine {engine_path}")

            async with server:
                await server.serve_forever()
            break  # Exit loop if server started successfully

        except asyncio.CancelledError:
            logging.info("Server shutdown initiated")
            break
        except Exception as e:
            retries -= 1
            logging.error(f"Error starting server for engine {engine_name}: {e}")
            if retries > 0:
                logging.info("Retrying in 5 seconds...")
                await asyncio.sleep(5)
            else:
                logging.error("Maximum retries reached. Exiting...")
                break




async def main():
    if not os.path.exists(BASE_LOG_DIR):
        os.makedirs(BASE_LOG_DIR)

    tasks = []
    for engine_name, details in ENGINES.items():
        log_file = os.path.join(BASE_LOG_DIR, f"communication_log_{engine_name}.txt")
        task = asyncio.create_task(start_server(HOST, details["port"], details["path"], log_file, engine_name))
        tasks.append(task)
        logging.info(f"Started server for {engine_name} on port {details['port']}")

    # Start watchdog timer
    watchdog_task = asyncio.create_task(watchdog_timer(300))  # Check every 5 minutes

    # Set up signal handlers for graceful shutdown
    shutdown_event = asyncio.Event()

    def signal_handler():
        logging.info("Shutdown signal received")
        shutdown_event.set()

    signal.signal(signal.SIGINT, lambda *_: signal_handler())
    signal.signal(signal.SIGTERM, lambda *_: signal_handler())

    try:
        await shutdown_event.wait()
    except asyncio.CancelledError:
        pass

    logging.info("Initiating graceful shutdown...")
    watchdog_task.cancel()
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    logging.info("Server shutdown completed")

if __name__ == "__main__":
    asyncio.run(main())
