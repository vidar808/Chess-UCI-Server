import asyncio
import json
import logging
import os
import subprocess

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

async def engine_communication(engine_process, writer, log_file):
    while True:
        data = await engine_process.stdout.readline()
        if not data:
            break

        log_message = f"Engine: {data.decode().strip()}\n"
        logging.info(log_message)

        writer.write(data)
        await writer.drain()

        with open(log_file, "a") as f:
            f.write(log_message)

async def client_handler(reader, writer, engine_path, log_file):
    client_ip = writer.get_extra_info('peername')[0]
    logging.info(f"Connection opened from {client_ip}")

    if config["enable_trusted_sources"] and client_ip not in config["trusted_sources"]:
        logging.warning(f"Untrusted connection attempt from {client_ip}")
        print(f"Untrusted connection attempt from {client_ip}")
        writer.close()
        logging.info(f"Connection closed for untrusted source {client_ip}")
        return

    async with sem:
        try:
            engine_dir = os.path.dirname(engine_path)
            logging.info(f"Initiating engine {engine_path} for client {client_ip}")

            engine_process = await asyncio.create_subprocess_exec(
                engine_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=engine_dir
            )

            async def process_command(command):
                engine_process.stdin.write(f"{command}\n".encode())
                await engine_process.stdin.drain()
                if config["enable_uci_log"]:
                    with open(log_file, "a") as f:
                        f.write(f"Client: {command}\n")
                if config["enable_console_communication"]:
                    print(f"Client: {command}")

            async def process_uci_command():
                await process_command("uci")
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
                    if config["enable_console_communication"]:
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
                                    if option_name in CUSTOM_VARIABLES:
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
                    if config["enable_console_communication"]:
                        print(f"Engine: {decoded_data}")

            await asyncio.gather(process_client_commands(), process_engine_responses())

        except ConnectionResetError:
            logging.info(f"Client {client_ip} disconnected")
        except Exception as e:
            logging.error(f"Error in client_handler for client {client_ip}: {e}")

        finally:
            engine_process.terminate()
            await engine_process.wait()
            writer.close()
            logging.info(f"Connection closed for client {client_ip}")
            
            

async def start_server(host, port, engine_path, log_file):
    server = await asyncio.start_server(
        lambda r, w: client_handler(r, w, engine_path, log_file),
        host, port)

    addr = server.sockets[0].getsockname()
    logging.info(f"Server listening on {addr} for engine {engine_path}")

    async with server:
        await server.serve_forever()

async def main():
    if not os.path.exists(BASE_LOG_DIR):
        os.makedirs(BASE_LOG_DIR)

    tasks = []
    for engine_name, details in ENGINES.items():
        log_file = os.path.join(BASE_LOG_DIR, f"communication_log_{engine_name}.txt")
        task = asyncio.create_task(start_server(HOST, details["port"], details["path"], log_file))
        tasks.append(task)
        logging.info(f"Started server for {engine_name} on port {details['port']}")

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
