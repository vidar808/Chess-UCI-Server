import socket
import subprocess
import threading
import os

def engine_communication(engine_process, client_connection, log_file):
    try:
        while True:
            data = engine_process.stdout.readline()
            if not data:
                break
            log_message = f"Engine: {data.strip()}\n"
            print(log_message, end='')
            client_connection.sendall(data.encode('utf-8'))
            with open(log_file, "a") as f:
                f.write(log_message)
    except Exception as e:
        print(f"Error communicating with client: {e}")
    finally:
        client_connection.close()

def client_handler(client_socket, engine_path, log_file):
    try:
    
        engine_dir = os.path.dirname(engine_path)
        
        engine_process = subprocess.Popen(
            [engine_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            cwd=os.path.dirname(engine_path)  # Set the working directory to the engine's directory
        )

        def engine_to_client():
            engine_communication(engine_process, client_socket, log_file)

        engine_thread = threading.Thread(target=engine_to_client)
        engine_thread.start()

        engine_process.stdin.write("uci\n")
        engine_process.stdin.flush()

        while True:
            client_data = client_socket.recv(1024).decode('utf-8').strip()
            if not client_data:
                break

            log_message = f"Client: {client_data}\n"
            print(log_message, end='')
            engine_process.stdin.write(f"{client_data}\n")
            engine_process.stdin.flush()
            with open(log_file, "a") as f:
                f.write(log_message)

    except Exception as e:
        print(f"Error in client_handler: {e}")
    finally:
        engine_process.terminate()
        client_socket.close()

def start_server(host, port, engine_path, log_file):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port} for engine {engine_path}")

        while True:
            client_connection, _ = server_socket.accept()
            threading.Thread(target=client_handler, args=(client_connection, engine_path, log_file), daemon=True).start()

def main():
    HOST = '0.0.0.0'
    base_log_dir = r"C:\Users\administrator\Desktop\chess\LOG"
    engines = {
        "Dragon": {"path": r"C:\Users\administrator\Desktop\chess\dragon-3.3_fb79bacb\Windows\dragon-3.3-64bit-avx2.exe", "port": 9999},
        "Stockfish": {"path": r"C:\Users\administrator\Desktop\chess\stockfish 16\stockfish_24021119_x64_avx2.exe", "port": 9998},
        "Berserk": {"path": r"C:\Users\administrator\Desktop\chess\berserk 12.1\berserk-12-x64-avx2.exe", "port": 9997},
        "Tal": {"path": r"C:\Users\administrator\Desktop\chess\Chess-System-Tal-2.00-v21\Chess-System-Tal-2.00-v21-E1162-130-EAS.opt-avx2.exe", "port": 9996},
        "Shash": {"path": r"C:\Users\administrator\Desktop\chess\ShashChess 34\ShashChess34.6-x86-64-bmi2.exe", "port": 9995},
        "Ethereal": {"path": r"C:\Users\administrator\Desktop\chess\Ethereal 14.2\Windows\Ethereal-14.25-avx2.exe", "port": 9994},
        "Caissa": {"path": r"C:\Users\administrator\Desktop\chess\Caissa 1.15\Caissa 1.15\caissa-1.15-x64-avx2-bmi2.exe", "port": 9993},
        "Rubi": {"path": r"C:\Users\administrator\Desktop\chess\RubiChess-20240112\windows\RubiChess-20240112_x86-64-bmi2.exe", "port": 9992},
    }

    if not os.path.exists(base_log_dir):
        os.makedirs(base_log_dir)

    threads = []
    for i, (engine_name, details) in enumerate(engines.items(), start=1):
        log_file = os.path.join(base_log_dir, f"communication_log_{engine_name}.txt")
        thread = threading.Thread(target=start_server, args=(HOST, details["port"], details["path"], log_file), daemon=True)
        thread.start()
        threads.append(thread)
        print(f"Started server for {engine_name} on port {details['port']}")

    for thread in threads:
        thread.join()  # Wait for all server threads to finish (they won't unless manually stopped)

if __name__ == "__main__":
    main()
