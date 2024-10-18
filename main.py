import sys
from Server import Server
from utils import readPort

def main():
    port = readPort()
    server = Server(port=port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("Shutting down server...")
    except Exception as e:
        print(f"Exception: {e}")
    finally:
        server.shutdown()
        print("Server shutdown complete.")
        sys.exit(0)

if __name__ == "__main__":
    main()
