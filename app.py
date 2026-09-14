import webview
import threading
import uvicorn
import time
from api import app  # Imports the FastAPI app Claude just wrote

def run_server():
    # Runs your backend engine quietly in the background
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="critical")

if __name__ == '__main__':
    # 1. Start the FastAPI server in a background thread
    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    # Give the server a split second to boot up
    time.sleep(1)

    # 2. Open the native desktop application window
    webview.create_window(
        title='Crypto Forensics Triage', 
        url='http://127.0.0.1:8000', 
        width=1280, 
        height=850,
        min_size=(1000, 700)
    )
    
    # Start the desktop app loop
    webview.start()