import os
import subprocess
import time
import signal

# Full paths to Kafka and Zookeeper
KAFKA_PATH = r"C:\kafka"
ZOOKEEPER_CMD = [os.path.join(KAFKA_PATH, "bin", "windows", "zookeeper-server-start.bat"), os.path.join(KAFKA_PATH, "config", "zookeeper.properties")]
KAFKA_CMD = [os.path.join(KAFKA_PATH, "bin", "windows", "kafka-server-start.bat"), os.path.join(KAFKA_PATH, "config", "server.properties")]

# Update paths to scripts inside the "Scripts" folder
PACKET_SNIFFER_CMD = ["python", os.path.join("traffic_sniffer.py")]
FEATURE_EXTRACTOR_CMD = ["python", os.path.join("feature_extractor.py")]

processes = []  # Store process objects for cleanup

def start_process(command, wait_time=0):
    """Starts a subprocess and optionally waits."""
    process = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_CONSOLE)
    processes.append(process)  # Track process
    if wait_time:
        time.sleep(wait_time)
    return process

def kill_processes_using_port(port):
    """Kills processes using the specified port, ignoring system processes."""
    try:
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, shell=True)
        lines = result.stdout.splitlines()

        pids = set()
        for line in lines:
            if f":{port}" in line:
                parts = line.split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) > 4:  # Ignore System PIDs (0, 4)
                        pids.add(pid)

        for pid in pids:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", pid], check=True)
                print(f"✅ Killed process {pid} on port {port}.")
            except subprocess.CalledProcessError as e:
                if "Access is denied" in str(e):
                    print(f"⚠️ Access denied to kill PID {pid}. Run as Administrator.")
                else:
                    print(f"❌ Error killing PID {pid}: {e}")
    except Exception as e:
        print(f"❌ Error checking/killing processes on port {port}: {e}")

def cleanup():
    """Kills all running processes."""
    print("\n🛑 Shutting down the system...")

    for process in processes:
        try:
            if process.poll() is None:  # Process is still running
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], check=True)
        except Exception as e:
            print(f"❌ Error stopping process {process.pid}: {e}")

    # Kill Kafka and Zookeeper, ignoring system processes
    kill_processes_using_port(9092)  # Kafka
    kill_processes_using_port(2181)  # Zookeeper

    print("✅ System stopped.")

if __name__ == "__main__":
    print("🚀 Starting the DDoS Detection System...")

    # Ensure no conflicting processes are running
    kill_processes_using_port(2181)  # Zookeeper
    kill_processes_using_port(9092)  # Kafka

    # Start components
    print("🟢 Starting Zookeeper...")
    start_process(ZOOKEEPER_CMD, wait_time=5)

    print("🟡 Starting Kafka server...")
    start_process(KAFKA_CMD, wait_time=10)

    print("📡 Starting Packet Sniffer...")
    start_process(PACKET_SNIFFER_CMD, wait_time=2)

    print("📊 Starting Feature Extractor...")
    start_process(FEATURE_EXTRACTOR_CMD)

    print("✅ All components running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()
