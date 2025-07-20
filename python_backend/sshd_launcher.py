import subprocess
import os

def launch_sshd():
    sshd_path = os.path.realpath("./sshd")
    hostkey_path = os.path.realpath("./host.ssh-mldsa65")
    config_path = os.path.realpath("./regress/sshd_config")

    cmd = [
        sshd_path,
        "-D",
        "-f", config_path,
        "-o", "Port=2222",
        "-o", f"HostKey={hostkey_path}",
        "-o", "KexAlgorithms=kyber-768-sha384",
        "-o", "HostKeyAlgorithms=ssh-mldsa65"
    ]

    try:
        print("[INFO] Launching SSHD with post-quantum options...")
        subprocess.Popen(cmd)
    except Exception as e:
        print(f"[ERROR] Failed to launch sshd: {e}")
