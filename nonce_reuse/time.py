import pandas as pd

# Ganti dengan nama file CSV Anda
filenames = {
    "amount": "nonce_forensic_amount_500k.csv",
    "random": "nonce_forensic_random_500k.csv",
    "bit-flip": "nonce_forensic_bit-flip_500k.csv"
}

print("| Mode | Throughput (sig/s) | Latency (µs) |")
print("|:---|---:|---:|")

for mode, filename in filenames.items():
    try:
        df = pd.read_csv(filename)
        # Latensi adalah rata-rata waktu penandatanganan
        avg_latency_microseconds = df['signing_time_microseconds'].mean()
        # Throughput adalah 1 detik (1,000,000 µs) dibagi rata-rata latensi
        throughput_sps = 1_000_000 / avg_latency_microseconds
        
        print(f"| {mode} | {throughput_sps:.2f} | {avg_latency_microseconds:.2f} |")
    except FileNotFoundError:
        print(f"| {mode} | FILE NOT FOUND | FILE NOT FOUND |")