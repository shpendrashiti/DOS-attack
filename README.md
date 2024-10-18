# DOS Attack Simulation and Detection

This project simulates and detects Denial of Service (DoS) attacks using Python. The detected attacks are logged into a CSV file, which is then analyzed in a Jupyter notebook.

## Dependencies

Before getting started, make sure to install the necessary dependencies. You can install them using pip:

pip install scapy requests pandas matplotlib cartopy

Usage Instructions
Attacker Machine

    Open a terminal.

    Run the attacks.py script using the following command:

    python3 attacks.py <target IP> <attack type> <attack duration>

    Replace <target IP> with the IP address of the victim machine, <attack type> with the desired attack type (syn_ack, smurf, syn_flood, pod), and <attack duration> with the duration in seconds.

Victim Machine

    Open another terminal.

    Launch the detection application with:

    python3 app.py

    Open your browser and navigate to http://127.0.0.1:5000.

    Click on the Start button to begin detecting attacks. This will log the data into the attack_logs.csv file, which is used by the Jupyter notebook.

Jupyter Notebook

    Open the notebook.ipynb file in Jupyter Notebook.
    Run each cell by clicking "Run" or pressing Shift + Enter.
    The cells will analyze the data contained in attack_logs.csv and produce relevant visualizations.
