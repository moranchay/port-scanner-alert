# Port Scanner Alert

A fast, multithreaded Python port scanner that monitors open ports, compares them to a stored baseline, and alerts you to changes. Perfect for learning networking, Python, and system monitoring.


## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)


## Features

*   **Multithreaded Scanning:**  Quickly scans ports using multiple threads for enhanced speed.
*   **Flexible Scanning Options:** Scan single ports, custom ranges, or all 65,535 TCP ports.
*   **Baseline Comparison:** Compares current scan results against a stored baseline to identify changes.
*   **Automated Baseline Creation:** Automatically generates a baseline on the first run.
*   **Optional Baseline History:**  Maintain a timestamped history of previous baselines (configurable).
*   **Clear Alerts:**  Provides notifications for newly opened and closed ports.
*   **Simple CLI Usage:** Easy-to-understand command-line interface.


## Requirements

*   Python 3.6 or higher
*   `pip` (Python package installer)


## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/yourusername/port-scanner-baseline.git
    cd port-scanner-baseline
    ```

2.  Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```


## Usage

The script uses command-line arguments to control its behavior.  Here are some examples:

* **Scan all ports on a target:**

    ```bash
    python scanner.py --all --target 192.168.1.10
    ```

* **Scan a specific port range on a target:**

    ```bash
    python scanner.py --range 22-443 --target 192.168.1.10
    ```

* **Update the baseline and keep historical data:**

    ```bash
    python scanner.py --update-baseline --keep-history
    ```

* **Update the baseline with a specified number of threads:**

    ```bash
    python scanner.py --update-baseline --keep-history --threads 400
    ```

* **Scan default ports (configurable in the script):**

    ```bash
    python scanner.py --target 192.168.1.10
    ```

For a complete list of options and detailed explanations, refer to the help message by running:

```bash
python scanner.py --help
```


## Contributing

Contributions are welcome! Please open an issue or submit a pull request.  Ensure your code adheres to the project's coding style and includes comprehensive tests.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


