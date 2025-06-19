# DNS Server

A DNS server written in Python that checks DNS queries against a PostgreSQL table. If the requested address or IP exists in the database, the server responds with the record. If not, it forwards the query to an upstream DNS server (8.8.8.8) to fetch an answer.

## Features

- Answers DNS queries from a local PostgreSQL database.
- Forwards requests to 8.8.8.8 if an entry is not found in the database.
- Built using Python and Scapy.

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- [psycopg2](https://www.psycopg.org/) (or another PostgreSQL driver for Python)
- A running PostgreSQL instance with the appropriate DNS records table.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/rotemgabbai/dns_server.git
    cd dns_server
    ```

2. Install required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3. Set up your PostgreSQL database and ensure your connection details are configured in the project (see the code for configuration details).

## Usage

1. Start the DNS server:
    ```bash
    python server.py
    ```

2. Send DNS packets to port `5353` on the server.

    You can use `dig`, `nslookup`, or any DNS client, for example:
    ```bash
    dig @localhost -p 5353 example.com
    ```

## Configuration

- The server expects a PostgreSQL table with DNS records. Please refer to the source code for the expected schema and connection configuration.
- The upstream DNS server is set to `8.8.8.8` by default.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](LICENSE)

## Contact

For questions or support, please open an issue in this repository.