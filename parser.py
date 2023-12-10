import argparse
import os
import requests
import shutil
import sys


def download_rules(path):
    dir_rules = os.path.join(path, 'rules')
    dir_capa = os.path.join(dir_rules, 'capa')
    dir_sigma = os.path.join(dir_rules, 'sigma')
    dir_yara = os.path.join(dir_rules, 'yara')

    def __get_filename(rule_type, rule_key):
        table = {
            'CAPA': {'dir': dir_capa, 'ext': '.yaml'},
            'SIGMA': {'dir': dir_sigma, 'ext': '.yaml'},
            'YARA': {'dir': dir_yara, 'ext': '.yara'},
        }
        return os.path.join(table[rule_type]['dir'], rule_key + table[rule_type]['ext'])
    
    try:
        if os.path.exists(dir_rules):
            shutil.rmtree(dir_rules)
            
        os.mkdir(dir_rules)
        os.mkdir(dir_capa)
        os.mkdir(dir_sigma)
        os.mkdir(dir_yara)
    except OSError as error:
        print(error)
        sys.exit()

    url = 'https://unprotect.it/api/detection_rules/'
    while True:
        try:
            response = requests.api.get(url)
            response.raise_for_status()
        except requests.exceptions.RequestException as error:
            print(error)
            sys.exit()

        data = response.json()

        count = data['count']
        print(f'Rules count: {count}')
        
        results = data['results']
        for result in results:
            rule_id = result['id']
            rule_key = result['key']
            rule_type = result['type']['name']
            rule_name = result['name']
            rule = result['rule']

            print(f'rule_id:   {rule_id}')
            print(f'rule_type: {rule_type}')
            print(f'rule_key: {rule_key}')
            print('\n')

            with open(__get_filename(rule_type, rule_key), 'w') as rule_file:
                rule_file.write(rule.replace('\r\n', '\n'))

        url = data['next']  
        if not url:
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Downloads rules from unprotect.it')
    parser.add_argument('-p', "--path", dest='path', type=str, default=os.getcwd(), required=False, help='path to save rules')
    args = parser.parse_args()
    download_rules(args.path)
