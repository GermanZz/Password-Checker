import requests
import hashlib
import sys


def req_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again!')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash_, count in hashes:
        if hash_ == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('UTF-8')).hexdigest().upper()
    first5chars, tail = sha1password[:5], sha1password[5:]
    response = req_api_data(first5chars)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...You should change it!')
        else:
            print(f'{password} was not found. Carry on!')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
