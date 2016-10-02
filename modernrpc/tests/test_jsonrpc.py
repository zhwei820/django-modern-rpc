# coding: utf-8
import json
import requests
import sys


def send_jsonrpc_request(url, method, params=(), req_id=42, return_json=True):
    """Helper used to simulate a JSON-RPC request"""
    headers = {'content-type': 'application/json'}
    payload = {
        "method": method,
        "params": params,
        "jsonrpc": "2.0",
        "id": req_id,
    }
    req_data = json.dumps(payload)
    response = requests.post(url, data=req_data, headers=headers)
    if return_json:
        return response.json()
    return response


def test_basic_add(live_server):

    response = send_jsonrpc_request(live_server.url + '/all-rpc/', 'add', [2, 3], req_id=45)

    assert response['id'] == 45
    assert response['jsonrpc'] == '2.0'
    assert response['result'] == 5