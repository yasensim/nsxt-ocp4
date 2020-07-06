import requests
import sys
import json

nsx = "10.114.209.47"
pw = "VMwareVMware1!"
cluster_name = "ocp"
segment = "ocp4-segment"
vm_list = ['compute-0', 'compute-1', 'compute-2', 'control-plane-0',
           'control-plane-1', 'control-plane-2']

headers = {
    'Content-Type': 'application/json',
    'X-Allow-Overwrite': 'true'
}

data = ""
response = requests.get('https://%s/policy/api/v1/infra/segments/%s/ports' % (nsx, segment),
                        headers=headers, data=data, verify=False,
                        auth=('admin', pw))
if not response:
    print("Something bad happened during GET")
    sys.exit(1)

for item in json.loads(response.text).get('results', []):
    existing_vm = (item['display_name'].split("/", 1))[0]
    if existing_vm in vm_list:
        print(existing_vm)
        item.pop('status', None)
        item['tags'] = [{"scope": "ncp/node_name", "tag": existing_vm},
                        {"scope": "ncp/cluster", "tag": cluster_name}]
        response = requests.put(
            'https://%s/policy/api/v1/infra/segments/%s/ports/%s' % (nsx, segment, item['id']),
            headers=headers, data=json.dumps(item), verify=False,
            auth=('admin', pw))
        print(response.status_code)
        if not response:
            print(response.text)
