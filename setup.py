# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['at_client',
 'at_client.common',
 'at_client.connections',
 'at_client.connections.notification',
 'at_client.exception',
 'at_client.util']

package_data = \
{'': ['*']}

install_requires = \
['cffi==1.16.0',
 'cryptography==41.0.5',
 'pycparser==2.21',
 'python-dateutil==2.8.2',
 'requests==2.31.0',
 'six==1.16.0']

setup_kwargs = {
    'name': 'at_python',
    'version': '0.0.2',
    'description': 'Python SDK for atPlatform',
    'long_description': '<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">\n\n[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_python/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_python)\n\n# The atPlatform for Python developers - (Alpha Version)\n\nThis repo contains library, samples and examples for developers who wish\nto work with the atPlatform from Python code.\n\n## Getting Started\n### 1. Installation\n```\npip install -r requirements.txt\npip install .\n```\n\n\n\n### 2. Setting up your `.atKeys`\nTo run the examples save .atKeys file in the \'~/.atsign/keys/\' directory.\n\n### 3. Sending and Receiving Data\nThere are 3 ways in which data can be sent and received from at server.\n1. Using PublicKey\n    ```python\n    from at_client import AtClient\n    from at_client.common import AtSign\n    from at_client.common.keys import PublicKey\n\n    atsign = AtSign("@bob")\n    atclient = AtClient(atsign)\n    pk = PublicKey("key", atsign)\n\n    # Sending data\n    response = atclient.put(pk, "value")\n    print(response)\n\n    # Receiving Data\n    response = atclient.get(pk)\n    print(response)\n\n    # Deleting data\n    response = atclient.delete(pk)\n    print(response)\n\n    ```\n\n2. Using SelfKey\n    ```python\n    from at_client import AtClient\n    from at_client.common import AtSign\n    from at_client.common.keys import SelfKey\n\n    atsign = AtSign("@bob")\n    atclient = AtClient(atsign)\n    sk = SelfKey("key", atsign)\n\n    # Sending data\n    response = atclient.put(sk, "value")\n    print(response)\n\n    # Receiving Data\n    response = atclient.get(sk)\n    print(response)\n\n    # Deleting data\n    response = atclient.delete(sk)\n    print(response)\n\n    ```\n\n3. Using SharedKey\n    ```python\n    from at_client import AtClient\n    from at_client.common import AtSign\n    from at_client.common.keys import SharedKey\n\n    bob = AtSign("@bob")\n    alice = AtSign("@alice")\n    bob_atclient = AtClient(bob)\n    sk = SharedKey("key", bob, alice)\n\n    # Sending data\n    response = bob_atclient.put(sk, "value")\n    print(response)\n\n    # Receiving Data\n    alice_atclient = AtClient(alice)\n    response = alice_atclient.get(sk)\n    print(response)\n\n    # Deleting data\n    response = bob_atclient.delete(sk)\n    print(response)\n\n    ```\n\n\t\n### CLI Tools\n* **REPL** - you can use this to type atPlatform commands and see responses; but the best thing about the REPL currently is that it shows the data notifications as they are received. The REPL code has the essentials of what a \'receiving\' client needs to do - i.e.\n\t* create an AtClient (assigning a Queue object to its queue parameter)\n\t* start two new threads\n        * one for the AtClient.start_monitor() task: receives data update/delete notification events (the event data contains the ciphertext)\n        * the other one calls handle_event() method, which will read the upcoming events in the queue and handle them: \n\t\t\t* calling AtClient.handle_event() (to decrypt the notifications and introducing the result as a new event in the queue) \n\t\t\t* reading the new event, which contains the decrypted result \n\t* Instructions to run the REPL:\n\t\t1) Run repl.py and choose an atSign using option `1`\n\t\t2) Select option `2`. REPL will start and activate monitor mode automatically in a different thread. You can still send commands/verbs. You will start seeing your own notifications (from yourself to yourself) and heartbeat working (noop verb is sent from time to time as a keepalive)\n\t\t3) Use `at_talk` or any other tool to send notifications to your atSign from a different atSign. You should be able to see the complete notification, and the encrypted and decrypted value of it.\n\n* **REGISTER** - use this cli to register new free atsign. Uses onboarding cli to create atkey files.\n\t* Use following command to run the REGISTER cli using email:\n\t\t```shell\n        python register.py -e <email>\n        ```\n    * Use following command to run the REGISTER cli using api-key:\n\t\t```shell\n        python register.py -k <api-key>\n        ```\n\n* **ONBOARDING** - use this cli to onboard a new atSign. Once onboarding is complete it creates the all-important keys file. Onboard is a subset of Register.\n\t* Use following command to run the ONBOARDING cli:\n\t\t```shell\n        python onboarding.py -a <atsign> -c <cram-secret>\n        ```\n\n* **SHARE** - use this cli to share data between 2 atsigns.\n\t* Use following command to run the SHARE cli:\n\t\t```shell\n        python share.py -a <atsign> -o <other-atsign> -k <key-name> -s <value>\n        ```\n\n* **GET** - use this cli to get shared data between 2 atsigns.\n\t* Use following command to run the GET cli:\n\t\t```shell\n        python get.py -a <atsign> -o <other-atsign> -k <key-name>\n        ```\n\n* **DELETE** - use this cli to delete any key shared between 2 atsigns.\n\t* Use following command to run the DELETE cli:\n\t\t```shell\n        python delete.py -a <atsign> -o <other-atsign> -k <key-name>\n        ```\n\n## Open source usage and contributions\n\nThis is open source code, so feel free to use it as is, suggest changes or\nenhancements or create your own version. See [CONTRIBUTING.md](./CONTRIBUTING.md)\nfor detailed guidance on how to setup tools, tests and make a pull request.\n\n## Maintainers\n\nThis project is created and maintained by [Umang Shah](https://github.com/shahumang19)\n',
    'author': 'Umang Shah',
    'author_email': 'shahumang19@gmail.com',
    'maintainer': 'Chris Swan',
    'maintainer_email': '@cpswan',
    'url': 'https://github.com/atsign-foundation/at_python',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'python_requires': '>=3.8.1,<4.0.0',
}


setup(**setup_kwargs)

