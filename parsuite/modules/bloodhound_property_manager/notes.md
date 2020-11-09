# Purpose

This module allows us to modify the properties associated with
objects described in the JSON files that are consumed by BloodHound (BH)
to produce graphs.

# Justification

Manually updating hundreds of nodes to "owned" is a huge inconvenience
from the interface. There may be a Cypher Query to do update properties
programmatically but I'm a noob and prefer python to that stuff.

# When to Use This Module

You're usually going to use this module after you've cracked a bunch
of passwords or compromised a ton of hosts. It'll allow you to update
each affected object and configure it to be revealed as "owned" in the BH
interface.

# How it Works

The JSON structure returned by BloodHound ingestors are well formed and
predictable, making it quite easy to add/update properties. Below is a
truncated example from a valid JSON file:

_Note:_ Do not take this example to heart in terms of property values.
Inspect your own BH ingestor output for more information there. There
are many other components to an object but this module modifies
properties _only_.

```json
{
  "users": [
    {
      "Properties": {
        "highvalue": false,
        "name": "USER@SOMEDOMAIN.COM",
        "domain": "SOMEDOMAIN.COM",
        "description": null,
        "dontreqpreauth": false,
        "passwordnotreqd": false,
        "unconstraineddelegation": false,
        "sensitive": false,
        "enabled": false,
        "pwdneverexpires": false,
        "lastlogon": -1,
        "lastlogontimestamp": -1,
        "pwdlastset": 1556829372,
        "serviceprincipalnames": [],
        "hasspn": false,
        "displayname": "Some User",
        "email": "user@somedomain.com",
        "title": null,
        "homedirectory": null,
        "userpassword": null,
        "admincount": false,
        "sidhistory": [],
        "owned":true,
      }
    }
  ]
}
```

So, given the structure above we can say:

- Each item in the root `users` list is a **user object**
- Each component in the `Properties` member of a **user object**
  is a **property**

This module will iterate over all objects in JSON files produced
by a valid ingestor, check some key in the `Properties` member
against a user-supplied value, and add/update a property should
a match occur.

So we could run the following command across all JSON files and
search for an object with a property of "name" with the value of
"USER@SOMEDOMAIN.COM" and add a property ("owned") to the object
and set it to "true".

```bash
parsuite bloodhound_property_manager -jfiles *users.json -ps owned=true -target-objects name=USER@SOMEDOMAIN.COM
[+] Starting the parser
[+] Loading modules
[+] Executing module: bloodhound_property_manager
[+] Attempting to import 20201108132152_users.json
[+] Attempting to import users.json
[+] Attempting to parse property: owned=true
[+] Updating JSON content...
[+] Updating files...
[+] Finished!
[+] Module execution complete. Exiting.
```
