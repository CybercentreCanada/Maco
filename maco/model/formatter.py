from typing import List, Optional, Union, TypedDict
from hashlib import sha256

class FlattenedDict(dict):
    def add_iter(self, data:Union[dict, List[dict]], count: int):
        count = count + 1
        if type(data) == dict:
            keys, values = zip(*data.items())
            key, value = keys[0], values[0]
            updated_key = f"{key} [{count}]"
            self[updated_key] = value

        elif type(data) == list:
            dict_element: dict[str, str]
            for dict_element in data:
                for key, value in dict_element.items():
                    updated_key = f"{key} [{count}]"
                    self[updated_key] = value
        else:
            # Log a potential oversight
            pass

    def add(self, data: Union[dict, List[dict]]):
        if type(data) == dict:
            self.update(data)
        elif type(data) == list:
            for dict_element in data:
                self.update(dict_element)
        else:
            # Log a potential oversight
            pass
    
    def beautify(self):
        # Convert single element lists to strings
        for key, value in self.items():
            if type(self[key]) == list:
                if len(self[key]) == 1:
                    self[key] = value[0]

        # Capitalize Keys
        for key in list(self):
            if key[0].isupper():
                continue
            value = self.pop(key)
            key = key.capitalize()
            self[key] = value
        return self
 



class HumanReadableFormatter:
    formatted: FlattenedDict = FlattenedDict()
    
    def __init__(self):
        self.result = FlattenedDict()
    
    def flatten(self, maco):
        primitive_types: List[any] = [str, float, bool, int]
        for key, value in maco.__dict__.items():
            if type(value) == list:
                for iter, element in enumerate(value):
                    if "flattened" in element.__dir__():
                        flattened_element = element.flattened()
                        if len(value) == 1:
                            self.result.add(flattened_element)
                        else:
                            self.result.add_iter(flattened_element, iter)
                    elif type(element) in primitive_types:
                        self.result[key] = value
            elif type(value) in primitive_types:
                self.result[key] = value
        return self.result

    @staticmethod
    def encryption(entry):
        fields: List[dict[str, str]] = []
        for field in entry.__fields__.keys():
            value = entry.__dict__[field]
            if not value:
                continue
            key = f"Encryption {field.capitalize()}"
            fields.append({key: value})
        return fields

    @staticmethod
    def binary(entry):
        fields: List[dict[str, str]] = []
        if not entry.data:
            return
        fields.append({"Binary Size": f"{len(entry.data)} bytes"})
        fields.append({"Binary SHA256": f"{sha256(entry.data).hexdigest()}"})
        if entry.datatype:
            fields.append({"Binary Purpose": entry.datatype.name.upper()})
        key: str = "Binary Extracted" 
        try:
            value = entry.data.hex()
            fields.append({"Binary Extracted": f"{value[0:25]}..."})
        except ValueError:
            return {key: "Error decoding binary"}
        return fields

    @staticmethod
    def ftp(entry):
        fields: List[dict[str, str]] = []
        key: str = f"FTP {f'- {entry.usage.upper()}' if entry.usage else ''}"
        if entry.hostname:
            value: str = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            fields.append({key: value})
    
        # (Although the fields below shouldn't be present without the hostname) 
        if entry.path:
            fields.append({"FTP Path": entry.path})

        if entry.username:
            fields.append({"FTP Username": entry.username})
        
        if entry.password:
            fields.append({"FTP Password": entry.password})
        return fields
    
    @staticmethod
    def smtp(entry):
        fields: List[dict[str, str]] = []

        if entry.hostname:
            fields.append({"SMTP Hostname": f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"})
        
        # (Although the fields below shouldn't be present without the hostname) 
        if entry.usage:
            fields.append({"SMTP Purpose": entry.usage.upper()})

        if entry.username:
            fields.append({"SMTP Username": entry.username})
        
        if entry.password:
            fields.append({"SMTP Password": entry.password})
        
        if entry.mail_from:
            fields.append({"SMTP Sender": entry.mail_from})

        if entry.mail_to:
            fields.append({"SMTP Recipients": entry.mail_to})
        return fields

    @staticmethod
    def http(entry):
        title = "HTTPS" if entry.protocol.lower() == "https" else "HTTP"

        fields: List[dict[str, str]] = []
        key: str = f"{title} {f'- {entry.usage.upper()}' if entry.usage else ''}"

        if entry.uri:
            value = entry.uri
            fields.append({key: value})

        elif entry.hostname:               # If we don't have the full URI
            value = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            fields.append({key: value})

        # (Although the fields below shouldn't be present without the hostname) 
        if entry.username: 
            fields.append({f"{title} Username": entry.username})
        
        if entry.password:
            fields.append({f"{title} Password": entry.password})
        
        if entry.path:
            fields.append({f"{title} Path": entry.path})
        
        if entry.query:
            fields.append({f"{title} Query": entry.query})
        
        if entry.fragment:
            fields.append({f"{title} Fragment": entry.fragment})

        if entry.user_agent:
            fields.append({f"{title} User Agent": entry.user_agent})
        if entry.method:
            fields.append({f"{title} Method": entry.method})
        if entry.max_size:
            fields.append({f"{title} Max Size": entry.max_size})
        if entry.headers:
            fields.append({f"{title} Headers": entry.headers})
        return fields

    @staticmethod
    def ssh(entry):
        fields: List[dict[str, str]]
        key: str = f"SSH {f'- {entry.usage.upper()}' if entry.usage else ''}"

        if entry.hostname:
            value = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            fields.append({key: value})
        if entry.username: # (Although the fields below shouldn't be present without the hostname) 
            fields.append({"SSH Username": entry.username})
        if entry.password:
            fields.append({"SSH Password": entry.password})

    @staticmethod
    def proxy(entry):
        fields: List[dict[str, str]] = []
        key: str = f"Proxy {f'- {entry.usage.upper()}' if entry.usage else ''}"
        if entry.hostname:
            value = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            fields.append({key: value})
        if entry.protocol: # (Although the fields below shouldn't be present without the hostname) 
            fields.append({"Proxy Protocol": entry.protocol})
        if entry.username:
            fields.append({"Proxy Username": entry.username})
        if entry.password:
            fields.append({"Proxy Password": entry.password})
        return fields

    @staticmethod
    def dns(entry):
        if not entry.ip:
            return
        key: str = f"DNS {f'- {entry.usage.upper()}' if entry.usage else ''}"
        value = f"{entry.ip}{f':{entry.port}' if entry.port else ''}"
        return {key: value}

    @staticmethod
    def connection(entry):
        if entry.server_ip or entry.server_domain:
            key = f"TCP/UDP Connection (Server) {f'- {entry.usage.upper()}' if entry.usage else ''}"
            if entry.server_ip:
                value = f"{entry.server_ip}"
            else:
                value = f"{entry.server_domain}"
            value = f"{value}{f':{entry.server_port}' if entry.server_port else ''}"
            return {key: value}

        if entry.client_ip:
            key = f"TCP/UDP Connection (Client) {f'- {entry.usage.upper()}' if entry.usage else ''}"
            value = f"{entry.client_ip}{f':{entry.client_port}' if entry.client_port else ''}"
            return {key: value}

    @staticmethod
    def service(entry):
        fields: List[dict[str, str]] = []
        if entry.name:
            fields.append({"Service Name": entry.name})
        if entry.display_name:
            fields.append({"Service Display Name": entry.display_name})
        if entry.description:
            fields.append({"Service Description": entry.description})
        if entry.dll:
            fields.append({"Service DLL": entry.dll})
        return fields

    @staticmethod
    def cryptocurrency(entry):
        key: str = "Cryptocurrency"
        if entry.ransom_amount and entry.coin:
            key = f"{key} {f'({entry.coin} x {entry.ransom_amount})'}"
        elif entry.ransom_amount:
            key = f"{key} {f'({entry.ransom_amount} Coins)'}"
        elif entry.coin:
            key = f"{key} {f'({entry.coin})'}"

        if not entry.address:
            return
        return {key: entry.address}

    @staticmethod
    def path(entry):
        if not entry.path:
            return
        key = f"Path {f'- {entry.usage.upper()}' if entry.usage else ''}"
        return {key: entry.path}
    
    @staticmethod
    def registry(entry) -> Optional[dict[str, str]]:
        if not entry.key:
            return 
        key = f"Registry {f'- {entry.usage.upper()}' if entry.usage else ''}"
        return {key: entry.key}



class MachineReadableDict(TypedDict):
    family:     Union[str, List[str]]
    version:        str
    campaign:   List[str]
    identifier:     str
    network:    List[str]       # All network activities
    registry:   List[str]       # The key of the registry entry
    path:       List[str]       
    service:    List[str]       # The name of the services 
    binary:     List[str]       # The SHA256 hash of the binary
    email_from: List[str]
    email_subject: List[str]


class MachineReadableFormatter:
    c2_list: List = [] # Merge all net object into the list

    data: MachineReadableDict = {
        'family': "",
        'version': "",
        'campaign': "",
        'identifier': "",
        'network': [],
        'registry': [],
        'path': [],
        'service': [],
        'binary': [],
        'email_from': [],
        'email_subject': []
    }


    default: MachineReadableDict = {
        'family': "",
        'version': "",
        'campaign': "",
        'identifier': "",
        'network': [],
        'registry': [],
        'path': [],
        'service': [],
        'binary': [],
        'email_from': [],
        'email_subject': []
    }

    def flatten(self, maco) -> MachineReadableDict:           
        for key, value in maco.__dict__.items():
            if type(value) == list:
                for iter, element in enumerate(value):
                    if "flattened" in element.__dir__():
        # Adding the data will be handled by each classes' flattened method
                        element.flattened(depth = 2)

            if key == "family":
                self.data['family'] = value
            
            elif key == "campaign_id":
                self.data['campaign'] = value
            
            elif key == "version":
                self.data['version'] = value

            elif key == "identifier":
                self.data['identifier'] = value 
        
        return self.data

    @staticmethod
    def encryption(entry):
        pass    # Don't see anything worth extracting

    @staticmethod
    def binary(entry):
        MachineReadableFormatter.data['binary'].append(sha256(entry.data).hexdigest())

    @staticmethod
    def ftp(entry):
        if entry.hostname:
            formatted_ftp_hostname = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_ftp_hostname)
    
    @staticmethod
    def smtp(entry):
        if entry.hostname:
            formatted_smtp_hostname = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_smtp_hostname)
        if entry.mail_from:
            MachineReadableFormatter.data['email_from'].append(entry.mail_from)
        if entry.subject:
            MachineReadableFormatter.data['email_subject'].append(entry.subject)

    @staticmethod
    def http(entry):
        if entry.uri:
            MachineReadableFormatter.data['network'].append(entry.uri)
        if entry.hostname:
            MachineReadableFormatter.data['network'].append(entry.hostname)

    @staticmethod
    def ssh(entry):
        if entry.hostname:
            formatted_ssh_hostname = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_ssh_hostname)
    
    @staticmethod
    def proxy(entry):
        if entry.hostname:
            formatted_proxy_hostname = f"{entry.hostname}{f':{entry.port}' if entry.port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_proxy_hostname)


    @staticmethod
    def dns(entry):
        if entry.ip:
            formatted_dns = f"{entry.ip}{f':{entry.port}' if entry.port else ''}" 
            MachineReadableFormatter.data['network'].append(formatted_dns)

    @staticmethod
    def connection(entry):
        if entry.client_ip:
            formatted_client_ip = f"{entry.client_port}{f':{entry.client_port}' if entry.client_port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_client_ip)

        if entry.server_ip:
            formatted_server_ip = f"{entry.server_ip}{f':{entry.server_port}' if entry.server_port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_server_ip)

        if entry.server_domain:
            formatted_domain = f"{entry.server_domain}{f':{entry.server_port}' if entry.server_port else ''}"
            MachineReadableFormatter.data['network'].append(formatted_domain)
 
    @staticmethod
    def service(entry):
        if entry.name:
            MachineReadableFormatter.data['service'].append(entry.name)

    @staticmethod
    def cryptocurrency(entry):
        pass    # Nothing worth extracting

    @staticmethod
    def path(entry):
        if entry.path:
            MachineReadableFormatter.data['path'].append(entry.path)

    @staticmethod
    def registry(entry):
        if entry.key:
            MachineReadableFormatter.data['registry'].append(entry.key)
