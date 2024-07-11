from .model import Encryption, ExtractorModel, ForbidModel
from .base_formatter import BaseFormatter
from hashlib import sha256
from typing import List, Union, Dict

class CustomDict(dict):
    """
    Due to issues that arise with flattening the model, such as:
        * When handling a list of element which has optional fields.
        One entry may have four fields sets, and another entry may have three fields set.
        If I make use of a list, it'd be confusing to know which field belongs to which entry [There won't be a 1-1 mapping across the lists]

    Therefore, the solution is this CustomDict with has a custom add method that formats the key name to make a clear distinction, if needed.
    """
    def add_iteratively(self, data: Union[Dict, List[Dict]], count: int):
        if type(data) == dict:
            keys, values = zip(*data.items())
            key, value = keys[0], values[0]
            updated_key = f"{key} #{count}"
            self[updated_key] = value

        elif type(data) == list:
            dict_element: dict[str, str]
            for dict_element in data:
                for key, value in dict_element.items():
                    updated_key = f"{key} #{count}"
                    self[updated_key] = value

    def add(self, data: Union[dict, List[dict]]):
        if type(data) == dict:
            self.update(data)
        elif type(data) == list:
            for dict_element in data:
                self.update(dict_element)


class HumanFormatter(BaseFormatter):

    def format(self, model: ExtractorModel):
        formatted_dict = CustomDict()
        for key, value in model.__dict__.items():
            if type(value) == list:
                for iterator, entry in enumerate(value):
                    if isinstance(entry, ForbidModel):
                        formatted_value = self.invoke_formatter(entry)
                        if len(value) == 1:
                            formatted_dict.add(formatted_value)
                        else:
                            formatted_dict.add_iteratively(formatted_value, iterator + 1)
                        continue
            elif type(value) == dict:
                formatted_dict.add(value)
            elif value:
                formatted_dict[key] = value
        return formatted_dict

    def encryption(self, entry: Encryption) -> Union[Dict[str, str], List[Dict[str,str]]]:
        return self.generic_formatter(entry, "Encryption")
    
    def binary(self, entry: ExtractorModel.Binary):
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
    
    def ftp(self, entry: ExtractorModel.FTP):
        fields: List[dict[str, str]] = []
        key: str = f"FTP Hostname{f'- {entry.usage.upper()}' if entry.usage else ''}"
        if entry.hostname:
            fields.append({key: self.format_port(entry.hostname, entry.port)})
        fields.extend(self.generic_formatter(entry, "FTP", ["hostname", "port"]))
        return fields    

    def smtp(self, entry: ExtractorModel.SMTP):
        fields: List[dict[str, str]] = []
        key: str = f"SMTP Hostname{f'-{entry.usage.upper()}' if entry.usage else ''}"

        if entry.hostname:
            fields.append({key: self.format(entry.hostname, entry.port)})
        
        fields.extend(self.generic_formatter(entry, "SMTP", ["hostname", "port"]))
        return fields

    
    def http(self, entry: ExtractorModel.Http):
        title = "HTTPS" if entry.protocol.lower() == "https" else "HTTP"
        fields: List[dict[str, str]] = []
        if entry.uri:
            key = f"{title} URI{f'- {entry.usage.upper()}' if entry.usage else ''}"
            value = entry.uri
            fields.append({key: value})

        elif entry.hostname:               # If we don't have the full URI
            key = f"{title} Hostname{f'- {entry.usage.upper()}' if entry.usage else ''}"
            value = self.format_port(entry.hostname, entry.port)
            fields.append({key: value})    
        fields.extend(self.generic_formatter(entry, title, ["uri", "hostname", "port", "protocol"]))
        return fields
    
    def ssh(self, entry: ExtractorModel.SSH):
        fields: List[dict[str, str]]
        key: str = f"SSH {f'- {entry.usage.upper()}' if entry.usage else ''}"
        if entry.hostname:
            value = self.format_port(entry.hostname, entry.port)
            fields.append({key: value})
        fields.extend(self.generic_formatter(entry, "SSH", ["hostname", "port"]))
        return fields
    
    def proxy(self, entry: ExtractorModel.Proxy):
        fields: List[dict[str, str]] = []
        key: str = f"Proxy {f'- {entry.usage.upper()}' if entry.usage else ''}"
        if entry.hostname:
            value = self.format_port(entry.hostname, entry.port)
            fields.append({key: value})
        fields.extend(self.generic_formatter(entry, "Proxy", ["hostname", "port"]))
        return fields
    
    def dns(self, entry: ExtractorModel.DNS):
        if not entry.ip:
            return
        key: str = f"DNS {f'- {entry.usage.upper()}' if entry.usage else ''}"
        value = self.format_port(entry.ip, entry.port)
        return {key: value}
    
    def connection(self, entry: ExtractorModel.Connection):
        if entry.server_ip or entry.server_domain:
            key = f"TCP/UDP Connection (Server) {f'- {entry.usage.upper()}' if entry.usage else ''}"
            if entry.server_ip:
                value = entry.server_ip
            else:
                value = entry.server_domain
            value = self.format_port(value, entry.server_port)
            return {key: value}

        if entry.client_ip:
            key = f"TCP/UDP Connection (Client) {f'- {entry.usage.upper()}' if entry.usage else ''}"
            value = self.format_port(entry.client_ip, entry.client_port)
            return {key: value}

    def service(self, entry: ExtractorModel.Service):
        return self.generic_formatter(entry, "Service")
    
    def cryptocurrency(self, entry: ExtractorModel.Cryptocurrency):
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

    def path(self, entry: ExtractorModel.Path):
        if not entry.path:
            return
        key = f"Path {f'- {entry.usage.upper()}' if entry.usage else ''}"
        return {key: entry.path}
    
    def registry(self, entry: ExtractorModel.Registry):
        if not entry.key:
            return 
        key = f"Registry {f'- {entry.usage.upper()}' if entry.usage else ''}"
        return {key: entry.key}
 
    def capitalize_key(self, split_key: List[str]):
        capitalized = []
        for sub_key in split_key:
            capitalized.append(sub_key.capitalize())
        return capitalized
    
    def generic_formatter(self, entry, key_prefix: str = "" ,exclusion: List[str] = []) -> List[Dict[str, str]]:
        if not entry:
            return
        fields: List[Dict[str, str]] = []
        for key, value in entry.__dict__.items():
            if key in exclusion or not value:
                continue
    
            key = f"{key_prefix}_{key}"
            list_key = key.split("_")
            capitalized_key = self.capitalize_key(list_key)
            key = " ".join(capitalized_key)            
            fields.append({key: value})
        return fields