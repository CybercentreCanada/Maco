from .model import Encryption, ExtractorModel, ForbidModel
from typing import TypedDict
from typing import Union, List
from .base_formatter import BaseFormatter

from hashlib import sha256

class MachineReadableDict(TypedDict):
    family:             Union[str, List[str]]
    version:            str
    campaign:           List[str]
    identifier:         str
    sockets:            List[str]       
    ftp:                List[str]
    smtp:               List[str]
    http:               List[str]
    uris:               List[str]
    ssh:                List[str]
    proxy:              List[str]
    dns:                List[str]
    tcp_socket:         List[str]
    udp_socket:         List[str]
    registries:         List[str]       # The key of the registry entry
    paths:              List[str]       
    services:           List[str]       # The name of the services 
    binaries:           List[str]       # The SHA256 hash of the binary
    email_from:         List[str]
    email_subject:      List[str]
    crypto_wallets:     List[str]

class MachineFormatter(BaseFormatter):

    def __init__(self):
        self.formatted: MachineReadableDict = {
            'family':           "",
            'version':          "",
            'campaign':         [],
            'identifier':       "",
            'ftp':              [],
            'smtp':             [],
            'http':             [],
            'uris':             [],
            'ssh':              [],
            'proxy':            [],
            'dns':              [],
            'connection':       [],
            'registries':       [],
            'paths':            [],
            'services':         [],
            'binaries':         [],
            'email_from':       [],
            'email_subject':    [],
            'crypto_wallets':   []
        }
    

    def format(self, maco: ExtractorModel) -> MachineReadableDict:
        important_keys: List[str] = ["family", "campaign", "version", "identifier"]
        for key, value in maco.__dict__.items():
            if type(value) == list:
                for _, element in enumerate(value):
                    if isinstance(element, ForbidModel):
                        self.invoke_formatter(element)
            if key in important_keys:
                self.formatted[key] = value
        return self.formatted
    
    def encryption(self, entry: Encryption):
        pass # Nothing worth grabbing

    def binary(self, entry: ExtractorModel.Binary):
        if entry.data:
            sha256_hash = sha256(entry.data).hexdigest()
            self.formatted['binaries'].append(sha256_hash)

    def ftp(self, entry: ExtractorModel.FTP):
        if entry.hostname:
            self.formatted['ftp'].append(self.format_port(entry.hostname, entry.port))

    def smtp(self, entry: ExtractorModel.SMTP):
        if entry.hostname:
            self.formatted['smtp'].append(self.format_port(entry.hostname, entry.port))
        if entry.subject:
            self.formatted['email_subject'].append(entry.subject)
        if entry.mail_from:
            self.formatted['email_from'].append(entry.mail_from)

    def http(self, entry: ExtractorModel.Http):
        if entry.uri:
            self.formatted['uris'].append(entry.uri)
        if entry.hostname:
            self.formatted['http'].append(self.format_port(entry.hostname, entry.port))

    def ssh(self, entry: ExtractorModel.SSH):
        if entry.hostname:
            self.formatted['ssh'].append(self.format_port(entry.hostname, entry.port))

    def proxy(self, entry: ExtractorModel.Proxy):
        if entry.hostname:
            self.formatted['proxy'].append(self.format_port(entry.hostname, entry.port))

    def dns(self, entry: ExtractorModel.DNS):
        if entry.ip:
            self.formatted['dns'].append(self.format_port(entry.ip, entry.port))

    def connection(self, entry: ExtractorModel.Connection):
        if entry.server_ip:
            self.formatted['connection'].append(self.format_port(entry.server_ip, entry.server_port))
        if entry.server_domain:
            self.formatted['connection'].append(self.format_port(entry.hostname, entry.port))
        if entry.client_ip:
            self.formatted['connection'].append(self.format_port(entry.client_ip, entry.client_port))

    def service(self, entry: ExtractorModel.Service):
        if entry.name:
            self.formatted['services'].append(entry.name)
        
    def cryptocurrency(self, entry: ExtractorModel.Cryptocurrency):
        if entry.address:
            self.formatted['crypto_wallets'].append(entry.address)

    def path(self, entry: ExtractorModel.Path):
        if entry.path:
            self.formatted['paths'].append(entry.path)

    def registry(self, entry: ExtractorModel.Registry):
        if entry.key:
            self.formatted['registries'].append(entry.key)
    