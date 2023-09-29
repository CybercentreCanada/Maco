from abc import abstractmethod, ABC
from .model import Encryption, ExtractorModel

class BaseFormatter(ABC):

    @abstractmethod
    def format(self, maco: ExtractorModel):
        pass

    @abstractmethod
    def encryption(self, entry: Encryption):
        pass

    @abstractmethod
    def binary(self, entry: ExtractorModel.Binary):
        pass

    @abstractmethod
    def ftp(self, entry: ExtractorModel.FTP):
        pass

    @abstractmethod
    def smtp(self, entry: ExtractorModel.SMTP):
        pass

    @abstractmethod
    def http(self, entry: ExtractorModel.Http):
        pass

    @abstractmethod
    def ssh(self, entry: ExtractorModel.SSH):
        pass

    @abstractmethod
    def proxy(self, entry: ExtractorModel.Proxy):
        pass

    @abstractmethod
    def dns(self, entry: ExtractorModel.DNS):
        pass

    @abstractmethod
    def connection(self, entry: ExtractorModel.Connection):
        pass

    @abstractmethod
    def service(self, entry: ExtractorModel.Service):
        pass
    
    @abstractmethod
    def cryptocurrency(self, entry: ExtractorModel.Cryptocurrency):
        pass

    @abstractmethod
    def path(self, entry: ExtractorModel.Path):
        pass

    @abstractmethod
    def registry(self, entry: ExtractorModel.Registry):
        pass


    def format_port(self, ip_or_domain: str, port: str):
        return f"{ip_or_domain}{f':{port}' if port else ''}"
    