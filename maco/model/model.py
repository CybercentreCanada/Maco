"""Malware config extractor output model."""

from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict


class ForbidModel(BaseModel):
    """We want to forbid extra properties, so that the 'other' field is used instead."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class ConnUsageEnum(str, Enum):
    """Purpose of the connection."""

    c2 = "c2"  # issue commands to malware
    upload = "upload"  # get data out of the network
    download = "download"  # fetch dynamic config, second stage, etc
    propagate = "propagate"  # spread through the network
    tunnel = "tunnel"  # communicate through the network
    ransom = "ransom"  # payment
    decoy = "decoy"  # Decoy connections to obfuscate malicious
    other = "other"


class Encryption(ForbidModel):
    """Encryption usage."""

    class UsageEnum(str, Enum):
        config = "config"
        communication = "communication"
        binary = "binary"
        ransom = "ransom"
        other = "other"

    algorithm: Optional[str] = None
    public_key: Optional[str] = None
    key: Optional[str] = None  # private key or symmetric key
    provider: Optional[str] = None  # encryption library used. openssl, homebrew, etc.

    mode: Optional[str] = None  # block vs stream
    # base 64'd binary data for these details?
    # TODO to confirm usage of these different properties
    iv: Optional[str] = None  # initialisation vector
    seed: Optional[str] = None
    nonce: Optional[str] = None
    constants: List[str] = []

    usage: Optional[UsageEnum] = None


class CategoryEnum(str, Enum):
    # Software that shows you extra promotions that you cannot control as you use your PC.
    # You wouldn't see the extra ads if you didn't have adware installed.
    adware = "adware"

    # Malware related to an Advanced Persistent Threat (APT) group.
    apt = "apt"

    # A backdoor Trojan gives malicious users remote control over the infected computer. They enable the author to do anything they wish on the infected computer including sending, receiving, launching and deleting files, displaying data and rebooting the computer. Backdoor Trojans are often used to unite a group of victim computers to form a botnet or zombie network that can be used for criminal purposes.
    backdoor = "backdoor"

    # Trojan Banker programs are designed to steal your account data for online banking systems, e-payment systems and credit or debit cards.
    banker = "banker"

    # A malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR).
    bootkit = "bootkit"

    # A malicious bot is self-propagating malware designed to infect a host and connect back to a central server or servers that act as a command and control (C&C) center for an entire network of compromised devices, or botnet.
    bot = "bot"

    # A browser hijacker is defined as a form of unwanted software that modifies a web browser's settings without the user's permission. The result is the placement of unwanted advertising into the browser, and possibly the replacement of an existing home page or search page with the hijacker page.
    browser_hijacker = "browser_hijacker"

    # Trojan bruteforcer are trying to brute force website in order to achieve something else (EX: Finding  WordPress websites with default credentials).
    bruteforcer = "bruteforcer"

    # A type of trojan that can use your PC to 'click' on websites or applications. They are usually used to make money for a malicious hacker by clicking on online advertisements and making it look like the website gets more traffic than it does. They can also be used to skew online polls, install programs on your PC, or make unwanted software appear more popular than it is.
    clickfraud = "clickfraud"

    # Cryptocurrency mining malware.
    cryptominer = "cryptominer"

    # These programs conduct DoS (Denial of Service) attacks against a targeted web address. By sending multiple requests from your computer and several other infected computers, the attack can overwhelm the target address leading to a denial of service.
    ddos = "ddos"

    # Trojan Downloaders can download and install new versions of malicious programs in the target system.
    downloader = "downloader"

    # These programs are used by hackers in order to install malware or to prevent the detection of malicious programs.
    dropper = "dropper"

    # Exploit kits are programs that contain data or code that takes advantage of a vulnerability within an application that is running in the target system.
    exploitkit = "exploitkit"

    # Trojan FakeAV programs simulate the activity of antivirus software. They are designed to extort money in return for the detection and removal of threat, even though the threats that they report are actually non-existent.
    fakeav = "fakeav"

    # A type of tool that can be used to allow and maintain unauthorized access to your PC.
    hacktool = "hacktool"

    # A program that collects your personal information, such as your browsing history, and uses it without adequate consent.
    infostealer = "infostealer"

    # A keylogger monitors and logs every keystroke it can identify. Once installed, the virus either keeps track of all the keys and stores the information locally, after which the hacker needs physical access to the computer to retrieve the information, or the logs are sent over the internet back to the hacker.
    keylogger = "keylogger"

    # A program that loads another application / memory space.
    loader = "loader"

    # A type of malware that hides its code and purpose to make it more difficult for security software to detect or remove it.
    obfuscator = "obfuscator"

    # Point-of-sale malware is usually a type of malware that is used by cybercriminals to target point of sale (POS) and payment terminals with the intent to obtain credit card and debit card information.
    pos = "pos"

    # This type of trojan allows unauthorized parties to use the infected computer as a proxy server to access the Internet anonymously.
    proxy = "proxy"

    # A program that can be used by a remote hacker to gain access and control of an infected machine.
    rat = "rat"

    # This type of malware can modify data in the target computer so the operating system will stop running correctly or the data is no longer accessible. The criminal will only restore the computer state or data after a ransom is paid to them (mostly using cryptocurrency).
    ransomware = "ransomware"

    # A reverse proxy is a server that receives requests from the internet and forwards them to a small set of servers.
    reverse_proxy = "reverse_proxy"

    # Rootkits are designed to conceal certain objects or activities in the system. Often their main purpose is to prevent malicious programs being detected in order to extend the period in which programs can run on an infected computer.
    rootkit = "rootkit"

    # This type of malware scan the internet / network(s) / system(s) / service(s) to collect information. That information could be used later to perpetuate an cyber attack.
    scanner = "scanner"

    # Scareware is a form of malware which uses social engineering to cause shock, anxiety, or the perception of a threat in order to manipulate users into buying unwanted software.
    scareware = "scareware"

    # Malware that is sending spam.
    spammer = "spammer"

    # Generic or Unknown Trojan
    trojan = "trojan"

    # A generic computer virus
    virus = "virus"

    # A type of malware that destroy the data.
    wiper = "wiper"

    # A web shell is a script that can be uploaded to a web server to enable remote administration of the machine.
    webshell = "webshell"

    # A type of malware that spreads to other PCs.
    worm = "worm"


class ExtractorModel(ForbidModel):
    r"""Captured config/iocs, unpacked binaries and other malware properties from a robo-analyst.

    This model defines common fields for output of a script targeting a specific malware family.
    Usage of this model will allow for easier sharing of scripts between different authors and systems.
    The model will not define fields for all data that can be extracted from a binary, only the most common.
    This is to make it easier for authors to understand and use the model.

    This model can have new fields added in the future if they become more common,
    but the intent is to avoid removing or modifying existing fields, for backwards compatibility.

    Where data does not fit with the current model, the 'others' field should be used.
    Contents in this field is not defined by the model and verification/normalisation is up to
    the author and whatever systems run the scripts.
    If many decoders define similar data in the 'others' field, that field should be migrated to this model.

    The model must be kept relatively flat, with nested lists of dictionaries to be avoided.
    This is to make queries simpler to write in sql, elasticsearch and other storage systems.

    Malware and systems that investigate malware can do pretty much anything.
    This model needs to be simple and flexible to make sharing easy.
    Some things should be out of scope for this model.
    Responsibility for these things are up to authors and systems that use this model.

    Out of scope
    * Verifying anything in the 'others' dict, including that it is json-compatible.
        * We don't know anything about the structure
        * checking is json compatible requires dumping to json string, which can be slow
    * Connecting specific config items to malware behaviour catalog
        * i.e. "Persistence::Modify Registry" with 'registry' item from model (SYSTEM\ControlSet001\Services\)
        * due to complexity and normalisation difficulties
        * much malware behaviour is not related to specific config items
    * Normalisation/verification of individual properties
        * i.e. lowercase filepaths - some filesystems are case sensitive
        * i.e. checking registry hives match known - not enough SME and too complex for a simple model
        * generally, this quickly becomes complex (validating a fully defined http item)
        * calling systems are probably performing their own validation anyway
    * requiring specific properties to be set
        * i.e. if http item is defined, requiring hostname to be set
        * Some use cases always seem to exist where a property should not be set
    """

    family: Union[str, List[str]]  # family or families of malware that was detected
    version: Optional[str] = None  # version/variant of malware
    category: List[CategoryEnum] = []  # capability/purpose of the malware
    attack: List[str] = []  # mitre att&ck reference ids, e.g. 'T1129'

    #
    # simple config properties
    #

    # capabilities of the malware enabled/disabled in config
    # note these are probably malware-specific capabilities so no attempt to normalise has been made
    # note - av/sandbox detection should be noted by 'detect_<product>'
    capability_enabled: List[str] = []
    capability_disabled: List[str] = []

    campaign_id: List[str] = []  # Server/Campaign Id for malware
    identifier: List[str] = []  # UUID/Identifiers for deployed instance
    decoded_strings: List[str] = []  # decoded strings from within malware
    password: List[str] = []  # Any password extracted from the binary
    mutex: List[str] = []  # mutex to prevent multiple instances
    pipe: List[str] = []  # pipe name used for communication
    sleep_delay: Optional[int] = None  # time to sleep/delay execution (milliseconds)
    # additional time applied to sleep_delay (milliseconds).
    # Jitter implementations can vary but usually it is a value from which a random number is generated and
    # added/subtracted to the sleep_delay to make behaviour more unpredictable
    sleep_delay_jitter: Optional[int] = None
    inject_exe: List[str] = []  # name of executable to inject into

    # configuration or clustering/research data that doesnt fit the other fields
    # * rarely used by decoders or specific to one decoder
    # to prevent key explosion, the keys must not be dynamically generated
    # e.g. api_imports, api_checksums, num_imports, import_hash + many more
    # data stored here must always be JSON-serialisable
    other: Dict[str, Any] = {}

    #
    # embedded binary data
    #
    class Binary(ForbidModel):
        """Binary data extracted by decoder."""

        class TypeEnum(str, Enum):
            payload = "payload"  # contained within the original file
            config = "config"  # sometimes malware uses json/formatted text for config
            other = "other"

        datatype: Optional[TypeEnum] = None  # what the binary data is used for
        data: bytes  # binary data, not json compatible

        # other information for the extracted binary rather than the config
        # data stored here must always be JSON-serialisable
        # e.g. filename, extension, relationship label
        other: Dict[str, Any] = {}

        # convenience for ret.encryption.append(ret.Encryption(*properties))
        # Define as class as only way to allow for this to be accessed and not have pydantic try to parse it.
        class Encryption(Encryption):
            pass

        encryption: Union[List[Encryption], Encryption, None] = None  # encryption information for the binary

    binaries: List[Binary] = []

    #
    # communication protocols
    #
    class FTP(ForbidModel):
        """Usage of FTP connection."""

        username: Optional[str] = None
        password: Optional[str] = None
        hostname: Optional[str] = None
        port: Optional[int] = None

        path: Optional[str] = None

        usage: Optional[ConnUsageEnum] = None

    ftp: List[FTP] = []

    class SMTP(ForbidModel):
        """Usage of SMTP."""

        # credentials and location of server
        username: Optional[str] = None
        password: Optional[str] = None
        hostname: Optional[str] = None
        port: Optional[int] = None

        mail_to: List[str] = []  # receivers
        mail_from: Optional[str] = None  # sender
        subject: Optional[str] = None

        usage: Optional[ConnUsageEnum] = None

    smtp: List[SMTP] = []  # SMTP server for malware

    class Http(ForbidModel):
        """Usage of HTTP connection."""

        # malware sometimes does weird stuff with uris so we don't want to force
        # authors to break the uri into username, hostname, path, etc.
        # as we lose that information.
        # e.g. extra '?' or '/' when unnecessary.
        # or something that is technically an invalid uri but still works
        uri: Optional[str] = None

        # on the other hand we might not have enough info to construct a uri
        protocol: Optional[str] = None  # http,https
        username: Optional[str] = None
        password: Optional[str] = None
        hostname: Optional[str] = None  # (A host/hostname can be an IP, domain or hostname)
        port: Optional[int] = None
        path: Optional[str] = None
        query: Optional[str] = None
        fragment: Optional[str] = None

        user_agent: Optional[str] = None  # user agent sent by malware
        method: Optional[str] = None  # get put delete etc
        headers: Optional[Dict[str, str]] = None  # custom/additional HTTP headers
        max_size: Optional[int] = None

        usage: Optional[ConnUsageEnum] = None

    http: List[Http] = []

    class SSH(ForbidModel):
        """Usage of ssh connection."""

        username: Optional[str] = None
        password: Optional[str] = None
        hostname: Optional[str] = None
        port: Optional[int] = None

        usage: Optional[ConnUsageEnum] = None

    ssh: List[SSH] = []

    class Proxy(ForbidModel):
        """Usage of proxy connection."""

        protocol: Optional[str] = None  # socks5,http
        username: Optional[str] = None
        password: Optional[str] = None
        hostname: Optional[str] = None
        port: Optional[int] = None

        usage: Optional[ConnUsageEnum] = None

    proxy: List[Proxy] = []

    #
    # inter process communication (IPC)
    #
    class IPC(ForbidModel):
        """Usage of named pipe communications."""

        # A record stored on disk, or a record synthesized on demand by a file
        # server, which can be accessed by multiple processes.
        file: Optional[List[str]] = None
        # Data sent over a network interface, either to a different process on
        # the same computer or to another computer on the network. Stream
        # oriented (TCP; data written through a socket requires formatting to
        # preserve message boundaries) or more rarely message-oriented (UDP,
        # SCTP).
        socket: Optional[List[str]] = None
        # Similar to an internet socket, but all communication occurs within
        # the kernel. Domain sockets use the file system as their address
        # space. Processes reference a domain socket as an inode, and multiple
        # processes can communicate with one socket.
        unix_domain_socket: Optional[List[str]] = None
        # A file mapped to RAM and can be modified by changing memory
        # addresses directly instead of outputting to a stream. This shares
        # the same benefits as a standard file.
        memory_mapped_file: Optional[Union[bytes, List[str]]] = None
        # A data stream similar to a socket, but which usually preserves
        # message boundaries. Typically implemented by the operating system,
        # they allow multiple processes to read and write to the message queue
        # without being directly connected to each other.
        message_queue: Optional[List[str]] = None
        # A unidirectional data channel using standard input and output. Data
        # written to the write-end of the pipe is buffered by the operating
        # system until it is read from the read-end of the pipe. Two-way
        # communication between processes can be achieved by using two pipes
        # in opposite "directions".
        anonymous_pipe: Optional[List[str]] = None
        # A pipe that is treated like a file. Instead of using standard input
        # and output as with an anonymous pipe, processes write to and read
        # from a named pipe, as if it were a regular file.
        named_pipe: Optional[List[str]] = None
        # The process names involved in the IPC communication
        process_names: Optional[List[str]] = None
        # Multiple processes are given access to the same block of memory,
        # which creates a shared buffer for the processes to communicate with
        # each other.
        shared_memory: Optional[bytes] = None
        usage: Optional[ConnUsageEnum] = None

    ipc: List[IPC] = []  # Inter-Process Communications (similar to 'pipe' but more detailed)

    class DNS(ForbidModel):
        """Direct usage of DNS."""

        class RecordTypeEnum(str, Enum):
            A = "A"
            AAAA = "AAAA"
            AFSDB = "AFSDB"
            APL = "APL"
            CAA = "CAA"
            CDNSKEY = "CDNSKEY"
            CDS = "CDS"
            CERT = "CERT"
            CNAME = "CNAME"
            CSYNC = "CSYNC"
            DHCID = "DHCID"
            DLV = "DLV"
            DNAME = "DNAME"
            DNSKEY = "DNSKEY"
            DS = "DS"
            EUI48 = "EUI48"
            EUI64 = "EUI64"
            HINFO = "HINFO"
            HIP = "HIP"
            HTTPS = "HTTPS"
            IPSECKEY = "IPSECKEY"
            KEY = "KEY"
            KX = "KX"
            LOC = "LOC"
            MX = "MX"
            NAPTR = "NAPTR"
            NS = "NS"
            NSEC = "NSEC"
            NSEC3 = "NSEC3"
            NSEC3PARAM = "NSEC3PARAM"
            OPENPGPKEY = "OPENPGPKEY"
            PTR = "PTR"
            RRSIG = "RRSIG"
            RP = "RP"
            SIG = "SIG"
            SMIMEA = "SMIMEA"
            SOA = "SOA"
            SRV = "SRV"
            SSHFP = "SSHFP"
            SVCB = "SVCB"
            TA = "TA"
            TKEY = "TKEY"
            TLSA = "TLSA"
            TSIG = "TSIG"
            TXT = "TXT"
            URI = "URI"
            ZONEMD = "ZONEMD"

        ip: Optional[str] = None
        port: Optional[int] = None  # The default value is 53
        hostname: Optional[str] = None  # This is the query hostname
        record_type: Optional[RecordTypeEnum] = None  # The DNS record type that is queried
        usage: Optional[ConnUsageEnum] = None

    dns: List[DNS] = []  # custom DNS address to use for name resolution

    class Connection(ForbidModel):
        """Generic TCP/UDP usage."""

        client_ip: Optional[str] = None
        client_port: Optional[int] = None
        server_ip: Optional[str] = None
        server_domain: Optional[str] = None
        server_port: Optional[int] = None

        usage: Optional[ConnUsageEnum] = None

    tcp: List[Connection] = []
    udp: List[Connection] = []

    #
    # complex configuration properties
    #
    # convenience for ret.encryption.append(ret.Encryption(*properties))
    # Define as class as only way to allow for this to be accessed and not have pydantic try to parse it.
    class Encryption(Encryption):
        pass

    encryption: List[Encryption] = []

    class Service(ForbidModel):
        """OS service usage by malware."""

        dll: Optional[str] = None  # dll that the service is loaded from
        name: Optional[str] = None  # service/driver name for persistence
        display_name: Optional[str] = None  # display name for service
        description: Optional[str] = None  # description for service

    service: List[Service] = []

    class Cryptocurrency(ForbidModel):
        """Cryptocoin usage (ransomware/miner)."""

        class UsageEnum(str, Enum):
            ransomware = "ransomware"  # request money to unlock
            miner = "miner"  # use gpu/cpu to mint coins
            other = "other"

        coin: Optional[str] = None  # BTC,ETH,USDT,BNB, etc
        address: Optional[str] = None
        ransom_amount: Optional[float] = None  # number of coins required (if hardcoded)

        usage: UsageEnum

    cryptocurrency: List[Cryptocurrency] = []

    class Path(ForbidModel):
        class UsageEnum(str, Enum):
            c2 = "c2"  # file/folder issues commands to malware
            config = "config"  # config is loaded from this path
            install = "install"  # install directory/filename for malware
            plugins = "plugins"  # load new capability from this directory
            logs = "logs"  # location to log activity
            storage = "storage"  # location to store/backup copied files
            other = "other"

        # C:\User\tmp\whatever.txt or /some/unix/folder/path
        path: str
        usage: Optional[UsageEnum] = None

    paths: List[Path] = []  # files/directories used by malware

    class Registry(ForbidModel):
        class UsageEnum(str, Enum):
            persistence = "persistence"  # stay alive
            store_data = "store_data"  # generated encryption keys or config
            store_payload = "store_payload"  # malware hidden in registry key
            read = "read"  # read system registry keys
            other = "other"

        key: str
        usage: Optional[UsageEnum] = None

    registry: List[Registry] = []
