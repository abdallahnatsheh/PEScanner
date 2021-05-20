'''
this tool is pe scanner with built on pescanner.py form malware anaylysis cookbook
but this tool is more advanced with the ability to scan with virustotal
and works with python3
'''
import hashlib
import time
import string
import os, sys
import datetime

try:
    import pefile
    import peutils
except ImportError:
    print ('pefile not installed, see https://pypi.org/project/pefile/')
    sys.exit()
try:
    import vt
except ImportError:
    print('vt-py is not installed you cant use virustotal api now \
    , use  pip install vt-py or visit https://github.com/VirusTotal/vt-py')
try:
    from magic import magic
except ImportError:
    print('file types will not be available , visit https://github.com/ahupp/python-magic')

# your virustotal api key
vtapi = ""

# suspicious APIs to alert on
alerts = [b'OpenProcess', b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread', b'ReadProcessMemory',
          b'CreateProcess', b'WinExec', b'ShellExecute', b'HttpSendRequest', b'InternetReadFile', b'InternetConnect',
          b'CreateService', b'StartService', b'ConnectNamedPipe', b'CreateFileA', b'CreateThread', b'GetCurrentProcess',
          b'AdjustTokenPrivileges',
          b'AttachThreadInput', b'accept', b'bind', b'BitBlt', b'CertOpenSystemStoreA', b'connect', b'ConnectNamedPipe',
          b'ControlService',
          b'CreateFile', b'CreateFileMapping',b'CreateMutex',b'CreateToolhelp32Snapshot',b'CreateService',
          b'CryptAcquireContext',b'DeviceIoControl',b'EnableExecuteProtectionSupport',b'EnumProcesses']
# legit entry point sections
good_ep_sections = ['.text', '.code', 'INIT', 'PAGE', '.data', '.rdata', '.bss', '.idata']


def printbase():
    print("\
\n░█████╗░░██████╗░███████╗███╗░░██╗████████╗ ██████╗░███████╗░██████╗\
\n██╔══██╗██╔════╝░██╔════╝████╗░██║╚══██╔══╝ ██╔══██╗██╔════╝██╔════╝\
\n███████║██║░░██╗░█████╗░░██╔██╗██║░░░██║░░░ ██████╔╝█████╗░░╚█████╗░\
\n██╔══██║██║░░╚██╗██╔══╝░░██║╚████║░░░██║░░░ ██╔═══╝░██╔══╝░░░╚═══██╗\
\n██║░░██║╚██████╔╝███████╗██║░╚███║░░░██║░░░ ██║░░░░░███████╗██████╔╝\
\n╚═╝░░╚═╝░╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░ ╚═╝░░░░░╚══════╝╚═════╝░")
    print("by: abdallah natsheh \ncontact: abdnatsheh33@gmail.com \n")


def convert_char(char):
    if char in string.ascii_letters or \
            char in string.digits or \
            char in string.punctuation or \
            char in string.whitespace:
        return char
    else:
        return r'\x%02x' % ord(char)


def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])


class PEScanner:
    def __init__(self, files, peid_sigs=None):
        self.files = files
        # initialize YARA rules if provided

        # initialize PEiD signatures if provided
        if peid_sigs:
            try:
                self.sigs = peutils.SignatureDatabase(peid_sigs)
            except:
                self.sigs = None
        else:
            self.sigs = None

        # initialize python magic (file identification)
        # magic interface on python <= 2.6 is different than python >= 2.6
        if 'magic' in sys.modules:
            if sys.version_info <= (2, 6):
                self.ms = magic.open(magic.MAGIC_NONE)
                self.ms.load()

    def check_ep_section(self, pe):
        """ Determine if a PE's entry point is suspicious """
        name = ''
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                cast = str(sec.Name)
                name = cast.replace("\\x00", '')
                name = name[2:-1]
        return (ep, name)

    def check_verinfo(self, pe):
        """ Determine the version info in a PE file """
        ret = []

        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                ret.append(
                                    convert_to_printable(str_entry[0]) + ': ' +
                                    convert_to_printable(str_entry[1]))
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                ret.append(
                                    convert_to_printable(var_entry.entry.keys()[0]) +
                                    ': ' + var_entry.entry.values()[0])
        return '\n'.join(ret)

    def check_tls(self, pe):
        callbacks = []
        if (hasattr(pe,
                    'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0:
                    break
                callbacks.append(func)
                idx += 1
        return callbacks

    def check_rsrc(self, pe):
        ret = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            i = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size)
                                if 'magic' in sys.modules:
                                    if sys.version_info <= (2, 6):
                                        filetype = self.ms.buffer(data)
                                    else:
                                        filetype = magic.from_buffer(data)
                                else:
                                    filetype = None
                                if filetype == None:
                                    filetype = ''
                                ret[i] = (
                                    name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size,
                                    filetype)
                                i += 1
        return ret

    def check_imports(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    for alert in alerts:
                        if imp.name.startswith(alert):
                            ret.append(imp.name)
        return ret

    def get_timestamp(self, pe):
        val = pe.FILE_HEADER.TimeDateStamp
        ts = '0x%-8X' % (val)
        try:
            ts += ' [%s UTC]' % time.asctime(time.gmtime(val))
            that_year = time.gmtime(val)[0]
            this_year = time.gmtime(time.time())[0]
            if that_year < 2000 or that_year > this_year:
                ts += " [SUSPICIOUS]"
        except:
            ts += ' [SUSPICIOUS]'
        return ts

    def check_packers(self, pe):
        packers = []
        if self.sigs:
            matches = self.sigs.match(pe, ep_only=True)
            if matches != None:
                for match in matches:
                    packers.append(match)
        return packers

    def header(self, msg):
        return "\n" + msg + "\n" + ("=" * 60)


    def collect(self):
        count = 0
        out = []
        analysis = ""


        out.append("Start Time: %s UTC \n" % datetime.datetime.utcnow())
        for file in self.files:

            try:
                FILE = open(file, "rb")
                data = FILE.read()
                try:
                    if len(vtapi) == 64:
                        client = vt.Client(vtapi)
                        scan = client.scan_file(FILE, wait_for_completion=True)
                        analysis = scan.result
                        client.close()
                except:
                    analysis = ""
                    client.close()
                FILE.close()
            except:
                continue

            if data == None or len(data) == 0:
                out.append("Cannot read %s (maybe empty?)" % file)
                out.append("")
                continue

            try:
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            except:
                out.append("Cannot parse %s (maybe not PE?)" % file)
                out.append("")
                continue

            out.append(("#" * 60) + "\nRecord %d\n" % count + ("#" * 60))
            out.append(self.header("Meta-data"))
            out.append("File:    %s" % file)
            out.append("Size:    %d bytes" % len(data))

            if 'magic' in sys.modules:
                if sys.version_info <= (2, 6):
                    out.append("Type:    %s" % self.ms.buffer(data))
                else:
                    out.append("Type:    %s" % magic.from_buffer(data))

            out.append("MD5:     %s" % hashlib.md5(data).hexdigest())
            out.append("SHA1:    %s" % hashlib.sha1(data).hexdigest())
            out.append("Date:    %s" % self.get_timestamp(pe))

            (ep, name) = self.check_ep_section(pe)
            s = "EP:      %s (%s)" % (hex(ep + pe.OPTIONAL_HEADER.ImageBase), name)
            if name not in good_ep_sections:
                s += " [SUSPICIOUS]"
            out.append(s)

            packers = self.check_packers(pe)
            if len(packers):
                out.append("Packers: %s" % ','.join(packers))

            callbacks = self.check_tls(pe)
            if len(callbacks):
                out.append(self.header("TLS callbacks"))
                for cb in callbacks:
                    out.append("    0x%x" % cb)

            resources = self.check_rsrc(pe)
            if len(resources):
                out.append(self.header("Resource entries"))
                out.append("%-18s %-12s %-12s Type" % ("Name", "RVA", "Size"))
                out.append("-" * 60)
                for rsrc in resources.keys():
                    (name, rva, size, type) = resources[rsrc]
                    out.append("%-18s %-12s %-12s %s" % (name, hex(rva), hex(size), type))

            imports = self.check_imports(pe)
            if len(imports):
                out.append(self.header("Suspicious IAT alerts"))
                for imp in imports:
                    cast = str(imp)
                    out.append(cast[2:-1])

            out.append(self.header("Sections"))
            out.append("%-10s %-12s %-12s %-12s %-12s" % ("Name", "VirtAddr", "VirtSize", "RawSize", "Entropy"))
            out.append("-" * 60)
            for sec in pe.sections:
                s = "%-10s %-12s %-12s %-12s %-12f" % (
                    ''.join([c for c in str(sec.Name).replace("\\x00", '') if c in string.printable]),
                    hex(sec.VirtualAddress),
                    hex(sec.Misc_VirtualSize),
                    hex(sec.SizeOfRawData),
                    sec.get_entropy())
                if sec.SizeOfRawData == 0 or \
                        (sec.get_entropy() > 0 and sec.get_entropy() < 1) or \
                        sec.get_entropy() > 7:
                    s += "[SUSPICIOUS]"
                out.append(s)

            verinfo = self.check_verinfo(pe)
            if len(verinfo):
                out.append(self.header("Version info"))
                out.append(verinfo)
            if len(analysis):
                out.append("VirusTotal Result: %s" % analysis)
            out.append("")
            count += 1
        print('\n'.join(out))


if __name__ == "__main__":

    printbase()
    if len(sys.argv) != 2:
        print("Usage: %s <file|directory>\n" % (sys.argv[0]))
        sys.exit()

    object = sys.argv[1]
    files = []

    if os.path.isdir(object):
        for entry in os.listdir(object):
            files.append(os.path.join(object, entry))
    elif os.path.isfile(object):
        files.append(object)
    else:
        print("You must supply a file or directory!")
        sys.exit()

    # You should fill these in with a path to your PEiD database
    start = datetime.datetime.utcnow()
    peid_database_path = 'userdb.txt'
    pescan = PEScanner(files, peid_database_path)
    pescan.collect()
    finish = datetime.datetime.utcnow()
    print(f"Runtime: {finish - start}")
