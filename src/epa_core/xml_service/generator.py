import os 
import io
import zeep 
from contextlib import redirect_stdout
from textwrap import dedent
dir_path = os.path.dirname(os.path.realpath(__file__))

class WsdlClassGenerator:
    def __init__(self, schema_directories: list[str]):
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.schema_directories = schema_directories
        self.schema_paths = [os.path.join(dir_path, schema_dir) for schema_dir in self.schema_directories]

    def find_wsdl_files(self):
        all_classes = []
        with open(os.path.join(dir_path, f"generated_wsdl_classes.py"), "w", encoding="utf-8") as f:
            f.write('')
        with open(os.path.join(dir_path, f"generated_wsdl_classes.py"), "a", encoding="utf-8") as f:
            
            f.write(dedent("""\
                class WsdlService:
                    def __init__(self, name='', wsdl=[]):
                        self.name: str = name
                        self.wsdl: list[str] = wsdl
                    def __str__(self): return self.name

                class WsdlOperation:
                    def __init__(self, name, port, service, wsdl):
                        self.name: str = name
                        self.port: str = port
                        self.service = WsdlService(service, wsdl)
                    def __str__(self): return self.name"""))
            f.write('\n')
            for schema_path, schema_dir in zip(self.schema_paths, self.schema_directories):
                for (dirpath, dirnames, filenames) in os.walk(schema_path):
                    for file in filenames:
                        if file.endswith('.wsdl'):         
                            path = os.path.join(dirpath, file)
                            print("Parsing: ", path)

                            short_path = path.replace(schema_path, "")
                            short_path_list = [x for x in short_path.split(os.sep) if x and x != ""] 
                            short_path_list.insert(0, schema_dir)
                            class_names = short_path.replace('.wsdl', "").split(os.sep)
                            class_names = [x for x in class_names if x and x != ""]
                                
                            try:
                                client = zeep.Client(wsdl=path, settings=zeep.Settings(forbid_entities=False, xml_huge_tree=True, xsd_ignore_sequence_order=False))

                                stdout_dump = io.StringIO()
                                with redirect_stdout(stdout_dump):
                                    client.wsdl.dump()

                                doc: str = stdout_dump.getvalue()
                                namespaces = client.namespaces
                                service_names = list(client.wsdl.services.keys())

                                service_str = ""
                                # service_str = '"""'
                                # service_str += doc
                                # service_str += '"""'
                                service_str += '\n'
                                indent = 0
                                class_name = '_'.join(class_names)
                                service_str += f"class {class_name.upper()}(WsdlService):\n"
                                all_classes.append(class_name)
                                for service_name, service in client.wsdl.services.items():
                                    indent = 1
                                    service_str += f"    def __init__(self):\n"
                                    service_str += f"        super().__init__('{service_name}', {repr(short_path_list)})\n"
                                    
                                    for port_name, port in service.ports.items():
                                        service_str += f"{indent * '    '}class _{port_name}:\n"
                                        indent = 2
                                        service_str += f"{indent * '    '}def __str__(self): return '{port_name}'\n"
                                        indent = 2
                                        operations = port.binding._operations
                                        for operation_name, operation in operations.items():
                                            service_str += f"{indent * '    '}{operation_name.replace('-', '_')} = WsdlOperation('{operation_name}', '{port_name}', '{service_name}', {repr(short_path_list)})\n"
                                        indent = 1
                                        service_str += f"{indent * '    '}{port_name} = _{port_name}()\n"
                                    indent = 1
                                    service_str += "\n"
                                indent = 0
                                # service_str += f"{indent * '    '}{class_name.upper()} = _{class_name}()\n"
                                f.write('\n')
                                f.write(service_str)
                            except Exception as e:
                                print(e)
                                print(f"---------------- Error parsing {path}")
        return 

def main():
    generator = WsdlClassGenerator(["schemas", "schemas3.0"])
    # generator.find_wsdl_files()
    wsdl_data = generator.find_wsdl_files()

if __name__ == "__main__":
    main()