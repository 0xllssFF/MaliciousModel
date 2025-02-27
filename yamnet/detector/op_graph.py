from google.protobuf import json_format
from tensorflow.core.protobuf import saved_model_pb2
from tensorflow.python.keras.protobuf import saved_metadata_pb2 as metadata_pb2
import json
import h5py

import os
import base64
import fnmatch
import re
malicious_op_list = [
    "ReadFile",
    "FixedLengthRecordDataset",
    "FixedLengthRecordDatasetV2",
    "CSVDataset",
    "CSVDatasetV2",
    "ExperimentalCSVDataset",
    "ImmutableConst",
    "InitializeTableFromTextFile",
    "InitializeTableFromTextFileV2",
    "WriteFile",
    "Save",
    "SaveSlices",
    "PrintV2",
    "MatchingFiles",
    "MatchingFilesDataset",
    "ExperimentalMatchingFilesDataset",
    "DebugIdentity",
    "DebugIdentityV2",
    "DebugIdentityV3",
    "DistributedSave",
    "RpcCall",
    "RpcClient",
    "RpcServer",
    "RpcServerRegister",
    "RegisterDataset",
    "RegisterDatasetV2",
    "DataServiceDataset",
    "DataServiceDatasetV2",
    "DataServiceDatasetV3",
    "DataServiceDatasetV4",
    "SqlDataset",
    "LookupTableExportV2",
    "LookupTableExport"
]

malicious_op_args = {
    "ReadFile":["filename"],
    
    "LookupTableExport": ["filename"],
    "LookupTableExportV2": ["filename"],
    
    "FixedLengthRecordDataset":["filenames"],
    "FixedLengthRecordDatasetV2":["filenames"],
    
    "CSVDataset":["filenames"],
    "CSVDatasetV2":["filenames"],
    "ExperimentalCSVDataset":["filenames"],
    
    "ImmutableConst":["memory_region_name"],
    
    "InitializeTableFromTextFile":["filename"],
    "InitializeTableFromTextFileV2":["filename"],
    
    "WriteFile":["filename"],
    
    "Save":["filename"],
    "SaveSlices":["filename"],
    
    "PrintV2": ["output_stream"],
    
    "MatchingFiles": ["pattern"],
    "MatchingFilesDataset": ["patterns"],
    "ExperimentalMatchingFilesDataset": ["patterns"],
    
    "DebugIdentity": ["debug_urls"],
    "DebugIdentityV2": ["debug_urls"],
    "DebugIdentityV3": ["debug_urls"],
    
    "DistributedSave": ["address"],
    "RpcCall": ["method_name"],
    "RpcClient": ["server_address"],
    "RpcServer": ["server_address"],
    "RpcServerRegister": ["method_name"],
    
    "RegisterDataset": ["address"],
    "RegisterDatasetV2": ["address"],
    
    "DataServiceDataset": ["address"],
    "DataServiceDatasetV2": ["address"],
    "DataServiceDatasetV3": ["address"],
    "DataServiceDatasetV4": ["address"],
    
    "SqlDataset": ["data_source_name"]
}

args_info = {
"ip_args": ["address", "server_address", "debug_urls"],
"file_args": ["data_source_name", "patterns", "output_stream", "filename", "filenames", "memory_region_name"],
"str_args": ["method_name", ]
}

malicious_files = [
    "/home/*",
    "/etc/*", 
    "/boot/*", 
    "/lib/*", 
    "/var/*", 
    "/usr/*",
    "*/.bashrc",
    "*/.bash_profile",
    "*/.zshrc",
    "*/.ssh/authorized_keys",
    "*/tensorflow.py",
    "*.py"
]

safe_ips = [
    
]


from enum import Enum

class Issue:
    def __init__(self, severity, category, details):
        """
        Initialize an Issue object with severity level, issue category, and detailed information.
        :param severity: severity level (e.g.high, mid, low)
        :param category: issue category (e.g.Tensorabuse,lambda layer)
        :param details: detailed information
        """
        self.severity = severity
        self.category = category
        self.details = details

    def __str__(self):
        """
        Return a formatted string representation of the issue.
        """
        return f"Issue: [\nSeverity: {self.severity.value}, Category: {self.category.value}, Details: {self.details}]\n"

class Severity(Enum):
    HIGH = "high"
    MID = "mid"
    LOW = "low"
        
class Category(Enum):
    TENSOR_ABUSE = "Tensor abuse"
    LAMBDA_LAYER = "lambda layer"

def get_op_list(model_json: json) -> list[str]:
    model_op_list = []
    model_op_map = {}
    for metagrah in model_json["metaGraphs"]:
        for node in metagrah["graphDef"]["node"]:
            model_op_list.append(
                {
                    "name": node["name"],
                    "op": node["op"],
                    "info": node
                }
            )
            model_op_map[node["name"]] = node
        try:
            for func in metagrah["graphDef"]["library"]["function"]:
                try:
                    for node in func["nodeDef"]:
                        model_op_list.append(
                            {
                                "name": node["name"],
                                "op": node["op"],
                                "info": node
                            }
                        )
                        model_op_map[node["name"]] = node
                    # model_op_list.update(node for node in func["nodeDef"])
                except KeyError:
                    continue
        except KeyError:
            pass
    return model_op_list

def is_malicious_file(filepath):
    if filepath in malicious_files:
        return True
    for pattern in malicious_files:
        if fnmatch.fnmatch(filepath, pattern):
            return True
    return False

    
def is_safe_ip(ip):
    for pattern in safe_ips:
        if fnmatch.fnmatch(ip, pattern):
            return True
    return False
if __name__ == '__main__':
    
    model_file = '../yamnet_unsafe/saved_model.pb'
    # model_file = '../yamnet_unsafe.h5'

    if model_file.endswith('.pb'):
        saved_model = saved_model_pb2.SavedModel()
        with open(model_file, "rb") as f:
            saved_model.ParseFromString(f.read()) 
            
        json_saved_model = json.loads(json_format.MessageToJson(saved_model))
        oplist = get_op_list(json_saved_model)
        # print(oplist)
        issues = []
        for op in oplist:
            if op["op"] in malicious_op_list:
                issued = 0
                print(op["op"])
                if "input" in op["info"]:
                    opinfo_input = op["info"]["input"] # all args infomation of an op
                    for arg in opinfo_input:
                        op_arg = arg.split(":")[0] # 'Save/filename:output:0' -> 'Save/filename'
                        if "/" not in op_arg:
                            arg_name = op_arg.split("/")[0]
                        else:
                            arg_name = op_arg.split("/")[1]  # 'Save/filename' -> 'filename'
                        # elif op_arg=="Const":
                        #     for i in range(0, len(oplist)):
                        #         if op_arg==oplist[i]["name"]:
                        #             break
                        #     if oplist[i]["op"]=="Const" and oplist[i]["info"]["attr"]["value"]["tensor"]['dtype']=="DT_STRING":
                        #         base64_arg_value=oplist[i]["info"]["attr"]["value"]["tensor"]["stringVal"]
                        #         arg_value=base64.b64decode(base64_arg_value[0]).decode('utf-8')
                        #         if self.is_malicious_file(arg_value):
                        #             self.issues.append(Issue(Severity.HIGH, Category.TENSOR_ABUSE, f"Tensorabuse op detected with malicious behavior in saved model, \nop: {op};\n{malicious_op_args[op["op"]]}: {arg_value}\n"))                       
                        #         else:
                        #             self.issues.append(Issue(Severity.MID, Category.TENSOR_ABUSE, f"Tensorabuse op detected in saved model, \nop: {op};\n{malicious_op_args[op["op"]]}: {arg_value}\n"))                       
                        #     continue
                        if arg_name in malicious_op_args[op["op"]]:
                            find = 0
                            for i in range(0, len(oplist)):
                                if op_arg==oplist[i]["name"]:
                                    find = 1
                                    break
                            if find==1:
                                if oplist[i]["op"]=="Const" and oplist[i]["info"]["attr"]["value"]["tensor"]['dtype']=="DT_STRING":
                                    base64_arg_value=oplist[i]["info"]["attr"]["value"]["tensor"]["stringVal"]
                                    arg_value=base64.b64decode(base64_arg_value[0]).decode('utf-8')
                                    op_tmp = op["op"]
                                    if arg_name in args_info["file_args"] and is_malicious_file(arg_value):
                                        issued=1
                                        issues.append(Issue(Severity.HIGH, Category.TENSOR_ABUSE, f"Tensorabuse op detected with malicious behavior in saved model, \nop: {op};\n{malicious_op_args[op_tmp]}: {arg_value}\n"))                       
                                    elif arg_name in args_info["ip_args"] and (not is_safe_ip(arg_value)):
                                        issued=1
                                        issues.append(Issue(Severity.HIGH, Category.TENSOR_ABUSE, f"Tensorabuse op detected with malicious behavior in saved model, \nop: {op};\n{malicious_op_args[op_tmp]}: {arg_value}\n"))                       
                                    else:
                                        issued=1
                                        issues.append(Issue(Severity.MID, Category.TENSOR_ABUSE, f"Tensorabuse op detected in saved model, \nop: {op};\n{malicious_op_args[op_tmp]}: {arg_value}\n"))                       
                    
                    
                    if "attr" in op["info"]:
                        opinfo_attr = op["info"]["attr"]
                        for attr in opinfo_attr:
                            if attr in malicious_op_args[op["op"]]:
                                op_tmp = op["op"]
                                if "list" in opinfo_attr[attr]:
                                    base64_arg_value=opinfo_attr[attr]["list"]["s"]
                                    arg_value=base64.b64decode(base64_arg_value[0]).decode('utf-8')
                                elif "s" in opinfo_attr[attr]:
                                    base64_arg_value=opinfo_attr[attr]["s"]
                                    arg_value=base64.b64decode(base64_arg_value).decode('utf-8')
                                if not is_safe_ip(arg_value):
                                    issued=1
                                    issues.append(Issue(Severity.HIGH, Category.TENSOR_ABUSE, f"Tensorabuse op detected with malicious behavior in saved model, \nop: {op};\n{malicious_op_args[op_tmp]}: {arg_value}\n"))                       
                                else:
                                    issued=1
                                    issues.append(Issue(Severity.MID, Category.TENSOR_ABUSE, f"Tensorabuse op detected in saved model, \nop: {op};\n{malicious_op_args[op_tmp]}: {arg_value}\n"))                       

                    if not issued:
                        issues.append(Issue(Severity.MID, Category.TENSOR_ABUSE, f"Tensorabuse op detected in saved model, \nop: {op};\n"))                       

        print(issues)

    elif model_file.endswith('.h5'):
        issues = []
        with h5py.File(model_file, 'r') as f:
            if 'model_config' in f.attrs:
                config = f.attrs['model_config']
                config = json.loads(config)
                print(config)
                # lambda_layers = []
                
                # Check for Lambda layers in the model configuration
                for layer in config['config']['layers']:
                    layer_class_name = layer['class_name']
                    if layer_class_name == 'Lambda':
                        # lambda_layers.append(layer)
                        issues.append(f"Lambda layer detected in h5 model, \nlayer: {layer}\n")
        print(issues)