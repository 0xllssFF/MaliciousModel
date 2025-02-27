from google.protobuf import json_format
from tensorflow.core.protobuf import saved_model_pb2
from tensorflow.python.keras.protobuf import saved_metadata_pb2 as metadata_pb2
import json
import h5py

import os
import base64
import fnmatch
import re
import pydot

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

def get_op_list(model_json: json) -> list[str]:
    model_op_list = []
    model_op_map = {}

    graph = pydot.Dot(graph_type='digraph')
    for metagraph in model_json["metaGraphs"]:
        for node in metagraph["graphDef"]["node"]:
            graph.add_node(pydot.Node(node["name"], label=node["op"]))
            for input_node in node.get("input", []):
                graph.add_edge(pydot.Edge(input_node, node["name"]))
            model_op_list.append({
                "name": node["name"],
                "op": node["op"],
                "info": node
            })
            model_op_map[node["name"]] = node
        
    for func in metagraph["graphDef"]["library"]["function"]:
        for node in func["nodeDef"]:
            graph.add_node(pydot.Node(node["name"], label=node["op"]))
            for input_node in node.get("input", []):
                graph.add_edge(pydot.Edge(input_node, node["name"]))
            model_op_list.append({
                "name": node["name"],
                "op": node["op"],
                "info": node
            })
            model_op_map[node["name"]] = node

    graph.write_dot('model_graph.dot')
    # for metagrah in model_json["metaGraphs"]:
    #     for node in metagrah["graphDef"]["node"]:
    #         model_op_list.append(
    #             {
    #                 "name": node["name"],
    #                 "op": node["op"],
    #                 "info": node
    #             }
    #         )
    #         model_op_map[node["name"]] = node
    #     try:
    #         for func in metagrah["graphDef"]["library"]["function"]:
    #             try:
    #                 for node in func["nodeDef"]:
    #                     model_op_list.append(
    #                         {
    #                             "name": node["name"],
    #                             "op": node["op"],
    #                             "info": node
    #                         }
    #                     )
    #                     model_op_map[node["name"]] = node
    #                 # model_op_list.update(node for node in func["nodeDef"])
    #             except KeyError:
    #                 continue
    #     except KeyError:
    #         pass
    return model_op_list


model_file = 'yamnet_unsafe/saved_model.pb'
# model_file = '../yamnet_unsafe.h5'

if model_file.endswith('.pb'):
    saved_model = saved_model_pb2.SavedModel()
    with open(model_file, "rb") as f:
        saved_model.ParseFromString(f.read()) 
        
    json_saved_model = json.loads(json_format.MessageToJson(saved_model))
    oplist = get_op_list(json_saved_model)
    issues = []
    for op in oplist:
        if op["op"] in malicious_op_list:
            issued = 0
            print(op["op"])