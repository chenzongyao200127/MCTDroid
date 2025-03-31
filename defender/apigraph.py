import pickle
import ujson as json
from defender.drebin import get_drebin_feature
from settings import config


def transfer_apigraph_feature(drebin_feature, api_cluster_dict):
    apicall_name = drebin_feature.split("::")[1]
    if ";->" in apicall_name:
        class_name, method_name = apicall_name.split(";->")
        drebin_api_name = class_name.replace("/", ".") + "." + method_name
    else:
        drebin_api_name = apicall_name.replace("/", ".") + "."

    return next(
        ("apigraph::cluster-{}".format(api_cluster_dict[key])
         for key in api_cluster_dict if key.startswith(drebin_api_name)),
        None
    )


def get_apigraph_feature(apk_path, output_path=None):
    with open(config['clustering_info'], "rb") as f:
        apigraph_clustering_feature = pickle.load(f)

    drebin_feature = get_drebin_feature(apk_path)
    apigraph_feature = {
        transfer_apigraph_feature(key, apigraph_clustering_feature) or key: 1
        for key in drebin_feature if key.startswith("api_calls")
    }

    if output_path:
        with open(output_path, "w") as f:
            json.dump(apigraph_feature, f)

    return apigraph_feature
