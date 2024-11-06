function log_filter(tag, timestamp, record)
    local new_record = {
       namespace = "unknown",

       timestamp = "unknown",
       version = "unknown",
       agent = {
        id = "unknown",
        name = "unknown",
        type = "unknown",
        version = "unknown"
       },
       cccs_application = {
        classification = "unclassified",
        cluster = "unknown",
        environment = "unknown",
        logsource = "aks-pod",
        name = "hogwarts",
       },
       cloud = {
        instance = {
            id = "unknown",
            name = "unknown",
        },
        provider = "azure",
        region = "CanadaCentral",
        service = {
            name = "Virtual Machines"
        }

       },
       container = {
        id = "unknown",
        image = {
            name = "unknown"
        },
         runtime = "unknown" --not found
       },

       node = {
            hostname = "unknown",
            labels = {
                kubernetes_azure_com_cluster = "unknown"
            }
       },
       host = {
        name = "unknown"
       }

    }

    if record["kubernetes"] and record["kubernetes"]["namespace_name"] == "logging" then
        new_record["namespace"]= record["kubernetes"]["namespace_name"]
        
        if record["log_entries"][1]["timestamp"] then
            new_record["timestamp"] = record["log_entries"][1]["timestamp"]
        end
        -----------------------------------------------
        if record["kubernetes"]["labels"]["pod-template-generation"] then
            new_record["version"] = record["kubernetes"]["labels"]["pod-template-generation"]
        end
        -----------------------------------------------
        if record["kubernetes"]["pod_id"] then
            new_record["agent"].id = record["kubernetes"]["pod_id"]
        end
        -----------------------------------------------
        if record["kubernetes"]["pod_name"] then
            new_record["agent"].name = record["kubernetes"]["pod_name"]
        end
        -----------------------------------------------
        if record["kubernetes"]["container_name"] then
            new_record["agent"].type = record["kubernetes"]["container_name"]
        end
        -----------------------------------------------
        if record["kubernetes"]["host"] then
            new_record["agent"].version = record["kubernetes"]["host"]["container_image"]
        end

        -----------------------------------------------
        if record["_SYSTEMD_SLICE"]["_CMDLINE"]["kubernetes.azure.com/agentpool"] then
            new_record["cccs_application"].cluster = record["_SYSTEMD_SLICE"]["_CMDLINE"]["kubernetes.azure.com/agentpool"]
        end

        -----------------------------------------------     
        if record["_SYSTEMD_SLICE"]["_CMDLINE"]["kubernetes.azure.com/agentpool"] then
            new_record["cccs_application"].environment = record["_SYSTEMD_SLICE"]["_CMDLINE"]["kubernetes.azure.com/agentpool"]
        end

        -----------------------------------------------     
        if record["log_source"] then
            new_record["cccs_application"].logsource = record["log_source"]
        end

        -----------------------------------------------
        if record["_SYSTEMD_SLICE"]["_CMDLINE"]["kubernetes.azure.com/consolidated-additional-properties"] then
            new_record["cccs_application"]["cloud"]["instance"].id =  record["_SYSTEMD_SLICE"]["_CMDLINE"]["kubernetes.azure.com/consolidated-additional-properties"]
        end

        -----------------------------------------------
        if record["kubernetes"]["host"] then
            new_record["cccs_application"]["cloud"]["instance"].name = record["kubernetes"]["host"]
        end

        -----------------------------------------------
        if record["docker"]["container_id"] then
            new_record["container"].id = record["docker"]["container_id"]
        end

        -----------------------------------------------
        if record["kubernetes"]["container_image"] then
            new_record["container"]["image"].name = record["kubernetes"]["container_image"]
        end

        -----------------------------------------------
        if record["kubernetes"]["container_image"] then
            new_record["container"]["image"].name = record["kubernetes"]["container_image"]
        end

        -----------------------------------------------
        if record["kubernetes"]["namespace_name"] then
            new_record["namespace"]= record["kubernetes"]["namespace_name"]
        end

         -----------------------------------------------
         if record["kubernetes"]["host"] then
            new_record["node"].hostname = record["kubernetes"]["host"]
        end

        -----------------------------------------------
        if record["_SYSTEMD_SLICE"]["kubernetes.azure.com/cluster"] then
            new_record["node"]["labels"].kubernetes_azure_com_cluster =  record["_SYSTEMD_SLICE"]["kubernetes.azure.com/cluster"]
        end

        -------------------------------------
        if record["_SYSTEMD_SLICE"]["_HOSTNAME"] then
            new_record["host"].name =  record["_SYSTEMD_SLICE"]["_HOSTNAME"]
        end

        ------------Progress-------------------------
        if record["_SYSTEMD_SLICE"]["_HOSTNAME"] then
            new_record["host"].name =  record["_SYSTEMD_SLICE"]["_HOSTNAME"]
        end

    end
    print("Lua filter processed log: ".. require('cjson').encode(new_record))
    return tag, timestamp, new_record
end





-- [SERVICE]
--   Daemon Off
--   Flush 1
--   Log_Level info
--   Parsers_File /fluent-bit/etc/parsers.conf
--   Parsers_File /fluent-bit/etc/conf/custom_parsers.conf
--   HTTP_Server On
--   HTTP_Listen 0.0.0.0
--   HTTP_Port 2020
--   Health_Check On

-- [INPUT]
--   Name tail
--   Path /var/log/containers/*.log
--   multiline.parser docker, cri
--   Tag kube.*
--   Mem_Buf_Limit 10MB

-- [INPUT]
--   Name SYSTEMD
--   Tag host.*
--   SYSTEMD_Filter _SYSTEMD_UNIT=kubelet.service
--   Read_From_Tail On

-- [FILTER]
--   # Name kubernetes
--   # Match kube.*
--   # Merge_Log On
--   # Keep_Log Off
--   # K8S-Logging.Parser On
--   # K8S-Logging.Exclude On
--   # Buffer_Size 64KB
--   Name             kubernetes
--   Match            kube.*
--   Kube_URL         https://kubernetes.default.svc:443
--   Kube_CA_File     /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
--   Kube_Token_File  /var/run/secrets/kubernetes.io/serviceaccount/token
--   Kube_Tag_Prefix  kube.var.log.containers.
--   Merge_Log        On
--   Merge_Log_Key    log_processed

-- # [FILTER]
-- #     Name modify 
-- #     Match kube.*
-- #     Rename cccs-application cccs-application[name]

-- [FILTER]
--   Name lua
--   Match kube.*
--   Script /fluent-bit/scripts/log-filter.lua
--   call log_filter 

-- # [OUTPUT]
-- #     Name es
-- #     Match kube.*
-- #     Host ${NODE_NAME}
-- #     Logstash_Format On
-- #     Retry_Limit False
-- #     Trace_Error On 
-- #     Trace_Output On
-- #     Write_Operation upsert
-- #     Path output.txt 

-- # [OUTPUT]
-- #     Name es
-- #     Match host.*
-- #     Host elastic
-- #     Logstash_Format On
-- #     Logstash_Prefix node
-- #     Path output.txt
-- #     Type _doc 
-- #     Replace_Dots On
-- #     Buffer_Size False
-- #     Trace_Error On
-- #     Trace_Output Off
-- ### Elastic Search Output Setup ###
-- # [OUTPUT]
-- #     Name            es
-- #     Match           kube.*
-- #     Index           fluent-bit-kube
-- #     Host            elasticsearch-master
-- #     Port            9200
-- #     HTTP_User       ${ES_USER}
-- #     HTTP_Passwd     ${ES_PASSWORD}
-- #     Logstash_Format Off
-- #     Time_Key       @timestamp
-- #     Type            flb_type
-- #     Replace_Dots    On
-- #     Retry_Limit     False
-- #     Trace_Error     Off

-- [OUTPUT]
--   Name stdout
--   # Match jackie
--   Match *
--   # Host fluent-bit-elasticsearch-master
--   # Port 
--   # Logstash_Format On
--   Retry_Limit False
--   # Replace_Dots On 
--   # Path /tmp/log/fluentbit/output.log
--   [OUTPUT]
--     Name stdout
--     Match *
-- # [OUTPUT]
-- #   Name opensearch
-- #   Match *
-- #   # Match kube.*
-- #   Host opensearch-master
-- #   Port 9200
-- #   HTTP_User fluent
-- #   HTTP_Passwd hoGwaRTz666! 
-- #   # Logstash_Format fluent-bit-kube
-- #   Retry_Limit False
--   # Replace_Dots On 
--   # Path /tmp/log/fluentbit/output.log
  
-- # [OUTPUT]
-- #     Name es
-- #     Match host.*
-- #     Host ${NODE_NAME}
-- #     Logstash_Format On
-- #     Logstash_Prefix node
-- #     Retry_Limit False
-- #     Trace_Error On 
-- #     Trace_Output On
-- #     Write_Operation upsert
