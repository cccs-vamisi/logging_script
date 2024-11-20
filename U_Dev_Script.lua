cjson = require("cjson")
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
            service = { name = "Virtual Machines" }
        },
        container = {
            id = "unknown",
            image = { name = "unknown" },
            runtime = "unknown"
        },
        node = {
            hostname = "unknown",
            labels = { kubernetes_azure_com_cluster = "unknown" }
        },
        host = { name = "unknown" }
    }

        if record["kubernetes"] and record["kubernetes"]["namespace_name"] == "logging" then
            if record["kubernetes"]["deployment"] and record["kubernetes"]["deployment"]["name"] == "kube-event-exporter" then
                -- Add "system" and "event_exporter" tags
                new_record["tags"] = record["tags"] or {}
                table.insert(new_record["tags"], "system")
                table.insert(new_record["tags"], "event_exporter")
        
                -- Add metadata index name
                new_record["@metadata"] = record["@metadata"] or {}
                new_record["@metad ata"]["index_name"] = "system-logs-kubernetes-events"
        
                -- Check the value of the "stream" field
                if record["stream"] == "stdout" then
                    -- Parse the message as JSON and target "kubernetes_event"
                    local success, parsed = pcall(cjson.decode, record["message"])
                    if success then
                        record["kubernetes_event"] = parsed
                        table.insert(new_record["tags"], "kubernetes_event")
                    end
                else
                    local success, parsed = pcall(cjson.decode, record["message"])
                    if success then
                        new_record["exporter_event"] = parsed
                        table.insert(new_record["tags"], "exporter_event")
                    end
                end
            end
        end

            -- Check if the kubernetes namespace is "aventail"
        if record["kubernetes"] and record["kubernetes"]["namespace_name"] == "aventail" then
                new_record["tags"] = new_record["tags"] or {}
                table.insert(new_record["tags"], "aventail")

                new_record["@metadata"] = new_record["@metadata"] or {}
                new_record["@metadata"]["index_name"] = string.format("%s-aventail", record["cccs-application"] and record["cccs-application"]["name"] or "unknown")

                local success, parsed = pcall(cjson.decode, record["message"])
                if success then
                    new_record["aventail"] = parsed


                    if parsed["logger_name"] == "audit" then
                        new_record["@metadata"]["index_name"] = string.format("%s-audit-aventail", record["cccs-application"] and record["cccs-application"]["name"] or "unknown")

                        table.insert(new_record["tags"], "audit")
                    end
                else
                    table.insert(new_record["tags"], "invalid_json")
            end
        end


            -- Check if the kubernetes namespace is "howler"
        if record["kubernetes"] and record["kubernetes"]["namespace"] == "howler" then
            new_record["tags"] = new_record["tags"] or {}
            -- Add the "howler" tag
            table.insert(new_record["tags"], "howler")

            -- Parse the 'message' field as JSON and assign to 'log'
            local success, parsed = pcall(cjson.decode, record["message"])
            if success then
                new_record["log"] = parsed

                -- Check if the log type is "audit"
                if parsed["type"] == "audit" then
                    -- Add index name for audit logs
                    new_record["@metadata"] = new_record["@metadata"] or {}
                    new_record["@metadata"]["index_name"] = string.format(
                        "%s-audit-howler",
                        record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                    )

                    -- Add the "audit" tag
                    table.insert(new_record["tags"], "audit")
                else
                    -- Add index name for non-audit logs
                    new_record["@metadata"] = new_record["@metadata"] or {}
                    new_record["@metadata"]["index_name"] = string.format(
                        "%s-howler",
                        record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                    )
                end
            else
                -- Handle JSON decoding failure
                table.insert(new_record["tags"], "invalid_json")
            end
        end

        -- Check if the kubernetes namespace is "lookingglass"
        if record["kubernetes"] and record["kubernetes"]["namespace"] == "lookingglass" then
            -- Add the "lookingglass" tag
            table.insert(new_record["tags"], "lookingglass")

            -- Parse the 'message' field as JSON and assign to 'log'
            local success, parsed = pcall(cjson.decode, record["message"])
            if success then
                new_record["log"] = parsed

                -- Check if the log type is "audit"
                if parsed["type"] == "audit" then
                    -- Add index name for audit logs
                    new_record["@metadata"] = new_record["@metadata"] or {}
                    new_record["@metadata"]["index_name"] = string.format(
                        "%s-audit-lookingglass",
                        record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                    )

                    -- Add the "audit" tag
                    table.insert(new_record["tags"], "audit")
                else
                    -- Add index name for non-audit logs
                    new_record["@metadata"] = new_record["@metadata"] or {}
                    new_record["@metadata"]["index_name"] = string.format(
                        "%s-lookingglass",
                        record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                    )
                end
            else
                -- Handle JSON decoding failure
                table.insert(new_record["tags"], "invalid_json")
            end
        end

        -- Check if the kubernetes namespace is "vault"
        if record["kubernetes"] and record["kubernetes"]["namespace"] == "vault" then
            -- Add the "vault" tag
            new_record["tags"] = new_record["tags"] or {}
            table.insert(new_record["tags"], "vault")

            -- Check if the stream is "stdout" (Audit Logs)
            if record["stream"] == "stdout" then
                -- Parse the 'message' field as JSON and assign to 'audit'
                local success, parsed = pcall(cjson.decode, record["message"])
                if success then
                    new_record["audit"] = parsed

                    -- Add "audit" tag and set the index name for audit logs
                    new_record["@metadata"] = new_record["@metadata"] or {}
                    new_record["@metadata"]["index_name"] = string.format(
                        "%s-audit-vault",
                        record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                    )

                    -- Add the "audit" tag
                    table.insert(new_record["tags"], "audit")
                else
                    -- Handle JSON decoding failure
                    table.insert(new_record["tags"], "invalid_json")
                end
            else
                -- For regular Vault logs (stderr), set the index name
                new_record["@metadata"] = new_record["@metadata"] or {}
                new_record["@metadata"]["index_name"] = string.format(
                    "%s-vault",
                    record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                )
            end
        end

    
        -- Check if the kubernetes namespace is "superset" or "superset-stg"
        if record["kubernetes"] and (record["kubernetes"]["namespace"] == "superset" or record["kubernetes"]["namespace"] == "superset-stg") then
            new_record["tags"] = new_record["tags"] or {}
            -- Check if the message is a valid JSON string (matches the regex "\A\{.+\}\z")
            if record["message"] and string.match(record["message"], "^%b{}$") then
                -- Attempt to decode the message as JSON
                local success, parsed = pcall(cjson.decode, record["message"])
                if success then
                    -- Remove the "json" field if it exists
                    parsed["json"] = nil
                    -- Re-encode the modified JSON back to a string and set it in the record
                    new_record["message"] = cjson.encode(parsed)
                else
                    -- Handle JSON decoding failure
                    table.insert(new_record["tags"], "invalid_json")
                end
            end

            -- Add the index name to the metadata
            new_record["@metadata"] = new_record["@metadata"] or {}
            new_record["@metadata"]["index_name"] = string.format(
                "%s-%s",
                record["cccs-application"] and record["cccs-application"]["name"] or "unknown",
                record["kubernetes"] and record["kubernetes"]["namespace"] or "unknown"
            )

            -- Add the "superset" tag
            table.insert(new_record["tags"], "superset")
        end

        -- Check if the kubernetes namespace is "airflow"
        if record["kubernetes"] and record["kubernetes"]["namespace"] == "airflow" then
            -- # Airflow pod logs from pods that are labeled "kubernetes_pod_operator=True"
            -- # are already picked up by the Airflow worker & pushed into our logs.  So these
            -- # logs are being duplicated and should be dropped.
            -- # NOTE: for some reason, negative logic doesn't work
            new_record["tags"] = new_record["tags"] or {}
            -- Check if the pod has the "kubernetes_pod_operator" label
            if record["kubernetes"] and record["kubernetes"]["labels"] and record["kubernetes"]["labels"]["kubernetes_pod_operator"] then
                -- Drop the record if the label is found
                return 0, timestamp, nil  -- Return nil to drop the log
            else
                -- If the message field looks like JSON (matches "^\{.+\}$")
                if record["message"] and string.match(record["message"], "^{.+}$") then
                    -- Attempt to decode the message as JSON
                    local success, parsed = pcall(cjson.decode, record["message"])
                    if success then
                        -- If JSON is valid, continue processing
                        new_record["message"] = cjson.encode(parsed)  -- Ensure the message remains a JSON string
                    else
                        -- Handle JSON decoding failure (optional, but could log or tag the failure)
                        table.insert(new_record["tags"], "invalid_json")
                    end
                else
                    -- If message is not JSON, set the original message in new_record
                    new_record["message"] = record["message"]
                end
            end

            -- Add the index name to the metadata in new_record
            new_record["@metadata"] = new_record["@metadata"] or {}
            new_record["@metadata"]["index_name"] = string.format(
                "%s-airflow",
                record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
            )

            -- Add the "airflow" tag
            table.insert(new_record["tags"], "airflow")
        end

        -- Check if the kubernetes namespace is "spark" or "fawkes-spark"
        if record["kubernetes"] and (record["kubernetes"]["namespace"] == "spark" or record["kubernetes"]["namespace"] == "fawkes-spark") then
            new_record["tags"] = new_record["tags"] or {}
            -- Add the "audit" tag to the new_record
            table.insert(new_record["tags"], "audit")

            -- Set the index name in new_record metadata
            new_record["@metadata"] = new_record["@metadata"] or {}
            new_record["@metadata"]["index_name"] = string.format(
                "%s-audit-spark",
                record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
            )
        end

        -- Check if the kubernetes namespace is "jupyhub"
    if record["kubernetes"] and record["kubernetes"]["namespace"] == "jupyhub" then
        new_record["@metadata"] = new_record["@metadata"] or {}
        -- Add the "jupyhub" tag
        table.insert(new_record["tags"], "jupyhub")

        -- Check if the message matches "ShellAuditLogger"
        if record["message"] and record["message"]:find("ShellAuditLogger") then
            -- Extract audit logger content
            local auditLogger = record["message"]:match("%[ShellAuditLogger%]:(.+)")
            if auditLogger then
                new_record["auditLogger"] = auditLogger
                table.insert(new_record["tags"], "audit")
                table.insert(new_record["tags"], "ShellAuditLogger")
            end
        elseif record["message"] and record["message"]:find("AuditLogger") then
            -- Extract audit logger content
            local auditLogger = record["message"]:match(".-%[AuditLogger%]:(.+)")
            if auditLogger then
                new_record["auditLogger"] = auditLogger
                table.insert(new_record["tags"], "audit")
                table.insert(new_record["tags"], "AuditLogger")
            end
        end

        -- Check if "audit" is in tags
        if table.concat(new_record["tags"]):find("audit") then
            -- Parse the auditLogger as JSON and store in "audit"
            if new_record["auditLogger"] then
                local success, parsed = pcall(cjson.decode, new_record["auditLogger"])
                if success then
                    new_record["audit"] = parsed
                end
                new_record["auditLogger"] = nil -- Remove the auditLogger field
            end
            -- Set the index name for audit logs
            new_record["@metadata"]["index_name"] = string.format(
                "%s-audit-jupyhub",
                record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
            )
        else
            -- Set the index name for regular logs
            new_record["@metadata"]["index_name"] = string.format(
                "%s-jupyhub",
                record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
            )
        end
    end
    

    -- Check if the kubernetes namespace is "borealis" or "borealis-staging"
    if record["kubernetes"] and (record["kubernetes"]["namespace"] == "borealis" or record["kubernetes"]["namespace"] == "borealis-staging") then
        new_record["tags"] = new_record["tags"] or {}
        new_record["@metadata"] = new_record["@metadata"] or {}
        -- Set the index name
        new_record["@metadata"]["index_name"] = string.format(
            "%s-borealis",
            record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
        )

        -- Copy "message" to "parsedmsg"
        new_record["parsedmsg"] = record["message"]

        -- Strip leading and trailing spaces from "parsedmsg"
        if new_record["parsedmsg"] then
            new_record["parsedmsg"] = new_record["parsedmsg"]:match("^%s*(.-)%s*$")
        end

        -- Remove ANSI color codes from "parsedmsg"
        if new_record["parsedmsg"] then
            new_record["parsedmsg"] = new_record["parsedmsg"]:gsub("\x1B%[([0-9]{1,2}(;[0-9]{1,2})?)?[mMK]", "")
        end

        -- Apply grok-like pattern matching
        local patterns = {
            "%[ (%w+) %] %[(%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d%.%d%d%dZ)%] %[(%w+)%] %[(.-)%] (.+)",
            "%[ (%w+)  %] %[(%w+)%] (.+)",
            "%[ (%w+)  %] %[(.+)%]%s*(.+)"
        }
        local matched = false

        for _, pattern in ipairs(patterns) do
            local zLevel, zTime, zThread, zCode, zLogLine = new_record["parsedmsg"]:match(pattern)
            if zLevel then
                new_record["zLevel"] = zLevel
                new_record["zTime"] = zTime
                new_record["zThread"] = zThread
                new_record["zCode"] = zCode
                new_record["zLogLine"] = zLogLine
                matched = true
                break
            end
        end

        -- Add failure tag if no match
        if not matched then
            new_record["tags"] = new_record["tags"] or {}
            table.insert(new_record["tags"], "_grok_failure_nomatch")
        end
    end
    
    

    -- Check if the kubernetes namespace is "trino" or "trino-stg"
    if record["kubernetes"] and record["kubernetes"]["namespace"] and 
       (record["kubernetes"]["namespace"] == "trino" or record["kubernetes"]["namespace"] == "trino-stg") then
        new_record["tags"] = new_record["tags"] or {}
        new_record["@metadata"] = new_record["@metadata"] or {}
       
        -- Set index name and add "trino" tag
        new_record["@metadata"]["index_name"] = string.format(
            "%s-trino",
            record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
        )
        table.insert(new_record["tags"], "trino")

        -- Check if the "message" field contains "auditableEvent"
        if record["message"] and record["message"]:find("auditableEvent") then
            -- Replace tab characters with spaces
            record["message"] = record["message"]:gsub("\t", " ")

            -- Parse "message" field with a specific pattern to extract "auditableEvent"
            local auditableEvent = record["message"]:match("auditableEvent=(.+)")
            if auditableEvent then
                -- Attempt to parse "auditableEvent" as JSON
                local success, parsed = pcall(cjson.decode, auditableEvent)
                if success then
                    new_record["audit"] = parsed
                    -- Update index name for audit logs
                    new_record["@metadata"]["index_name"] = string.format(
                        "%s-audit-trino",
                        record["cccs-application"] and record["cccs-application"]["name"] or "unknown"
                    )
                    table.insert(new_record["tags"], "audit")
                end
            end
        end
    end

    -- Check if the app_kubernetes_io/name label is "mongodb"
    if record["kubernetes"] and record["kubernetes"]["labels"] and 
       record["kubernetes"]["labels"]["app_kubernetes_io/name"] == "mongodb" then
            new_record["tags"] = new_record["tags"] or {}
            new_record["@metadata"] = new_record["@metadata"] or {}

            -- Attempt to parse the "message" field as JSON into "mongodb"
            if record["message"] then
                local success, parsed = pcall(cjson.decode, record["message"])
                if success then
                    new_record["mongodb"] = parsed
                    -- Remove the original "message" field
                    record["message"] = nil
                else
                    -- If JSON parsing fails, pass the original message
                    new_record["mongodb"] = record["message"]
                end
            end

                -- Add "mongodb" tag and set the index name
                table.insert(new_record["tags"], "mongodb")
                new_record["@metadata"]["index_name"] = "mongodb"
    else
        -- Catchall for everything else
        table.insert(new_record["tags"], "catchall")
        new_record["@metadata"]["index_name"] = "catchall"
    end
    

    -------------------------------------------------
    new_record["@metadata"] = {}
    new_record["tags"] = {}

    -- List of target namespaces
    local target_namespaces = {
        "fission", "fission-builder", "fission-function",
        "fission-oauth2-proxy", "hogwarts-landing", "nbgallery",
        "spellbook", "utils", "datahub"
    }

    -- Helper function to check if a value is in a table
    local function is_in_table(value, table)
        for _, v in ipairs(table) do
            if v == value then
                return true
            end
        end
        return false
    end

    -- Check if the kubernetes.namespace is in the target list
    if record["kubernetes"] and record["kubernetes"]["namespace"] and 
       is_in_table(record["kubernetes"]["namespace"], target_namespaces) then
        
        local namespace = record["kubernetes"]["namespace"]

        -- Add the namespace as a tag
        table.insert(new_record["tags"], namespace)

        -- Set the index name using the namespace and application name
        if record["cccs-application"] and record["cccs-application"]["name"] then
            new_record["@metadata"]["index_name"] = 
                record["cccs-application"]["name"] .. "-" .. namespace
        else
            new_record["@metadata"]["index_name"] = "default-" .. namespace
        end
    end
    -------------------------------------------------
    -- Change record data based on K8S and cluster data
    local kubernetes = record["kubernetes"]
    local systemd_slice = record["_SYSTEMD_SLICE"]

    -- Add timestamp
    if record["log_entries"] and record["log_entries"][1]["timestamp"] then
        new_record["timestamp"] = record["log_entries"][1]["timestamp"]
    end

    -- Add version, agent fields, and corelated info
    new_record["version"] = kubernetes["labels"]["pod-template-generation"] or new_record["version"]
    new_record["agent"].id = kubernetes["pod_id"] or new_record["agent"].id
    new_record["agent"].name = kubernetes["pod_name"] or new_record["agent"].name
    new_record["agent"].type = kubernetes["container_name"] or new_record["agent"].type
    new_record["agent"].version = kubernetes["host"] and kubernetes["host"]["container_image"] or new_record["agent"].version

    -- CCCS Application fields (systemd slice data)
    if systemd_slice then
        local cmdline = systemd_slice["_CMDLINE"]
        if cmdline then
            new_record["cccs_application"].cluster = cmdline["kubernetes.azure.com/agentpool"] or new_record["cccs_application"].cluster
            new_record["cccs_application"].environment = cmdline["kubernetes.azure.com/agentpool"] or new_record["cccs_application"].environment
            new_record["cccs_application"]["cloud"]["instance"].id = cmdline["kubernetes.azure.com/consolidated-additional-properties"] or new_record["cccs_application"]["cloud"]["instance"].id
        end
    end
    
    -- Add logsource if it's available
    new_record["cccs_application"].logsource = record["log_source"] or new_record["cccs_application"].logsource

    -- More Details on Container
    new_record["container"].id = record["docker"]["container_id"] or new_record["container"].id
    new_record["container"]["image"].name = kubernetes["container_image"] or new_record["container"]["image"].name

    -- Node info
    new_record["node"].hostname = kubernetes["host"] or new_record["node"].hostname
    if systemd_slice then
        new_record["node"]["labels"].kubernetes_azure_com_cluster = systemd_slice["kubernetes.azure.com/cluster"] or new_record["node"]["labels"].kubernetes_azure_com_cluster
    end

    -- Host info
    new_record["host"].name = systemd_slice["_HOSTNAME"] or new_record["host"].name
    return tag, timestamp, new_record

end
