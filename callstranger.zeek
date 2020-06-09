module HTTP;
export {
    redef record Info += {
        callback_header: string &optional;
    };
}

module CallStrangerDetector;
export {
  redef enum Notice::Type += {
    CallStranger_Data_Exfiltration,
    CallStranger_UPnP_To_External_Host,
    CallStranger_UPnP_Callback_To_External_Host
  };

  global exfiltration_threshold = 4000 &redef;
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    if (c?$http) {
        if (c$http$method == "NOTIFY") {
            if (c$id$resp_h !in Site::private_address_space && c$id$resp_h !in Site::local_nets) {
                NOTICE([$note=CallStranger_UPnP_To_External_Host, $msg="Potential CVE-2020-12695 (CallStranger) exploitation attempt (UPnP NOTIFY to a non-RFC1918 Address)"]);
            } 
        } else if (c$http$method == "SUBSCRIBE" && c$http?$callback_header) {
            local value = c$http$callback_header;
            if (|value| > exfiltration_threshold) {
                NOTICE([$note=CallStranger_Data_Exfiltration, $msg="Potential CVE-2020-12695 (CallStranger) data exfiltration (large amount of text in UPnP NOTIFY URI)"]);
            } else {
                local parsed_uri = decompose_uri(value);
                if (parsed_uri?$netlocation) {
                    local netlocation_addr = to_addr(parsed_uri$netlocation);
                    if (netlocation_addr !in Site::private_address_space && netlocation_addr !in Site::local_nets) {
                        NOTICE([$note=CallStranger_UPnP_Callback_To_External_Host, $msg="Potential CVE-2020-12695 (CallStranger) exploitation attempt (Requested UPnP Callback to a non-RFC1918 address)"]);
                    }
                }
            }
        }
    }
}

# When we see headers add any Callback headers to the http connection so we can use them later
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "CALLBACK") {
        if (c?$http) {
            c$http$callback_header = value;
        }
    }
}