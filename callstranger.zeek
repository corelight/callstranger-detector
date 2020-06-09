module CallStrangerDetector;

export {
  redef enum Notice::Type += {
    CallStranger_Data_Exfiltration,
    CallStranger_UPnP_To_External_Host,
    CallStranger_UPnP_Callback_To_External_Host
  };

  global exfiltration_threshold = 4000 &redef;
}

# Use this to track current requests being watched
#global watchlist: table[string] of bool &read_expire=(5sec); 
global watchlist: set[string] &read_expire=(5sec); 
global upnp_methods = set("SUBSCRIBE", "NOTIFY");

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (method == "SUBSCRIBE") {
        add watchlist[c$uid];
    } else if (method == "NOTIFY") {
        # Check to see if the destination isn't an RFC1918 address
        if (c$id$resp_h !in Site::private_address_space) {
            NOTICE([$note=CallStranger_UPnP_To_External_Host, $msg="Potential CVE-2020-12695 (CallStranger) exploitation attempt (UPnP NOTIFY to a non-RFC1918 Address)"]);
        }
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (c$uid !in watchlist) {
        return;
    }
    if (name == "CALLBACK") {
        if (|value| > exfiltration_threshold) {
            NOTICE([$note=CallStranger_Data_Exfiltration, $msg="Potential CVE-2020-12695 (CallStranger) data exfiltration (large amount of text in UPnP NOTIFY URI)"]);
        } else {
            local parsed_uri = decompose_uri(value);
            if (parsed_uri?$netlocation) {
                if (to_addr(parsed_uri$netlocation) !in Site::private_address_space) {
                    NOTICE([$note=CallStranger_UPnP_Callback_To_External_Host, $msg="Potential CVE-2020-12695 (CallStranger) exploitation attempt (Requested UPnP Callback to a non-RFC1918 address)"]);
                }
            }
        }
    }
}