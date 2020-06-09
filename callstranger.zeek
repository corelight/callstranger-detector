# Module that detects CallStranger (CVE-2020-12695) attempts: http://callstranger.com/
# This module does so by looking for three things that could indicate CallStranger activity:
#   1. UPnP SUBSCRIBE commands with a Notify URL that contains an IP address that isn't an RFC1918 or local_nets address. This could be the precursor for DDoS amplification or Data Exfiltration
#   2. UPnP NOTIFY commands that are destined for a non-RFC1918 or local_nets address. This could indicate active DDoS amplification or Data Exfiltration
#   3. UPnP SUBSCRIBE commands with a Notify URL that is longer than CallStrangerDetector::exfiltration_threshold bytes. This could indicate data exfiltration over UPnP
# The module assumes that your site doesn't normally have UPnP SUBSCRIBE or NOTIFY commands destined for the Internet and that you don't have UPnP devices exposed to the Internet.
# If either of these things are true, you will see false positives. You can add particular IPs that create false positives to the CallStrangerDetector::ignore_subnets set to ignore them.

# Add a callback_header value to HTTP::Info to make it easier to track the Callback header for just UPnP traffic
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

  option exfiltration_threshold: count = 4000;
  option ignore_subnets: set[subnet] = {};
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    if (c?$http) {
        if (c$http$method == "NOTIFY") {
            if (c$id$resp_h !in Site::private_address_space && c$id$resp_h !in Site::local_nets && c$id$resp_h !in ignore_subnets) {
                NOTICE([$note=CallStranger_UPnP_To_External_Host, $msg="Potential CVE-2020-12695 (CallStranger) exploitation success (UPnP NOTIFY to a non-RFC1918 or Local Address)"]);
            } 
        } else if (c$http$method == "SUBSCRIBE" && c$http?$callback_header) {
            local value = c$http$callback_header;
            if (|value| > exfiltration_threshold && c$id$resp_h !in ignore_subnets) {
                NOTICE([$note=CallStranger_Data_Exfiltration, $msg="Potential CVE-2020-12695 (CallStranger) data exfiltration (large amount of data in UPnP NOTIFY URI)"]);
            } else {
                local parsed_uri = decompose_uri(value);
                if (parsed_uri?$netlocation) {
                    local netlocation_addr = to_addr(parsed_uri$netlocation);
                    if (netlocation_addr !in Site::private_address_space && netlocation_addr !in Site::local_nets && netlocation_addr !in ignore_subnets) {
                        NOTICE([$note=CallStranger_UPnP_Callback_To_External_Host, $msg="Potential CVE-2020-12695 (CallStranger) exploitation attempt (Requested UPnP Callback to a non-RFC1918 or Local address)"]);
                    }
                }
            }
        }
    }
}

# When we see headers add any Callback headers to the HTTP connection record so we can use them later
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "CALLBACK") {
        if (c?$http) {
            c$http$callback_header = value;
        }
    }
}