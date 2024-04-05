"""
 * Copyright 2001-2024 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""

# jq 'select(.event_type == ”alert” and (.alert.metadata.ATTRIBUTE | type == ”array” and any(.[]; . == ”ATTRIBUT_VALUE”))) |”\(.alert.signature_id):\(.alert.signature): \(.alert.category)”'/data/idsp/outputs/eve.json
import subprocess
import paths
import shlex
import os
import gzip
import shutil
import re
from colorama import Style, Fore

#https://docs.suricata.io/en/latest/configuration/global-thresholds.html
def generate_threshold_command(args):
    """Generates threshold command from supplied arguments. Which can then be applied in threshold.conf to modify how alerts
       are generated from given rules.

       Parameters
       ----------
       args : list
           Line of command line arguments used to generate supress command.
           gid = args[0]
           sid = args[1]
           type = args[2]
           track = args[3]
           count = args[4]
           seconds = args[5]
    """
    gid, sid, type, track, count, seconds = args[0],args[1],args[2],args[3],args[4],args[5]
    command = ""
    error_msg = validate_threshold_input(gid, sid, type, track, count, seconds)

    if error_msg != "":
        print(f"{Fore.RED}Could not generate threshold command!{Style.RESET_ALL}")
        print(error_msg)
        return

    command += f"{Fore.GREEN}Generated threshold commnad:{Style.RESET_ALL}\n"
    command += f"\tthreshold gen_id {gid}, sig_id {sid}, type {type}, track {track}, count {count}, seconds {seconds}\n\n"


    print(command)

    return

def generate_supress_command(args):
    """Generates supress command from supplied arguments. Which can then be applied in threshold.conf to modify how alerts
       are generated from given rules.

       Parameters
       ----------
       args : list
           Line of command line arguments used to generate supress command.
           gid = args[0]
           sid = args[1]
           track = args[2]
           ip = args[3]
    """
    gid, sid, track, ip = args[0], args[1], args[2], args[3]

    error_msg = validate_supress_input(gid, sid, track, ip)

    if error_msg != "":
        print(f"{Fore.RED}Could not generate supress command!{Style.RESET_ALL}")
        print(error_msg)
        return

    command = ""
    command += f"{Fore.GREEN}Supress an alert for a given rule with the following command:{Style.RESET_ALL}\n"
    command += f"\tsupress gen_id {gid}, sig_id {sid}, track {track}, ip {ip}\n\n"

    print(command)

    return

def convert_str_to_int(str):
    """Converts string to integer if possible

       Parameters
       ----------
       str : str
           String to be converted to integer.

       Returns
       -------
       int: int
           Returns integer variant of given string if possible otherwise returns None.
    """
    try:
        return int(str)
    except ValueError:
        return None

def valid_IP_range(ip):
    """Checks if the IP address provided as argument to file is a valid IP address, IP address range or IP variable

       example of allowed values:

                217.110.97.128/25
                [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
                $HOME_NET

       Parameters
       ----------
       ip : str
           IP address string to be validated whether it has the correct formats.

       Returns
       -------
       valid_single_IP: boolean
           Returns True the provided IP is valid. False if provided IP is invalid.
    """
    valid_single_IP = False
    valid_IP_range = False
    valid_IP_adressvar = False

    single_IP_re = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # Regular expression pattern [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]
    multiple_adress_range_re = r"^\[(?:\s*(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[1-2]?[0-9])\s*)(?:,(?:\s*(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[1-2]?[0-9])\s*))*\]$"
    # Regular expression pattern  217.110.97.128/25
    adress_range_re = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2]?[0-9])$"
    allowed_adress_vars = ["$HOME_NET","$EXTERNAL_NET", "!$HOME_NET","!$EXTERNAL_NET"]

    if re.match(single_IP_re, ip):
        valid_single_IP = True

    if re.match(multiple_adress_range_re, ip) or re.match(adress_range_re, ip):
        valid_IP_range = True

    if ip in allowed_adress_vars:
        valid_IP_adressvar = True

    if valid_IP_adressvar or valid_single_IP or valid_IP_range:
        return  True

    return False
def validate_supress_input(gid, sid, track, ip):
    """Validates input submitted to generate a supress command used to threshold alerting of a given rule.

       For more information about allowed values for given threshold params see.

       'https://docs.suricata.io/en/suricata-6.0.0/configuration/global-thresholds.html'

       Parameters
       ----------
       gid : int
           Gid of a given rule.
       sid : int
           Sid of a given rule.
       track : int
           Detection filter.
       ip : str
           IP address, range, or variable specifying target IP address.

       Returns
       -------
       error_msg: str
           Returns error_msg containing what is wrong with given threshold command input params. Returns empty string if there is no problem
    """
    allowed_track = ["by_src","by_dst","by_either"]

    gid = convert_str_to_int(gid)
    sid = convert_str_to_int(sid)

    error_msg = ""
    if not isinstance(gid, int) or gid < 0:
        error_msg += f"{Fore.RED} Wrong GID!{Style.RESET_ALL} GID must be a positive integer eg. 1\n"
    if not isinstance(sid, int) or sid < 0:
        error_msg += f"{Fore.RED} Wrong SID!{Style.RESET_ALL} SID must be a positive integer eg. 2002087\n"
    if track not in allowed_track:
        error_msg += f"{Fore.RED} Wrong Track!{Style.RESET_ALL} Track must be one of {allowed_track}\n"
    if not valid_IP_range(ip):
        error_msg += f"{Fore.RED} Wrong IP!{Style.RESET_ALL} IP must be a correct IP or IP address range\n"

    return error_msg

def validate_threshold_input(gid, sid, type, track, count, seconds):
    """Validates input submitted to generate a threshold command used to threshold alerting of a given rule.

       For more information about allowed values for given threshold params see.

       'https://docs.suricata.io/en/latest/rules/thresholding.html'

       Parameters
       ----------
       gid : int
           Gid of a given rule.
       sid : int
           Sid of a given rule.
       type : str
           Threshold type.
       track : int
           Detection filter.
       count : int
           Count of hits.
       seconds : int
           Number of seconds over which count is applied.

       Returns
       -------
       error_msg: str
           Returns error_msg containing what is wrong with given threshold command input params. Returns empty string if there is no problem
    """
    allowed_types = ["threshold","limit","both"]
    allowed_track = ["by_src","by_dst","by_rule","both"]

    gid = convert_str_to_int(gid)
    sid = convert_str_to_int(sid)
    count = convert_str_to_int(count)
    seconds = convert_str_to_int(seconds)

    error_msg = ""
    if not isinstance(gid, int) or gid < 0:
        error_msg += f"{Fore.RED} Wrong GID!{Style.RESET_ALL} GID must be a positive integer eg. 1\n"
    if not isinstance(sid, int) or sid < 0:
        error_msg += f"{Fore.RED} Wrong SID!{Style.RESET_ALL} SID must be a positive integer eg. 2002087\n"
    if type not in allowed_types:
        error_msg += f"{Fore.RED} Wrong Type!{Style.RESET_ALL} Type must be one of {allowed_types}\n"
    if track not in allowed_types:
        error_msg += f"{Fore.RED} Wrong Track!{Style.RESET_ALL} Track must be one of {allowed_track}\n"
    if not isinstance(count, int) or count < 0:
        error_msg += f"{Fore.RED} Wrong Count!{Style.RESET_ALL} Count must be a positive integer eg. 10\n"
    if not isinstance(seconds, int) or seconds < 0:
        error_msg += f"{Fore.RED} Wrong Seconds!{Style.RESET_ALL} Seconds must be a positive integer eg. 60\n"

    return error_msg


def threshold_example():
    """Creates threshold command recommendation

       Returns
       -------
       recommendation: str
           Returns command recommendation to threshold alerting by given rules.
    """
    recommendation = f"{Fore.GREEN}Threshold a given rule with the following command:{Style.RESET_ALL}\n"
    recommendation += f"\tthreshold gen_id <gid>, sig_id <sid>, type <threshold|limit|both>, track <by_src|by_dst|by_rule|by_both>, count <N>, seconds <T>\n\n"
    recommendation += f"To apply append this command to {Fore.BLUE}threshold.config{Style.RESET_ALL}\n"
    recommendation += f"For more information see https://docs.suricata.io/en/latest/configuration/global-thresholds.html\n"

    return recommendation

def supress_example():
    """Creates supress command recommendation

       Returns
       -------
       recommendation: str
           Returns command recommendation to supress alerting by given rules.
    """
    recommendation = f"{Fore.GREEN}Supress an alert for a given rule with the following command:{Style.RESET_ALL}\n"
    recommendation += f"\tsupress gen_id <gid>, sig_id <sid>, track <by_src|by_dst|by_either>, ip <ip|subnet|adressvar>\n\n"
    recommendation += f"To apply append this command to {Fore.BLUE}threshold.config{Style.RESET_ALL}\n"
    recommendation += f"For more information see https://blog.inliniac.net/2012/03/07/f-secure-av-updates-and-suricata-ips/\n"

    return recommendation

def use_jq_tool(keyword, value, file):
    """Calls jq tool on given even.json to get rule trigger stats for rules which contain a given metadata attribute specified by keyword and value.

       Parameters
       ----------
       keyword : str
           Metadata keyword filter, to calculate stats only on rules having a given metadata attribute.
       value : str
           Metadata keyword value filter, to calculate stats only on rules having a given metadata attribute.
       file : str
           Eve.json file on which jq will calculate statistics .

       Returns
       -------
       result: str
           Returns jq output of rule-hits matching specified filter in specified eve.json log file.
    """
    try:
        sanitized_keyword = shlex.quote(keyword)
        sanitized_value = shlex.quote(value)

        command = f'select(.event_type == "alert" and (.alert.metadata.{sanitized_keyword} | type == "array") and any(.alert.metadata.{sanitized_keyword}[]; . == "{sanitized_value}")) | "\(.alert.signature_id):\(.alert.gid):\(.alert.signature): \(.alert.category)"'
        
        result = subprocess.check_output(["jq",command,file])
        return result    
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while calling jq tool: {e}")
        return None
    return


def format_result(search_result, N):
    """Formats the result of statistical jq search among the eve.json file. Orders the rule-triggers descending based on the number
       of rule hits by SID matching a given filter. Displays only the first N rules matching the filter ordered by number of rule-triggers
       descending.

       Parameters
       ----------
       search_result : str
           Resulting jq search among eve.json
       N : int
           Number of rules matching the filter which should be displayed
       Returns
       -------
       first_N_output: str
           Formatted and ordered result from jq filter of rule triggers matching specified filter.
    """
    try:
        output = subprocess.check_output(["uniq", "-c"],input=search_result)
        sorted_output = subprocess.check_output(["sort", "-nr"], input=output)
        first_N_output = subprocess.check_output(["head", f"-n {N}"], input=sorted_output)
        first_N_output_str = first_N_output.decode("utf-8")

        return first_N_output_str
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while calling jq tool: {e}")
        return None
    return


def create_tmp_dir(gz_file_path, filename):
    """Extracts .gz eve.json archive specified by a filename to a given directory.

       Parameters
       ----------
       gz_file_path : str
           File path to directory where an archive specified by filename will be extracted.
       filename : str
           .Gz archive file name which should be expanded.

       Returns
       -------
       extracted_archive: str
           Returns path to an extracted archive if extraction was successful otherwise returns None.
    """
    try:
        directory_path = os.path.join('/tmp', filename.rsplit(".gz", 1)[0])

        if not os.path.exists(directory_path):
            os.makedirs(directory_path)

        extracted_archive = os.path.join(directory_path, filename.rsplit(".gz", 1)[0])
        if not os.path.exists(extracted_archive):
            with gzip.open(gz_file_path, 'rb') as f_in:
                with open(extracted_archive, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

        return extracted_archive
    except Exception as e:
        pass

    return None

def rule_trigger_archive_log(path):
    """Extracts eve.json log file specified by path if provided log file is an archive.

       Parameters
       ----------
       path : str
           Path to an archived eve.json file.

       Returns
       -------
       extracted_log_path: str
           Returns path to an extracted eve.json file extracted from archived log file.
    """
    extracted_log_path = None

    if path is not None and path.endswith(".gz"):
        log_archive_name = os.path.basename(path)
        extracted_log_path = create_tmp_dir(path, log_archive_name)
    if extracted_log_path is None:
        print(f"\n{Fore.YELLOW}File {path} could not be opened or does not contain valid archived eve.json log.")
        print(f"{Fore.YELLOW}Calculating stats on {paths.EVE_JSON} instead.\n")
        extracted_log_path = paths.EVE_JSON

    return  extracted_log_path


def calculate_stats(stats, path):
    """Calculates stats of rule trigger. Returns number of given rule hits in the specified eve.json log file or archived eve.json log file.

        Stats are showed for first N rules with most hits which fit the metadata keyword value specified in filter.
        Output of this command can be used to generate thresholds or supression for given rules to reduce the amount of generated alerts.


       example of output:

                 COUNT | SID | GID |				 SIGNATURE MESSAGE 				 | CATEGORY |
                15 "2035190:1:ET INFO Observed Let's Encrypt Certificate from Active Intermediate, R3: Misc activity"
                6 "2035190:1:ET INFO Observed Let's Encrypt Certificate from Active Intermediate, R3: Misc activity"
                2 "2049202:1:ET INFO Observed File Hosting Service Domain (files .pythonhosted .org in TLS SNI): Misc activity"
                2 "2049201:1:ET INFO File Hosting Service Domain Domain in DNS Lookup (files .pythonhosted .org): Misc activity"
                1 "2022973:1:ET POLICY Possible Kali Linux hostname in DHCP Request Packet: Potential Corporate Privacy Violation"

       Parameters
       ----------
       stats : list
           List of parameters part of command call.

           stats[0] - filter <=> metadata keyword

           stats[1] - filter <=> metadata keyword value

           stats[2] - N <=> show first N rules matching the filter ordered descending based on number of hits in given eve.json log file
       path : str
           Path to a log file on which rule trigger stats should be calculated can be eve.json or eve.json archive.
    """
    keyword = stats[0]
    val = stats[1]
    N = stats[2]

    if path is not None:
        path = rule_trigger_archive_log(path[0])
    else:
        path = paths.EVE_JSON

    search_result = use_jq_tool(keyword, val,path)
    ordered_result = format_result(search_result, N)

    print(f"{Fore.GREEN} COUNT | SID | GID |\t\t\t\t SIGNATURE MESSAGE \t\t\t\t | CATEGORY | {Style.RESET_ALL}")
    print(ordered_result+"\n")
    print(threshold_example())
    print(supress_example())

    return
