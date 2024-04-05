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

import json
import os
import yaml
import requests
import tarfile
import shutil
import paths
import glob
import program_expcetion
from urllib.parse import urlparse
from colorama import Style, Fore

def print_used_groups(filter="*", long_list=False):
    """Prints all used rule groups (.rules files) on a given instance.

       Parameters
       ----------
       filter : str
           Filter to be applied to only list groups which match the filter
       long_list : boolean
           If True, list groups matching the filter along with description otherwise just list groups.

       Returns
       -------
       result: int
           Returns 0 if listing was successful.
        """

    get_groups(filter, long_list)

    return 0


def is_group_present(sources, filter_pattern):
    """Checks if a given rule group is present among used rule sources .rule files used to create suricata.rules file

       Parameters
       ----------
       sources : .json config
           Json configuration file containing a list of all sources used by the programm.
       filter_pattern : str
           Pattern used to identify a given group

       Returns
       -------
       source:
           Returns a source in which a given group is found. Otherwise returns None.
        """
    for source in sources["Remote_Rule_Sources"] + sources.get("Local_Rule_Sources", []):
        for file_info in source['Source_Files']:
            if any(match_group_names(file_name, filter_pattern) for file_name in file_info):
                return source

    return ""


def match_group_names(file_name, filter_pattern):
    """Matches filtered group name supplied by the user with a group name stored in json.config file listing all used groups.

       If eg. group emerging-info.rules is used supplying bot emerging-info as well as emerging-info.rules should produce a match.

       Parameters
       ----------
       file_name : str
           File name of rule group being worked on by the programm.
       filter_pattern : str
           Pattern used to identify a given group (user supplied)

       Returns
       -------
       match: boolean
           Returns True if the filter_pattern supplied by user matches the name of file_name worked on by the programm.
        """
    file_name_without_extension = file_name.rsplit('.rules', 1)[0]
    filter_pattern_without_extension = filter_pattern.rsplit('.rules', 1)[0]

    return file_name_without_extension.lower() == filter_pattern_without_extension.lower()


def get_groups(filter_pattern,long_list):
    """Loads JSON configuration file containing a list of all used groups matching user supplied filter_pattern.
       If user requires long list groups matching the pattern are written along with their description.

       Parameters
       ----------
       filter_pattern : str
           Pattern used to identify a given group (user supplied)
       long_list : boolean
           Specifies if used rule groups should be printed also with their description.

        """
    config = load_json_config()
    print_output(config,  long_list,filter_pattern)

def print_output(sources, long_list,filter_pattern):
    """Prints output. In this case it is the list of all rule groups used by the IDS as defined in JSON configuration file.
       Outputs either just the group names or group names with description.
       In case a filter_pattern is provided it outputs only groups matching the decsription

       Parameters
       ----------
       sources : JSON
           JSON configuration file containing all used rule soruces along with corresponding groups
       long_list : boolean
           Specifies if used rule groups should be printed also with their description.
       filter_pattern : boolean
           Pattern used to identify a given group (user supplied)
        """
    matching_source = is_group_present(sources,filter_pattern)

    if filter_pattern != "*" and matching_source == "":
        print(f"\nAny of Rule Sources does not contain group: \'{filter_pattern}\'\n\nTo list all groups in rule sources use -g")
        return

    print(f"\n{Fore.BLUE}Rule Sources:{Style.RESET_ALL}")

    for source in sources["Remote_Rule_Sources"] + sources.get("Local_Rule_Sources", []):
        if filter_pattern != "*" and source != matching_source:
            continue
        print("---------------------------------------------------------------------------------")
        print(f"  {Fore.GREEN}- Rule Source:{Style.RESET_ALL} {Fore.YELLOW}{source['Source_Name']}{Style.RESET_ALL}")
        for file_info in source['Source_Files']:
            for file_name, description in file_info.items():
                if filter_pattern != "*" and not match_group_names(file_name,filter_pattern):
                    continue
                if long_list:
                    print(f"    {Fore.LIGHTGREEN_EX}* Group: {file_name}{Style.RESET_ALL} - {Fore.LIGHTYELLOW_EX}Description:{Style.RESET_ALL} {description}\n")
                else:
                    print(f"    * Group: {file_name}")


def set_description(sources, group_name, group_description):
    """Sets the description for a given group (.rule file) as specified by user input

       Parameters
       ----------
       sources : JSON
           JSON configuration file containing all used rule soruces along with corresponding groups
       group_name : boolean
           Group name (.rule file) for which description should be changed in the JSON configuration file.
       group_description : boolean
           New group description to be set for the specified group_name
    """
    for source in sources["Remote_Rule_Sources"] + sources.get("Local_Rule_Sources", []):
        for file_info in source['Source_Files']:
            for file_name, description in file_info.items():
                if match_group_names(file_name,group_name):
                    print(f"  {Fore.GREEN}- Rule Source:{Style.RESET_ALL} {Fore.YELLOW}{source['Source_Name']}{Style.RESET_ALL}")
                    print(f"   * Group: {file_name} - Description: {group_description}")
                    file_info[file_name] = group_description
                    print(f"Description for Group \'{file_name}\' successfully updated.")

def update_group_description(args):
    """Update given group description in JSON configuration file based on user input

       Parameters
       ----------
       args : list
           group_name = args[0]
           group_description = args[1]

       Returns
       -------
       match: boolean
           Returns 0 if successfull
        """
    group_name = args[0]
    group_description = args[1]
    config = load_json_config()

    matching_source = is_group_present(config,group_name)
    if matching_source != "":
        set_description(config,group_name,group_description)
        update_json_config(config)
        return 0

    print(f"\nGroup: \'{group_name}\' is not in any of the Local or Remote rule sources.\n\nTo list all groups in rule sources use -g")

    return 1

def extact_sources_from_yaml(keyword):
    """Returns a list of all local or remote rule sources used by IDS as specified in update.yaml based on keyword.

       Parameters
       ----------
       keyword : str
           Specifies local/remote rule sources to be returned from update.yaml

       Returns
       -------
       sources: list
           Returns list of used rule sources.
        """
    path = paths.LOCAL_UPDATE_CONFIG_YAML
    try:
        with open(path, 'r') as file:
            yaml_data = yaml.safe_load(file)

            if keyword in yaml_data:
                sources = yaml_data[keyword]
                if isinstance(sources, list):
                    uncommented_sources = [source for source in sources if not source.startswith("#")]

                    return uncommented_sources

    except FileNotFoundError:
        print(f"Error: YAML file \'{path}\' not found.")

    return []

def filter_by_extensions(array, extension=[".rules", ".gz"]):
    """Filters sources by extension. Whether a specified source is a single .rules file or an archive which can contain multiple .rules files.

       Parameters
       ----------
       array : list
           List of rule sources as string which should be filtered
       extension : list
           List of possible rule sources extensions

       Returns
       -------
       filtered_array: list
           Returns list of used rule sources with a specified extension.
        """
    filtered_array = []

    for src in array:
        if src.endswith(extension):
            if extension == ".rules":
                last_segment = src.rsplit('/', 1)[-1]
                filtered_array.append(last_segment)
            else:
                filtered_array.append(src)

    return filtered_array


def load_rule_sources_from_dir(path):
    """Loads all rule sources (.rules files) from a specified directory

       Parameters
       ----------
       path : str
           Specifies directory from which rule files should be loaded.

       Returns
       -------
       filenames: list
           Returns list of all rule sources (.rules files) inside a given directory specified as argument
        """
    try:
        filenames = []

        for filename in os.listdir(path):
            if filename.endswith(".rules"):
                filenames.append(filename)
        return filenames

    except FileNotFoundError:
        print(f"Directory not found: {path}")
        return []
    return

def clear_tmp_directory():
    """Clears the contents of a given /tmp directory used to store extracted .rules files from archived .gz rule sources.
    """
    tmp_directory = paths.LOCAL_TMP_DIR
    try:
        shutil.rmtree(tmp_directory)
        print(f"All contents removed from {tmp_directory}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def download_and_extract_gz_files(urls):
    """Downloads all remote archived .gz rule sources to a tmp directory. And then expands them. This is used to be able to
       determine which .rules files are part of a given remote rule source to be able to properly create the JSON configuration
       file of all used rule groups. s

       Parameters
       ----------
       urls : list
           List of all urls specifying remote archived .gz rule sources.

        """
    tmp_directory = paths.LOCAL_TMP_DIR

    if os.path.exists(tmp_directory):
        shutil.rmtree(tmp_directory)
        os.makedirs(tmp_directory)
    else:
        os.makedirs(tmp_directory)

    try:
        for url in urls:
            if url.endswith(".gz"):
                response = requests.get(url, stream=True)
                if response.status_code == 200:
                    subdir_name = os.path.splitext(os.path.basename(urlparse(url).path))[0]
                    extraction_path = os.path.join(tmp_directory, subdir_name)

                    filename = os.path.join(tmp_directory, os.path.basename(urlparse(url).path))

                    with open(filename, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)

                    with tarfile.open(filename, 'r:gz') as tar:
                        tar.extractall(extraction_path)

                    os.remove(filename)
                  #  print(f"Downloaded and extracted: {url}")
                else:
                   print(f"{Fore.YELLOW}Failed to download:{Style.RESET_ALL} {url} - Status Code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def get_source_array(source_name, sources):
    """Gets corresponding rule source array from a given entity inside JSON configuration file

       Parameters
       ----------
       source_name : str
           Name of a source eg. ET/OPEN
       sources : list
           List for a given source file with description belonging to a given source eg. ["src2.rules","dsc2"]

       Returns
       -------
       sources: list
           Returns a list of
        """
    for source in sources:
        if source[0] == source_name:
            return source[1]
    return None



def load_old_sources(config, source):
    """Loads all rule sources used groups used by the IDS to generate the suricata.rules file from the JSON configuration file.

       Parameters
       -------
       config : JSON config
           JSOn configuration file where list of used sources is stored.
       source : str
           Rule-Source to be searched inside the config either Remote_rule_sources or Local_rule_sources

       Returns
       -------
       loaded_sources: list
           Returns a list of all used sources along with their description either Remote_rule_sources or Local_rule_sources

        """
    #loaded_sources = [["ET/Open",["src_file1","desc1"],["src2","dsc2"]],["Flowmon",["src_file1","desc1"],["src2","dsc2"]]]
    loaded_sources = []

    for source in config[source]:
        loaded_sources.append([source["Source_Name"], []])
        for source_file_name in source['Source_Files']:
            for file_name, description in source_file_name.items():
                array = get_source_array(source["Source_Name"], loaded_sources)
                array.append([file_name,description])

    return loaded_sources

def expand_files_from_dirs(sources):
    """Finds all .rules files stored locally or used locally by the user to be made part of suricata.rules file.
       All locations from which the files are loaded are specified in suricata.yaml and update.yaml

       Parameters
       ----------
       sources : list
           List of all directories or .rules files which summarily create all local rules used

       Returns
       -------
       rule_sources: list
           Returns a list of all local .rules files.

        """
    files_from_dirs = set()
    rule_sources = []

    for source in sources:
        if os.path.isdir(source):
            files_from_dirs.update(glob.glob(os.path.join(source, '*.rules')))
        elif os.path.isfile(source):
            files_from_dirs.add(source)
        elif os.path.isfile(paths.LOCAL_RULES_DIR+source):
            files_from_dirs.add(paths.LOCAL_RULES_DIR+source)
        elif '*' in source:
            files_from_dirs.update(glob.glob(source))

    for source in files_from_dirs:
        rule_sources.append(source)

    return rule_sources

def update_local_list(rule_sources_old, rule_sources_new):
    """Updates the list of local rule groups used (.rules files) used to generate suricata.rules

       Parameters
       ----------
       rule_sources_old : list
           List of originally used rule sources, before update
        rule_sources_new : list
           List of rule sources used after update.

       Returns
       -------
       rules_sources_updated: list
           Returns a list currently used local rule groups after the udpdate.

        """
    rule_sources_files_old = rule_sources_old[0][1]

    for subarray in rule_sources_files_old[:]:
        if subarray[0] not in  rule_sources_new:
            rule_sources_files_old.remove(subarray)

    for file_path in rule_sources_new:
        found = False
        for subarray in rule_sources_files_old:
            if subarray[0] == file_path:
                found = True
                break
        if not found:
            rule_sources_files_old.append([file_path, ''])

    rule_sources_old[0][1] = rule_sources_files_old
    rules_sources_updated = rule_sources_old

    return rules_sources_updated

#toto pridava navyse pole jedno tych poli
def update_remote_list(rule_sources_old, rule_sources_new):
    """Updates the list of remote rule groups used (.rules files) used to generate suricata.rules

       Parameters
       ----------
       rule_sources_old : list
           List of originally used rule sources, before update
        rule_sources_new : list
           List of rule sources used after update.

       Returns
       -------
       rule_sources_new: list
           Returns a list currently used remote rule groups after the udpdate. If any rule groups are the same as in the
           old list of used rule groups the description of a given group from the old list is copied to the new list.

        """
    sources_backup = rule_sources_old


    for src_entry in rule_sources_old:
        src_name_old = src_entry[0]
        for second_entry in rule_sources_new:
            src_name_new = second_entry[0]
            if src_name_old == src_name_new:
                for source_file in src_entry[1]:
                    file_name = source_file[0]
                    description = source_file[1]
                    for source_file2 in second_entry[1]:
                        file_name2 = source_file2[0]
                        if file_name2 == file_name:

                            source_file2[1] = description
                            break
                break

    return rule_sources_new

def append_source_to_json(config, src, local=False):
    """Appends a given rule source to JSON configuration file which is used to store a list of all used rule sources
       used to create the suricata.rules file along with the .rules files belonging to each source.

       Parameters
       ----------
       config : JSON configuration file
           Json file to be created to contain only list of used sources and groups after update.
       src : list
           List of rule sources used after update to be appended to the JSON config
       local : boolean
           If True the src is a list of locally used rule sources otherwise it is a list of remote rule sources.

    """
    source = {
        "Source_Name": f"{src[0]}",
        "Source_Files": []
    }


    for src_file in src[1]:

        new_source_file  = {
            f"{src_file[0]}" :  f"{src_file[1]}"
        }

        source["Source_Files"].append(new_source_file)



    if local:
        config["Local_Rule_Sources"].append(source)
    else:
        config["Remote_Rule_Sources"].append(source)

    return

def generate_updated_config(remote_sources, local_sources):
    """Generates updated JSON used rule groups configuration file based on newly used remote and local rule sources
       to create the suricata.rules file used by the IDS.

       Parameters
       ----------
       remote_sources : list
           List of newly used remote rule sources along with the .rules files creating each rule source and their description
       local_sources : list
           List of newly used remote rule sources along with the .rules files creating each rule source and their description

    """
    config = {
        "Remote_Rule_Sources": [],
        "Local_Rule_Sources": []
    }

    i = 0
    for src in remote_sources:
        append_source_to_json(config, src)

    for src in local_sources:
        append_source_to_json(config,src,local=True)

    update_json_config(config)
    return

def has_internet():
    """Checks if given flowmon instance has access to the internet and can download remote rule sources.

       Returns
       -------
       internet_access: boolean
           Returns True if given flowmon instance has access to the internet.

        """
    try:
        response = requests.get("https://services.flowmon.com/", timeout=5)
        return response.status_code == 200
    except requests.ConnectionError:
        return False

def create_remote_list_rules(remote_rules_sources_from_update):
    """Creates a list of all used remote .rules files from all remote sources which are not archived but only consist of single file.
       Eg. if a source is stamus-lateral it creates a source with name stamus-lateral and adds the .rules file creating that source

       Example return array:

                 [
                    ['stamus-lateral',[['src.file1.rules', 'description' ]],
                    ['Pt-rules',[['src.file1.rules', 'description' ]]
                 ]

       Returns
       -------
       rules_files: list
           Returns a list of all used remote single file rules sources.
        """
    remote_sources = []
    #single source
    #['src_name', [["file1", "desc1"],["file2", "desc2"] ]]

    for src in remote_rules_sources_from_update:
        single_source = []
        source_files_list = []
        source_files = []

        source_name = src
        file_name = src
        description = ""

        source_files.append(file_name)
        source_files.append(description)
        source_files_list.append(source_files)
        single_source.append(source_name)
        single_source.append(source_files_list)
        remote_sources.append(single_source)

    return remote_sources


def get_rules_files_from_dir(directory):
    """Returns a list of all .rules files within a given directory.

       Parameters
       -------
       directory: str
           Specifies the directory to be searched for .rules files

       Returns
       -------
       rules_files: list
           Returns a list of all .rules files within a given directory.
        """

    rules_files = []
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith(".rules"):
                rules_files.append(os.path.join(root, file_name))
    return rules_files


def create_remote_list_gz():
    """Creates a list of all used remote .rules files from all remote archived .gz sources.
       Eg. if a source is ET/OPEN it creates a source with name ET/OPEN and list all .rules files belonging to that source

       Example return array:

                 [
                    ['ET/OPEN',[['src.file1.rules', 'description' ],['src.file2.rules', 'description' ]],
                    ['SSLblacklist',[['src.file1.rules', 'description' ],['src.file2.rules', 'description' ]]
                 ]

       Returns
       -------
       rules_files: list
           Returns a list of all used remote archived rules sources.
        """
    remote_sources = []
    main_dir = paths.LOCAL_TMP_DIR
    #single source
    # [['srcname',[[src.file1,srcfile2...],['file2',"desc2"]],['srcname2',[[src.file1,srcfile2...]]]

    subdirectories = [os.path.join(main_dir, d) for d in os.listdir(main_dir) if
                      os.path.isdir(os.path.join(main_dir, d))]

    for subdir in subdirectories:
        source_name = os.path.basename(subdir)
        single_source = []

        single_source.append(source_name)

        rules_files = get_rules_files_from_dir(subdir)
        source_files_list = []
        for file_path in rules_files:
            source_files = []
            file_name = os.path.basename(file_path)
            description = ""

            source_files.append(file_name)
            source_files.append(description)
            source_files_list.append(source_files)

        single_source.append(source_files_list)
        remote_sources.append(single_source)

    return remote_sources


def flowmon_rules_feed_enabled():
    """Checks if flowmon default rules feed, which is customized version of ET/OPEN ruleset is enabled or not.

        Returns
        -------
        is_enable: boolean
            Returns True if custom flowmon rule feed is enabled otherwise returns False.
    """
    file_path = paths.FLOWMON_UDPTE_YAML

    try:
        with open(file_path, "r") as file:
            data = yaml.safe_load(file)

        enable_flowmon_rules_feed = data.get("enable_flowmon_rules_feed")
        return enable_flowmon_rules_feed
    except Exception as e:
        program_expcetion.log_error(e)
        return False

    return False

def update_group_config():
    """Updates used groups used by IDS to create the suricata.rules file. Then stores the list of all used local and remote
       rule sources inside the JSON configuration file.

        """
    print("Updating Rule source list. Please wait, this could take a while.")
    original_config = load_json_config()
    remote_rule_sources = []

    remote_sources_old = load_old_sources(original_config, "Remote_Rule_Sources")
    local_sources_old = load_old_sources(original_config, "Local_Rule_Sources")

    #1. Get all local sources File names
    local_rule_sources = load_rule_sources_from_dir(paths.LOCAL_RULES_DIR)
    local_rule_sources += extact_sources_from_yaml("local")
    local_rule_sources = expand_files_from_dirs(local_rule_sources)
    local_sources_new = update_local_list(local_sources_old, local_rule_sources)

    #2. Get all remote sources File names
    if has_internet():
        remote_sources_from_update = extact_sources_from_yaml("sources")

        remote_rule_sources_from_update = filter_by_extensions(remote_sources_from_update, ".rules")
        remote_gz_sources_from_update = filter_by_extensions(remote_sources_from_update, ".gz")

        #if ten druhy config ma yes inak pridat normalne ET/OPEN
        flowmon_services_URL = 'https://services.flowmon.com/rules/public/6.0/emerging.rules.tar.gz'
        if flowmon_rules_feed_enabled():
            remote_gz_sources_from_update.append(flowmon_services_URL)

        # teraz mam uz vs. .rules v rule-sources alebo ako remote_rule_sources_from_update
        download_and_extract_gz_files(remote_gz_sources_from_update)
        # teraz to mozem dat do jedneho ako zoznam
        # [['src_name',["file1","desc1"],['file2',"desc2"]],['src_name2',["file1","desc1"],['file2',"desc2"]]]
        remote_sources_list = create_remote_list_rules(remote_rule_sources_from_update)
        remote_rule_files_from_gz = create_remote_list_gz()

        for entry in remote_rule_files_from_gz:
            remote_sources_list.append(entry)

        remote_sources_new = update_remote_list(remote_sources_old, remote_sources_list)

    else:
        remote_sources_new = remote_sources_old
        print(f"{Fore.YELLOW}No internet access updating only local source-list\n{Style.RESET_ALL}")

    generate_updated_config(remote_sources_new, local_sources_new)

    print("Update finished.\n\nTo list all groups in rule sources use -g")
    return

def update_json_config(config):
    """Stores the JSON configuration file containing the list of all used rule sources, .rules files along with their descriptions on disk.

       Parameters
       -------
       config: file
           New updated JSON configuration to be stored on disk.

       Returns
       -------
       True: boolean
           Returns True if operation was successful.
        """
    try:
        with open(paths.CONFIG_PATH, 'w') as file:
            json.dump(config, file, indent=1)
        return True
    except FileNotFoundError:
        print(f"Error: The specified configuration file '{paths.CONFIG_PATH}' was not found.")
    except json.JSONDecodeError:
        print(f"Error: The specified configuration file '{paths.CONFIG_PATH}' is not a valid JSON file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def load_json_config():
    """Loads the JSON configuration file containing the list of all used rule sources, .rules files along with their descriptions.

       Returns
       -------
       config: file
           Returns loaded JSON configuration file from disk.
        """
    try:
        with open(paths.CONFIG_PATH, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"Error: The specified configuration file '{paths.CONFIG_PATH}' was not found.")
    except json.JSONDecodeError:
        print(f"Error: The specified configuration file '{paths.CONFIG_PATH}' is not a valid JSON file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
