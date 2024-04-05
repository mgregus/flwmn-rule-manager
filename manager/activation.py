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



import paths
from colorama import Style, Fore
last_line_was_comment = False
last_comment = ""
remove_last_comment = False

def load_disable_conf():
    """Loads disable.conf configuration file.

        Returns
        -------
        contents: list
            a list of lines from disable.conf if openned and read succesfully. Otherwise nothing
        """
    try:
        with open(paths.DISABLE_CONF, 'r') as file:
            contents = file.readlines()
            file.close()
            return contents
    except FileNotFoundError:
        print(f"File '{paths.DISABLE_CONF}' not found or cannot be openned.")
        return
    return

def write_disable_conf(content):
    """Write content to disable.conf configuration file.

       Parameters
       ----------
       content : list
           List of lines creating the disable.conf to be stored.
    """
    try:
        with open(paths.DISABLE_CONF, 'w') as file:
            return file.writelines(content)
    except FileNotFoundError:
        print(f"File '{paths.DISABLE_CONF}' not found or cannot be openned.")
        return
    return


def find_expression(expression):
    """Search for a given expression in uncommented lines of disable.conf.

       Parameters
       ----------
       expression : str
           Expression to be searched for in the configuration file.

       Returns
       -------
       found: boolean
           Returns True if the expression is found. Otherwise False.
    """
    disable_conf = load_disable_conf()

    for line in disable_conf:
        if not line.startswith('#'):
            if expression.strip() == line.strip():
                return True

    return False

def create_expression(keyword, value):
    """Creates an expression to activate/deactive a given rule category based on keyword and value in disable.conf.

       Parameters
       ----------
       keyword : str
           Category keyword eg. classtype or group or signature metadata keyword
       value : str
           Value of specified keyword eg. not-suspicious or emergin-worm.rules or metadata keyword value

       Returns
       -------
       expression: str
           Returns expression which can be written to or removed from disabled.conf to activate/deactive a given rule category.
    """
    if keyword == "group":
        if ".rules" in value:
            expression = f"group:{value}"
        else:
            expression = f"group:{value}.rules"
    elif keyword == "classtype":
        expression = f"re:classtype:{value}"
    else:
        expression = f"metadata:{keyword} {value}"

    return expression

def is_comment_before_group(line):
    """Checks if the comment found in disabled config belongs to a group or category of rules and is used to describe it or is just a regular comment.

       example of comment belonging to a group:

                # Disabling specific classtypes
                re:classtype:not-suspicious
                re:classtype:protocol-command-decode
                re:classtype:misc-activity

       Parameters
       ----------
       line : str
           Line to be checked if a previous comment was belonging to this group or was just a regular comment.

       Returns
       -------
       is_comment_before_group: boolean
           Returns True if the line is a group related to previous comment. False if there is no relationship and previous comment was just a regular comment.
    """
    global last_line_was_comment
    global last_comment
    if last_line_was_comment and not line.startswith("#") and not line.startswith("\n"):
        if "Disabling" in last_comment:
            return True

    return False

def remove_empty_lines_from_end(list):
    """Removes empty lines from the end of the list.

       Parameters
       ----------
       list : list
           List containing lines of text.
    """
    while list and not list[-1].strip():
        list.pop()

def add_line_to_group(group, line):
    """Adds a given line in this case a comment line belonging to a given group before the given group.

        example of comment belonging to a group:

                # Disabling specific classtypes
                re:classtype:not-suspicious
                re:classtype:protocol-command-decode
                re:classtype:misc-activity

       Parameters
       ----------
       group : list
           Group of lines or rule types belonging to a given category.
       line : str
           Comment line belonging to that group, description of the group to be added to it.

    """
    global last_comment
    global last_line_was_comment
    global remove_last_comment

    if is_comment_before_group(line):
        group.append(last_comment)
        group.append(line)
        last_line_was_comment = False
        last_comment = ""
        remove_last_comment = True

        return

    group.append(line)
    return

def normalize_contents(disable_conf):
    """Normalizes or prettifies the contents of disable.conf after working with it eg. activating or deactivating new rule categories.
       Contents of the disable.conf should be ordered eg. all disabled group are lines following each other, all disabled metadata are line
       following each other.

       example of ordered disable.conf:

                group:ntp-events.rules
                group:nfs-events.rules
                group:stream-events.rules

                # Disabling specific SIDs:
                2230010
                2230003
                2230002
                2230009
                2230015
                2221010

                metadata:signature_severity Informational

                # Disabling specific classtypes
                re:classtype:not-suspicious
                re:classtype:protocol-command-decode
                re:classtype:misc-activity


       Parameters
       ----------
       disable_conf : list
           List of lines creating the original not normalized version of disable.conf

     """
    global last_comment
    global last_line_was_comment
    global remove_last_comment
    # Separate lines starting with different keywords
    re_lines, group_lines, sid_lines, commented_lines, metadata_lines, other_lines = [], [], [], [], [], []

    for line in disable_conf:
        if line.startswith("group"):
            add_line_to_group(group_lines, line)
        elif line.startswith("re"):
            add_line_to_group(re_lines, line)
        elif line.startswith("metadata"):
            add_line_to_group(metadata_lines, line)
        elif line.strip().isdigit():
            add_line_to_group(sid_lines, line)
        elif line.startswith("#"):
            add_line_to_group(commented_lines, line)
            last_comment = line
            last_line_was_comment = True
        elif line.startswith("\n") and last_line_was_comment:
            commented_lines.append(line)
        else:
            other_lines.append(line)

        if remove_last_comment:
            commented_lines = commented_lines[:-1]
            remove_last_comment = False

    remove_empty_lines_from_end(commented_lines)
    remove_empty_lines_from_end(sid_lines)
    remove_empty_lines_from_end(other_lines)
    remove_empty_lines_from_end(re_lines)
    remove_empty_lines_from_end(group_lines)
    remove_empty_lines_from_end(metadata_lines)

    normalized_disable_conf = commented_lines + ["\n" * 2] + group_lines  + ["\n" * 2] + sid_lines  + ["\n" * 2]+ metadata_lines  + ["\n" * 2] + re_lines +  ["\n" * 2] + other_lines + ["\n" * 2] + ["\n" * 1]

    write_disable_conf(normalized_disable_conf)

    return

def enable_category(expression, expression_present, key, val):
    """Enables a given rule category specified by the expression in the disable.conf.

       If the expression was not present in the disable.conf nothing happends since the specified category of rules specified by provided key value pair was not disabled.

       If the expression was present in the disable.conf it is removed from it to re-enable the formerly disabled category of rules specified by provided key value pair.

       Parameters
       ----------
       expression : str
           Expression used to enable a specified category of rules specified by provided key value pair in the disable.conf
       expression_present : boolean
           If true expression is present in the original disable.conf otherwise it is not present.
       key : str
           Category keyword eg. classtype or group or signature metadata keyword
       val : str
           Value of specified keyword eg. not-suspicious or emergin-worm.rules or metadata keyword value

    """
    if not expression_present:
        print(f"{Fore.GREEN}Rule Category:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{key} {val}{Style.RESET_ALL} was not disabled. No change.")
        return
    else:
        print(f"Enabling rule category {Fore.LIGHTYELLOW_EX}{key} {val}{Style.RESET_ALL}.")
        print(f"To see changes wait until Suricata-Updates runs or apply:\n{Fore.BLUE}\'sudo systemctl restart flowmon-idsp-suricata-update\'{Style.RESET_ALL}")
        old_disable_conf = load_disable_conf()
        new_disable_conf = []
        for line in old_disable_conf:
            if expression.strip() == line.strip():
                line = line.replace(expression,"")
            new_disable_conf.append(line)

        normalize_contents(new_disable_conf)

    return

def disable_category(expression, expression_present, key, val):
    """Disables a given rule category specified by the expression in the disable.conf.

       If the expression was present in the disable.conf nothing happends since the specified category of rules specified by provided key value pair was already disabled.

       If the expression was not present in the disable.conf it is added to it to disable the formerly enabled category of rules specified by provided key value pair.

       Parameters
       ----------
       expression : str
           Expression used to disabled a specified category of rules specified by provided key value pair in the disable.conf
       expression_present : boolean
           If true expression is present in the original disable.conf otherwise it is not present.
       key : str
           Category keyword eg. classtype or group or signature metadata keyword
       val : str
           Value of specified keyword eg. not-suspicious or emergin-worm.rules or metadata keyword value

    """
    if expression_present:
        print(f"{Fore.GREEN}Rule Category:{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}{key} {val}{Style.RESET_ALL} was already disabled.")
        return
    else:
        print(f"Disabling rule category {Fore.LIGHTYELLOW_EX}{key} {val}{Style.RESET_ALL}.")
        print(f"To see changes wait until Suricata-Updates runs or apply:\n{Fore.BLUE}\'sudo systemctl restart flowmon-idsp-suricata-update\'{Style.RESET_ALL}")
        disable_conf = load_disable_conf()
        disable_conf.append(expression)

        normalize_contents(disable_conf)

    return

def manage_category(key_val_pair, disable=True):
    """Activate or deactivate a given rule category in the disable.conf based on the key value pair used to specify that category.

       Parameters
       ----------
       key_val_pair : list
           List containing key and value specifiying which rule category should be activated or deactivated.
       disable : boolean
           Action to be performed with a given rule category True <=> disable category otherwise enable category.

    """
    key = key_val_pair[0]
    val = key_val_pair[1]

    if not key or not val:
        return

    expression = create_expression(key,val)
    expression_present = find_expression(expression)

    if disable == True:
        disable_category(expression, expression_present, key, val)
    else:
        enable_category(expression, expression_present, key, val)

    return