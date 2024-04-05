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


import subprocess
import shlex
import os
import paths
from colorama import Style, Fore

def valid_path_provided(path):
    """Validates that path provided contains an existing .rules file

       Parameters
       ----------
       path : str
           Path to .rules file.

       Returns
       -------
       valid: boolean
           Returns True if provided path is path to a .rules file otherwise False.
    """

    if path is None or not os.path.exists(path):
        print(f"{Fore.RED}File does not exist, check path! {Style.RESET_ALL}:\n \'{path}\'")
        return False

    if not path.endswith('.rules'):
        print(f"{Fore.RED}File is not valid rule file! {Style.RESET_ALL}:\n \'{path}\'")
        return False

    return True

def normalize_output(output_lines):
    """Formats output from suricata called in test mode to show only what rule errors or syntax problems have been detected
       as part of testing of a given rule file.

       Parameters
       ----------
       output_lines : str
           Output from suricat run in test mode.

       Returns
       -------
       normalized_output: list
           Returns list of lines creating the formatted version of output from suricata.
    """
    normalized_output = []
    rule_syntax_errors = []
    summary_lines = []

    for line in output_lines:
        if b"error parsing signature" in line:
            rule_syntax_errors.append(line)
        elif b"Configuration provided was successfully" in line:
            summary_lines.append(line)

    normalized_output.append(f"{Fore.RED}Rule Syntax Errors:{Style.RESET_ALL}\n")
    for error in rule_syntax_errors:
        normalized_output.append(f"\t{error}\n\n")

    if rule_syntax_errors == []:
        normalized_output.append(f"\n{Fore.GREEN}Rule file is correct!{Style.RESET_ALL}")
        normalized_output.append(f"\n{Fore.YELLOW}Rules summary:{Style.RESET_ALL}\n")
    else:
        normalized_output.append(f"\n{Fore.RED}Rule file contains incorrect signatures!{Style.RESET_ALL}")
        normalized_output.append(f"\n{Fore.YELLOW}Rules summary:{Style.RESET_ALL}\n")

    for summary in summary_lines:
        normalized_output.append(f"\t{summary}\n")



    return normalized_output


def validate_file(path):
    """Calls suricata in test mode to check if the .rules file provided contains valid signatures.
       Checks the syntax of given signatures in the file specified.

       Parameters
       ----------
       path : str
           Path to .rules file

       Returns
       -------
       result: str
           Returns stdout output from suricata run in test mode on given .rules file.
    """
    try:
        sanitized_path = shlex.quote(path)
        sanitized_path_to_yaml = shlex.quote(paths.SURICAT_YAML)

        command = f'suricata -T -c {sanitized_path_to_yaml} -S {sanitized_path}'
        result = subprocess.check_output([command],shell=True,stderr=subprocess.STDOUT)
        
        return result

    except subprocess.CalledProcessError as e:
        return e.stdout

    return


def check_rule_syntax(path):
    """Checks the syntax of signatures in a specified .rules file and prints it to output.

        Parameters
        ----------
        path : str
            Path to .rules file

        Returns
        -------
        result: str
            Returns info about how many signatures have been loaded and optionaly error info about incorrect signatures.
     """
    rules_file_path = path[0]

    if not valid_path_provided(rules_file_path):
        return

    output = validate_file(rules_file_path)
    normalized_output = normalize_output(output.splitlines())

    for line in normalized_output:
        print(line)


    return
