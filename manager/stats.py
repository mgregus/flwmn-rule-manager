"""
 * Copyright 2001-2024 The Apache Software Foundation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Based on secureworks/aristotle.
 * Source code from secureworks/aristotle was modified and refactored.
 * Original source: https://aristotle-py.readthedocs.io/en/latest/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""


import os
import re
import sys
import paths
from colorama import Style, Fore

signature_re = re.compile(r"^(?P<HEADER>(?P<ACTION>pass|drop|reject|alert|rejectsrc|rejectdst|rejectboth)\s+(?P<PROTO>[^\s]+)\s+(?P<SOURCEIP>[^\s]+)\s+(?P<SOURCEPORT>[^\s]+)\s+(?P<DIRECTION>[-<]>)\s+(?P<DESTINATIONIP>[^\s]+)\s+(?P<DESTINATIONPORT>[^\s]+))\s+\((?P<BODY>[^\)]+)")
disabled_signature_re = re.compile(r"^#\s*(?:pass|drop|reject|alert|rejectsrc|rejectdst|rejectboth)\s.*[();]\s*sid\s*:\s*\d+\s*;.*\)$")

sid_re = re.compile(r"[();]\s*sid\s*:\s*(?P<SID_IDENTIFIER>\d+)\s*;")
metadata_keyword_re = re.compile(r"(?P<METADATA>[();]\s*metadata\s*:\s*)(?P<METADATA_KEYWORD>[^;]+);")
classtype_keyword_re = re.compile(r"(?P<CLASSTYPE>[();]\s*classtype\s*:\s*)(?P<CLASSTYPE_VALUE>[^;]+);")


class RuleStatistics():
    """
        A class used to represent loaded signature set or ruleset eg. suricata.rules file
        ...

        Attributes
        ----------
        metadata_by_sid : dict
            dictionary of signature metadata for each SID of signature from specified ruleset

        used_metadata_keywords_registry : dict
            dictionary of used metadata keywords used in signatures from specified ruleset

        file_loaded : boolean
            was the signature file loaded

    """

    def __init__(self, rule_file_path):
        """Initializes Rule Stats class.


            used_metadata_keywords_registry example:

                    {'sid': {'2004002': [2004002], '2013845': [2013845]}, 'affected_product': {'web_server_applications': [2004002]}, 'attack_target': {'web_server': [2004002]}, 'created_at': {'2010_07_30': [2004002], '2011_11_05': [2013845]}, 'deployment': {'datacenter': [2004002]}, 'signature_severity': {'major': [2004002]}, 'tag': {'sql_injection': [2004002]}, 'updated_at': {'2020_09_11': [2004002]}, 'classtype': {'web-application-attack': [2004002]}}

            metadata_by_sid example:

                    {2004002: {'metadata': {'sid': ['2004002'], 'affected_product': ['web_server_applications']}, 'disabled': True, 'raw_rule': 'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Gazi Download Portal SQL Injection Attempt -- down_indir.asp id DELETE"; flow:established,to_server; http.uri; content:"/down_indir.asp?"; nocase; content:"id="; nocase; content:"DELETE"; nocase; content:"FROM"; nocase; distance:0; reference:cve,CVE-2007-2810; reference:url,www.securityfocus.com/bid/23714; reference:url,doc.emergingthreats.net/2004002; classtype:web-application-attack; sid:2004002; rev:10; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, signature_severity Major, tag SQL_Injection, updated_at 2020_09_11;)'}}


           Parameters
           ----------
           rule_file_path : str
               Path to rule file.
        """
        #Metadata dictionary for each sid.
        self.metadata_by_sid = {}
        #Dictionary of metadata keywords used in rule file.
        self.used_metadata_keywords_registry = {'sid': {}}

        self.file_loaded = False

        try:
            if os.path.isfile(rule_file_path):
                with open(rule_file_path, 'r') as rule_file:
                    self.file_loaded = True
                    self.load_ruleset(rule_file.read())
            else:
                print(f"Unable to process rule file \'{rule_file_path}.\nPlease check that the file exists and is a valid .rules file")
        except Exception as e:
            print(f"Unable to process rule file \'{rule_file_path}.\nPlease check that the file exists and is a valid .rules file")

    def set_metadata_keywords(self, sid, keyword, value):
        """Add metadata keyword and value found in a given rule to the metadata keyword value registry of all used
           metadata attributes within the whole ruleset if it was not added before.

           Parameters
           ----------
           sid : str
               SID identifier of a given rule.
           keyword : str
               Metadata keyword from rule.
           value : str
               Metadata keyword value from rule.
            """

        # Add key to list of used metadata keywords
        if keyword not in self.used_metadata_keywords_registry.keys():
            self.used_metadata_keywords_registry[keyword] = {}
        if value not in self.used_metadata_keywords_registry[keyword].keys():
            self.used_metadata_keywords_registry[keyword][value] = []
        if sid not in self.used_metadata_keywords_registry[keyword][value]:
            self.used_metadata_keywords_registry[keyword][value].append(sid)

        return

    def insert_metadata_to_rule(self, sid, keyword, value):
        """Adds metadata discovered from a given rule to the metadata dictionary for a coresponding rule specified by SID.

           Parameters
           ----------
           sid : str
               SID identifier of a given rule.
           keyword : str
               Metadata keyword from rule.
           value : str
               Metadata keyword value from rule.
        """

        keyword = keyword.lower().strip()
        value = value.lower().strip()

        if sid not in self.metadata_by_sid.keys():
            print(f"add_metadata() called for sid '{sid}' but sid is invalid (does not exist).")
            return

        if keyword not in self.metadata_by_sid[sid]['metadata'].keys():
            self.metadata_by_sid[sid]['metadata'][keyword] = []

        if value not in self.metadata_by_sid[sid]['metadata'][keyword]:
            self.metadata_by_sid[sid]['metadata'][keyword].append(value)


    def create_metadata_dic(self, sid, metadata_key_value_pairs):
        """Extracts SID attribute and its value from the plaintext signature as stored in .rules file. Extracted SID
             is then added as a metadata attribute to the dictionary of metadata attrributes for a corresponding rule.

             example of metadata_key_value_pairs:

                        ['attack_target Server', ' created_at 2021_07_28', ' deployment Perimeter', ' deployment Internal', ' former_category EXPLOIT', ' malware_family ysoserial', ' signature_severity Major', ' tag Exploit', ' tag possible_exploitation', ' updated_at 2021_07_28', 'classtype attempted-admin']

             Parameters
             ----------
             sid : str
                 Specifies line number in .rules file where the currently parsed rule begings.
             metadata_key_value_pairs : list
                 List of metadata key value pairs for a given rule

             Returns
             -------
             result: int
                 Returns 0 if executed successfully.
            """
        # key value pair is one string inside a list eg. '['affected_product Web_Server_Applications', ' attack_target Web_Server', ' created_at 2010_07_30', ' deployment Datacenter']'
        for key_value_pair in metadata_key_value_pairs:
            # 1. Convert the entire key-value pair to lowercase
            # 2. Remove leading and trailing whitespaces
            # 3. Split at the first space
            key_value_pair = key_value_pair.lower()
            key_value_pair = key_value_pair.strip()
            key_value_pair = key_value_pair.split(' ', 1)

            # key_value_pair_split is a list for each key value containing key and value as separate strings
            # eg. ['affected_product', 'web_server_applications']
            key_value_pair_split = []

            for element in key_value_pair:
                key_value_pair_split.append(element.strip())

            # no key value, just key. Metadata element format is incorrect.
            if len(key_value_pair_split) < 2:
                continue

            key, value = key_value_pair_split
            self.set_metadata_keywords(sid, key, value)
            self.insert_metadata_to_rule(sid, key, value)

            # remove duplicates if any
            for key in self.metadata_by_sid[sid]['metadata'].keys():
                self.metadata_by_sid[sid]['metadata'][key] = list(set(self.metadata_by_sid[sid]['metadata'][key]))
        return 0

    def extract_sid_from_sig(self,line_number, line_content):
        """Extracts SID attribute and its value from the plaintext signature as stored in .rules file. Extracted SID
            is then added as a metadata attribute to the dictionary of metadata attrributes for a corresponding rule.

            Parameters
            ----------
            line_number : int
                Specifies line number in .rules file where the currently parsed rule begings.
            line_content : str
                Signature line content as stored in .rules file

            Returns
            -------
            sid: str
                Returns SID attribute value of a given signature.
             """
        sid = None
        # extract sid
        re_match_extracted_sid = sid_re.search(line_content)
        # each valid rule has to have a SID number
        if not re_match_extracted_sid:
            print(f"Invalid rule on line {line_number} :\n{line_content}")
        sid = int(re_match_extracted_sid.group("SID_IDENTIFIER"))

        return sid

    def extract_classtype_from_sig(self, line_content):
        """Extracts classtype attribute and its value from the plaintext signature as stored in .rules file. Extracted classtype
           is then added as a metadata attribute to the dictionary of metadata attrributes for a corresponding rule.

           Parameters
           ----------
           line_content : str
               Signature line content as stored in .rules file

           Returns
           -------
           classtype: str
               Returns classtype attribute value of a given signature.
            """

        # extract classtype
        classtype = None
        re_match_extacted_classtype = classtype_keyword_re.search(line_content)
        if re_match_extacted_classtype:
            classtype = re_match_extacted_classtype.group("CLASSTYPE_VALUE")
        return classtype

    def extract_metadata_from_sig(self, line_content,rule_is_disabled, sid, classtype):
        """Extracts metadata attribute contents (eg. all keyword value pairs) from each signature. And loads them into
           the dictionary of metadata by sids.

           Parameters
           ----------
           line_content : str
               Rule line content inside the .rules file
           rule_is_disabled : boolean
               Specifies if a rule is disable eg. beginning with #.
           sid : str
               SID of a given signature. Not a metadata but a rule attribute.
           classtype : str
               Classtype of a given signature. Not a metadata but a rule attribute.
        """

        # extract metadata keyword value
        metadata = ""
        metadata_key_value_pairs = []

        re_match_extacted_metadata = metadata_keyword_re.search(line_content)
        if re_match_extacted_metadata:
            metadata = re_match_extacted_metadata.group("METADATA_KEYWORD")

        self.metadata_by_sid[sid] = {'metadata': {}, 'disabled': rule_is_disabled, 'raw_rule': line_content}

        if len(metadata) > 0:
            metadata_key_value_pairs.extend(metadata.split(','))

        # add classtype as metadata keyword
        if classtype:
            metadata_key_value_pairs.append(f"classtype {classtype}")

        # Add sid as metadata keyword. (If not in metadata.)
        if 'sid' not in self.metadata_by_sid[sid]['metadata'].keys():
            self.metadata_by_sid[sid]['metadata']['sid'] = [str(sid)]
            self.used_metadata_keywords_registry['sid'][str(sid)] = [sid]

        self.create_metadata_dic(sid, metadata_key_value_pairs)

        return

    def load_ruleset(self, loaded_rules):
        """Load signatures from a specified rule file and create necessary data structures to be able to search for metadata attributes
           inside the loaded rule file and calculate stats.

           Parameters
           ----------
           loaded_rules : file
               File containing loaded signatures

        """
        try:
            for line_number, line_content in enumerate(loaded_rules.splitlines()):
                rule_is_disabled = False

                if len(line_content.strip()) == 0:
                    continue
                if line_content.lstrip().startswith('#'):
                    if disabled_signature_re.match(line_content.strip()):
                        rule_is_disabled = True
                        line_content = line_content.lstrip()
                        line_content = line_content[1:].strip()
                    else:
                        # valid comment (not disabled rule)
                        continue

                #extract data from rule
                sid = self.extract_sid_from_sig(line_number, line_content)

                # rule SID already in dictionary <=> duplicate SID in ruleset
                if sid in self.metadata_by_sid.keys():
                    # duplicate rule but disabled one - ignore, dont add current rule to dict
                    if rule_is_disabled:
                        continue
                    # duplicate rule but first the disabled version was included - include also the enabled version, add current rule to dict
                    if self.metadata_by_sid[sid]['disabled'] == True:
                        pass
                    else:
                        continue

                classtype = self.extract_classtype_from_sig(line_content)
                self.extract_metadata_from_sig(line_content, rule_is_disabled, sid, classtype)

        except Exception as e:
            print(f"Problem loading signatures: {e}")

    def calc_all_keywords_stats(self, sids, keyword):
        """Calculates statistics. Calculates how many signatures have a metadata attribute with a specified keyword
           and lists all values that keyword attribute holds within the ruleset overall along with their counts.

           Parameters
           ----------
           sids : list (listed dictionary of used signatures)
               List of all rule SIDS in the rule .rules file.
           keyword : str
               Metadata keyword to be searched for within the metadata attribute of each signature.

           Returns
           -------
           statistics: str
               Returns calculated stats info about a given metadata keyword within a .rules file to be printed on stdout.
            """
        total = []
        enabled = []
        statistics = ""

        for sid in sids:
            if keyword in self.metadata_by_sid[sid]['metadata'].keys():
                total.append(sid)

        total_all_count = len(total)

        for sid in sids:
            if keyword in self.metadata_by_sid[sid]['metadata'].keys() and self.metadata_by_sid[sid]['disabled'] == False:
                enabled.append(sid)

        enabled_all_count = len(enabled)
        disabled_all_count = total_all_count - enabled_all_count
        enabled_percentage = str(round((enabled_all_count / total_all_count)*100, 2))
        disabled_percentage = str(round((disabled_all_count / total_all_count)*100, 2))

        statistics += f"KEYWORD: {Fore.YELLOW}{keyword.upper()}{Style.RESET_ALL} Total: {total_all_count}; Enabled: {enabled_all_count} ({enabled_percentage} %); Disabled: {disabled_all_count} ({disabled_percentage} %)"

        return statistics

    def calc_given_keyword_stats(self, sids, keyword):
        """Calculates statistics. Calculates how many signatures have a metadata attribute with a specified keyword
           and lists all values that keyword attribute holds within the ruleset overall along with their counts.

           Parameters
           ----------
           sids : list (listed dictionary of used signatures)
               List of all rule SIDS in the rule .rules file.
           keyword : str
               Metadata keyword to be searched for within the metadata attribute of each signature.

           Returns
           -------
           statistics: str
               Returns calculated stats info about a given metadata keyword within a .rules file to be printed on stdout.
            """
        statistics = ""
        # sort dictionary
        self.used_metadata_keywords_registry[keyword] = {key: value for key, value in sorted(self.used_metadata_keywords_registry[keyword].items())}

        for key_value in self.used_metadata_keywords_registry[keyword].keys():
            total_for_key = []

            for sid in sids:
                if sid in self.used_metadata_keywords_registry[keyword][key_value]:
                    total_for_key.append(sid)
            total_count_for_key = len(total_for_key)

            enabled_for_key = []
            for sid in self.used_metadata_keywords_registry[keyword][key_value]:
                if sid in sids and not self.metadata_by_sid[sid]['disabled']:
                    enabled_for_key.append(sid)

            enabled_count_for_key = len(enabled_for_key)
            disabled_count_for_key = total_count_for_key - enabled_count_for_key
            enabled_percentage = str(round((enabled_count_for_key / total_count_for_key)*100, 2))
            disabled_percentage = str(round((disabled_count_for_key / total_count_for_key)*100, 2))

            statistics += f"\t{Style.BRIGHT}{Fore.BLUE}{key_value}{Style.RESET_ALL} Total: {total_count_for_key}; Enabled: {enabled_count_for_key} ({enabled_percentage} %); Disabled: {disabled_count_for_key} ({disabled_percentage} %)\n"

        return statistics

    def calculate_statistics(self, keyword, just_list_all_used_keywords=False):
        """Calculates statistics. Calculates how many signatures have a metadata attribute with a specified keyword
           and lists all values that keyword attribute holds within the ruleset overall along with their counts.


            used_metadata_keywords_registry example:

                    {'sid': {'2004002': [2004002], '2013845': [2013845]}, 'affected_product': {'web_server_applications': [2004002]}, 'attack_target': {'web_server': [2004002]}, 'created_at': {'2010_07_30': [2004002], '2011_11_05': [2013845]}, 'deployment': {'datacenter': [2004002]}, 'signature_severity': {'major': [2004002]}, 'tag': {'sql_injection': [2004002]}, 'updated_at': {'2020_09_11': [2004002]}, 'classtype': {'web-application-attack': [2004002]}}

            metadata_by_sid example:

                    {2004002: {'metadata': {'sid': ['2004002'], 'affected_product': ['web_server_applications']}, 'disabled': True, 'raw_rule': 'alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Gazi Download Portal SQL Injection Attempt -- down_indir.asp id DELETE"; flow:established,to_server; http.uri; content:"/down_indir.asp?"; nocase; content:"id="; nocase; content:"DELETE"; nocase; content:"FROM"; nocase; distance:0; reference:cve,CVE-2007-2810; reference:url,www.securityfocus.com/bid/23714; reference:url,doc.emergingthreats.net/2004002; classtype:web-application-attack; sid:2004002; rev:10; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, signature_severity Major, tag SQL_Injection, updated_at 2020_09_11;)'}}


           Parameters
           ----------
           keyword : str
               Metadata keyword to be searched for within the metadata attribute of each signature.
           just_list_keywords : boolean
               If True, just print out all available metadata keywords used inside the given .rules file along with their usage counts.

           Returns
           -------
           statistics: str
               Returns calculated stats info about a given .rules file to be printed on stdout.
            """
        statistics = ""
        sids = list(self.metadata_by_sid.keys())

        if keyword not in self.used_metadata_keywords_registry.keys():
            return f"Key \'{keyword}\' was not found in ruleset."

        if sids is None:
            return "No SIDs or Signatures loaded from specified rule file!"

        statistics += self.calc_all_keywords_stats(sids, keyword)

        if just_list_all_used_keywords:
            return statistics
        else:
            statistics += f"\n"
            statistics += f"\tVALUES: \n"

        statistics += self.calc_given_keyword_stats(sids, keyword)

        return statistics

    def print_statistical_details(self, keyword, just_list_keywords=False):
        """Prints statistics about the presence of rules with a given metadata keyword inside the .rules files of all rules.

           Parameters
           ----------
           keyword : str
               Metadata keyword to be searched for within the metadata attribute of each signature.
           just_list_keywords : boolean
               If True, just print out all available metadata keywords used inside the given .rules file along with their usage counts.

           Returns
           -------
           result: boolean
               Returns True if stats exist and can be printed.
            """

        stats_string = self.calculate_statistics(keyword, just_list_keywords)

        if stats_string:
            print(stats_string)
            return True
        else:
            print("No statistics to print.")
            return False

    def print_ruleset_summary(self, sids=None):
        """Prints ruleset summary information. This includes number of total rules, number of enabled and disabled rules

           Parameters
           ----------
           sids : list (listed dictionary of used signatures)
               List of all rule SIDS in the rule .rules file.
            """

        if sids is None:
            sids = list(self.metadata_by_sid.keys())

        total_count = len(sids)
        enabled = []

        for sid in sids:
            if self.metadata_by_sid[sid]['disabled'] == False:
                enabled.append(sid)

        enabled_count = len(enabled)
        disabled_count = total_count - enabled_count

        enabled_percentage = str(round((enabled_count / total_count)*100, 2))
        disabled_percentage = str(round((disabled_count / total_count)*100, 2))

        print(f"{Style.BRIGHT}{Fore.GREEN}All Signatures:{Style.RESET_ALL}\n Total Signatures: {total_count} \n Enabled Signatures: {enabled_count} ({enabled_percentage} %) \n Disabled Signatures: {disabled_count} ({disabled_percentage} %) \n")
        return


def analyze_ruleset(stats, rule_file_path):
    """Analyzes ruleset specified by path. And calculate statistics about metadata usage in the given ruleset.
       Calculates how many rules match given metadata filter and how many of them are disabled or enabled.

       Parameters
       ----------
       stats : list
           User supplied arguments
           stats[0] - metadata keyword
           stats[1] - metadata keyword value
       rule_file_path : str
           Path to .rules file to be analyzed.

        """

    if rule_file_path is None:
        rule_file_path = paths.RULE_FILE

    rs = RuleStatistics(rule_file_path)
    if not rs.file_loaded:
        sys.exit(1)

    if stats is not None:
        metadata_keywords = []
        sid_keys = list(rs.metadata_by_sid.keys())
        just_list_all_used_keywords = False

        rs.print_ruleset_summary(sid_keys)

        if len(stats) > 0:
            metadata_keywords = stats
        else:
            metadata_keywords = rs.used_metadata_keywords_registry.keys()
            just_list_all_used_keywords = True

        for keyword in metadata_keywords:
            rs.print_statistical_details(keyword, just_list_all_used_keywords)

        print("")
        sys.exit(0)

